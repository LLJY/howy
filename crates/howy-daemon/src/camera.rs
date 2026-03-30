//! Camera capture backend for howy.
//!
//! Design goals:
//! - Keep the camera cold until authentication starts
//! - Prefer the same working path as howdy: OpenCV + CAP_V4L
//! - Fall back to a persistent ffmpeg rawvideo sidecar for awkward IR devices
//! - Never write frames to disk in the real pipeline
//!
//! Notes on performance:
//! - Models stay hot in memory / GPU
//! - Camera is opened only for the auth window
//! - For GREY/IR devices we keep capture grayscale as long as possible, then
//!   expand to BGR immediately before inference because the current inference
//!   stack expects 3-channel BGR input.

use std::io::{BufReader, Read};
use std::path::Path;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use opencv::{core, imgproc, prelude::*, videoio};
use tracing::{debug, info, warn};
use v4l::video::Capture as CaptureTraitImport;

const FRAME_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// A camera capture device.
pub struct Camera {
    width: u32,
    height: u32,
    format: CaptureFormat,
    device_path: String,
    worker: Option<CaptureWorker>,
}

struct CaptureWorker {
    latest_message: Arc<Mutex<Option<CaptureMessage>>>,
    notify_rx: mpsc::Receiver<()>,
    stop_tx: mpsc::Sender<()>,
}

enum CaptureMessage {
    Frame((Vec<u8>, u32, u32)),
    Error(String),
}

enum Backend {
    OpenCv(OpenCvBackend),
    Ffmpeg(FfmpegBackend),
}

struct OpenCvBackend {
    cap: videoio::VideoCapture,
}

struct FfmpegBackend {
    child: Child,
    stdout: BufReader<ChildStdout>,
    width: u32,
    height: u32,
    format: CaptureFormat,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum CaptureFormat {
    Mjpeg,
    Yuyv,
    Grey,
}

impl Camera {
    /// Probe a camera device and prepare it for later start.
    ///
    /// This does not open a persistent capture stream yet. `start()` does that,
    /// which keeps the camera cold until an auth request actually begins.
    pub fn open(device_path: &str, req_width: i32, req_height: i32) -> Result<Self> {
        let path = if device_path.is_empty() {
            find_camera_device()?
        } else {
            device_path.to_string()
        };

        info!("Probing camera: {path}");

        let device = v4l::Device::with_path(&path)
            .context(format!("failed to open camera device: {path}"))?;

        let caps = device.query_caps()?;
        debug!("Camera: {} ({})", caps.card, caps.driver);

        let (width, height, format) = negotiate_format(&device, req_width, req_height)?;
        info!("Camera format: {width}x{height} ({format:?})");

        Ok(Self {
            width,
            height,
            format,
            device_path: path,
            worker: None,
        })
    }

    /// Start the capture backend.
    ///
    /// Strategy:
    /// 1. Try OpenCV CAP_V4L first (matches howdy's default working path)
    /// 2. Fall back to a persistent ffmpeg sidecar if OpenCV cannot open the device
    pub fn start(&mut self) -> Result<()> {
        if self.worker.is_some() {
            return Ok(());
        }

        let device_path = self.device_path.clone();
        let width = self.width;
        let height = self.height;
        let format = self.format;

        let latest_message = Arc::new(Mutex::new(None));
        let latest_message_worker = Arc::clone(&latest_message);
        let (notify_tx, notify_rx) = mpsc::sync_channel(1);
        let (stop_tx, stop_rx) = mpsc::channel();

        thread::spawn(move || {
            capture_worker_loop(
                device_path,
                width,
                height,
                format,
                latest_message_worker,
                notify_tx,
                stop_rx,
            );
        });

        self.worker = Some(CaptureWorker {
            latest_message,
            notify_rx,
            stop_tx,
        });

        Ok(())
    }

    /// Capture a single frame as BGR pixel data.
    /// Returns (bgr_data, width, height).
    pub fn capture_frame(&mut self) -> Result<(Vec<u8>, u32, u32)> {
        let worker = self.worker.as_ref().context("camera not started")?;

        loop {
            if let Some(message) = take_latest_message(&worker.latest_message) {
                return decode_capture_message(message);
            }

            match worker.notify_rx.recv_timeout(FRAME_READ_TIMEOUT) {
                Ok(()) => continue,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    warn!(
                        timeout_secs = FRAME_READ_TIMEOUT.as_secs(),
                        "Camera backend timed out waiting for a frame"
                    );
                    return Err(anyhow!(
                        "timed out waiting for camera frame after {}s",
                        FRAME_READ_TIMEOUT.as_secs()
                    ));
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(anyhow!("camera capture worker stopped unexpectedly"));
                }
            }
        }
    }

    pub fn width(&self) -> u32 {
        self.width
    }

    pub fn height(&self) -> u32 {
        self.height
    }
}

impl Drop for Camera {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = worker.stop_tx.send(());
        }
    }
}

fn capture_worker_loop(
    device_path: String,
    width: u32,
    height: u32,
    format: CaptureFormat,
    latest_message: Arc<Mutex<Option<CaptureMessage>>>,
    notify_tx: mpsc::SyncSender<()>,
    stop_rx: mpsc::Receiver<()>,
) {
    let mut backend = match start_backend(&device_path, width, height, format) {
        Ok(backend) => backend,
        Err(e) => {
            warn!("Failed to start camera backend: {e:#}");
            let _ = publish_message(
                &latest_message,
                &notify_tx,
                CaptureMessage::Error(format!("failed to start camera backend: {e:#}")),
            );
            return;
        }
    };

    loop {
        match stop_rx.try_recv() {
            Ok(()) | Err(mpsc::TryRecvError::Disconnected) => {
                debug!("Camera capture worker stopping");
                return;
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }

        let using_opencv = matches!(&backend, Backend::OpenCv(_));
        let frame_result = match &mut backend {
            Backend::OpenCv(backend) => backend.next_frame(),
            Backend::Ffmpeg(backend) => backend.next_frame(),
        };

        match frame_result {
            Ok(frame) => {
                if !publish_message(&latest_message, &notify_tx, CaptureMessage::Frame(frame)) {
                    debug!("Camera frame receiver dropped");
                    return;
                }
            }
            Err(e) if using_opencv => {
                warn!("OpenCV capture failed: {e:#}; falling back to ffmpeg");
                match FfmpegBackend::new(&device_path, width, height, format) {
                    Ok(ffmpeg_backend) => {
                        info!("Using ffmpeg camera backend");
                        backend = Backend::Ffmpeg(ffmpeg_backend);
                    }
                    Err(fallback_error) => {
                        warn!(
                            "ffmpeg fallback failed after OpenCV capture error: {fallback_error:#}"
                        );
                        let _ = publish_message(
                            &latest_message,
                            &notify_tx,
                            CaptureMessage::Error(format!(
                                "OpenCV capture failed: {e:#}; ffmpeg fallback failed: {fallback_error:#}"
                            )),
                        );
                        return;
                    }
                }
            }
            Err(e) => {
                warn!("Camera backend capture failed: {e:#}");
                let _ = publish_message(
                    &latest_message,
                    &notify_tx,
                    CaptureMessage::Error(format!("camera backend capture failed: {e:#}")),
                );
                return;
            }
        }
    }
}

fn start_backend(
    device_path: &str,
    width: u32,
    height: u32,
    format: CaptureFormat,
) -> Result<Backend> {
    match OpenCvBackend::new(device_path, width, height) {
        Ok(backend) => {
            info!("Using OpenCV CAP_V4L camera backend");
            Ok(Backend::OpenCv(backend))
        }
        Err(e) => {
            warn!("OpenCV backend unavailable: {e:#}; falling back to ffmpeg");
            let backend = FfmpegBackend::new(device_path, width, height, format)?;
            info!("Using ffmpeg camera backend");
            Ok(Backend::Ffmpeg(backend))
        }
    }
}

fn publish_message(
    latest_message: &Arc<Mutex<Option<CaptureMessage>>>,
    notify_tx: &mpsc::SyncSender<()>,
    message: CaptureMessage,
) -> bool {
    let mut slot = match latest_message.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    *slot = Some(message);
    drop(slot);

    match notify_tx.try_send(()) {
        Ok(()) | Err(mpsc::TrySendError::Full(())) => true,
        Err(mpsc::TrySendError::Disconnected(())) => false,
    }
}

fn take_latest_message(
    latest_message: &Arc<Mutex<Option<CaptureMessage>>>,
) -> Option<CaptureMessage> {
    let mut slot = match latest_message.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    slot.take()
}

fn decode_capture_message(message: CaptureMessage) -> Result<(Vec<u8>, u32, u32)> {
    match message {
        CaptureMessage::Frame(frame) => Ok(frame),
        CaptureMessage::Error(message) => Err(anyhow!(message)),
    }
}

impl OpenCvBackend {
    fn new(device: &str, width: u32, height: u32) -> Result<Self> {
        let mut cap = videoio::VideoCapture::from_file(device, videoio::CAP_V4L)
            .context("failed to open device with OpenCV CAP_V4L")?;

        if !cap.is_opened()? {
            bail!("OpenCV could not open device {device}");
        }

        // Best-effort low-latency knobs. Some drivers ignore these.
        let _ = cap.set(videoio::CAP_PROP_FRAME_WIDTH, width as f64);
        let _ = cap.set(videoio::CAP_PROP_FRAME_HEIGHT, height as f64);
        let _ = cap.set(videoio::CAP_PROP_FPS, 30.0);
        let _ = cap.set(videoio::CAP_PROP_BUFFERSIZE, 1.0);

        Ok(Self { cap })
    }

    fn next_frame(&mut self) -> Result<(Vec<u8>, u32, u32)> {
        let mut frame = core::Mat::default();
        self.cap.read(&mut frame).context("OpenCV read() failed")?;
        if frame.empty() {
            bail!("OpenCV returned empty frame");
        }

        let rows = frame.rows();
        let cols = frame.cols();
        let channels = frame.channels();

        let bgr = match channels {
            1 => {
                let mut converted = core::Mat::default();
                imgproc::cvt_color_def(&frame, &mut converted, imgproc::COLOR_GRAY2BGR)
                    .context("OpenCV GRAY2BGR conversion failed")?;
                converted.data_bytes()?.to_vec()
            }
            3 => frame.data_bytes()?.to_vec(),
            4 => {
                let mut converted = core::Mat::default();
                imgproc::cvt_color_def(&frame, &mut converted, imgproc::COLOR_BGRA2BGR)
                    .context("OpenCV BGRA2BGR conversion failed")?;
                converted.data_bytes()?.to_vec()
            }
            other => bail!("unsupported OpenCV channel count: {other}"),
        };

        Ok((bgr, cols as u32, rows as u32))
    }
}

impl FfmpegBackend {
    fn new(device: &str, width: u32, height: u32, format: CaptureFormat) -> Result<Self> {
        let input_format = ffmpeg_input_format(format);
        let output_pix_fmt = ffmpeg_output_pix_fmt(format);

        let mut child = Command::new("ffmpeg")
            .args([
                "-hide_banner",
                "-loglevel",
                "error",
                "-nostdin",
                "-fflags",
                "nobuffer",
                "-flags",
                "low_delay",
                "-probesize",
                "32",
                "-analyzeduration",
                "0",
                "-f",
                "v4l2",
                "-input_format",
                input_format,
                "-video_size",
                &format!("{}x{}", width, height),
                "-framerate",
                "30",
                "-i",
                device,
                "-pix_fmt",
                output_pix_fmt,
                "-f",
                "rawvideo",
                "-",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("failed to spawn ffmpeg sidecar")?;

        let stdout = child.stdout.take().context("ffmpeg stdout missing")?;
        Ok(Self {
            child,
            stdout: BufReader::new(stdout),
            width,
            height,
            format,
        })
    }

    fn next_frame(&mut self) -> Result<(Vec<u8>, u32, u32)> {
        match self.format {
            CaptureFormat::Grey => {
                let frame_size = (self.width * self.height) as usize;
                let mut gray = vec![0u8; frame_size];
                self.stdout
                    .read_exact(&mut gray)
                    .context("failed to read gray frame from ffmpeg")?;

                let mut bgr = Vec::with_capacity(frame_size * 3);
                for g in gray {
                    bgr.push(g);
                    bgr.push(g);
                    bgr.push(g);
                }
                Ok((bgr, self.width, self.height))
            }
            CaptureFormat::Mjpeg | CaptureFormat::Yuyv => {
                let frame_size = (self.width * self.height * 3) as usize;
                let mut bgr = vec![0u8; frame_size];
                self.stdout
                    .read_exact(&mut bgr)
                    .context("failed to read bgr frame from ffmpeg")?;
                Ok((bgr, self.width, self.height))
            }
        }
    }
}

impl Drop for FfmpegBackend {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Auto-detect a suitable camera device.
fn find_camera_device() -> Result<String> {
    let by_path = Path::new("/dev/v4l/by-path");
    if by_path.is_dir() {
        if let Ok(entries) = std::fs::read_dir(by_path) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.contains("ir") || name.contains("infrared") {
                    if let Ok(resolved) = std::fs::canonicalize(entry.path()) {
                        return Ok(resolved.to_string_lossy().to_string());
                    }
                }
            }
        }
    }

    for i in 0..10 {
        let path = format!("/dev/video{i}");
        if Path::new(&path).exists() {
            if let Ok(dev) = v4l::Device::with_path(&path) {
                if let Ok(caps) = dev.query_caps() {
                    if caps
                        .capabilities
                        .contains(v4l::capability::Flags::VIDEO_CAPTURE)
                    {
                        return Ok(path);
                    }
                }
            }
        }
    }

    bail!("No camera device found. Set video.device_path in config.")
}

/// Negotiate the best capture format.
fn negotiate_format(
    device: &v4l::Device,
    req_width: i32,
    req_height: i32,
) -> Result<(u32, u32, CaptureFormat)> {
    use v4l::format::Format;
    use v4l::FourCC;

    let preferred = [
        (FourCC::new(b"MJPG"), CaptureFormat::Mjpeg),
        (FourCC::new(b"YUYV"), CaptureFormat::Yuyv),
        (FourCC::new(b"GREY"), CaptureFormat::Grey),
    ];

    let width = if req_width > 0 { req_width as u32 } else { 640 };
    let height = if req_height > 0 {
        req_height as u32
    } else {
        480
    };

    for (fourcc, cap_fmt) in &preferred {
        let fmt = Format::new(width, height, *fourcc);

        match CaptureTraitImport::set_format(device, &fmt) {
            Ok(actual) => {
                let actual_fmt = match &actual.fourcc.repr {
                    b"MJPG" => Some(CaptureFormat::Mjpeg),
                    b"YUYV" => Some(CaptureFormat::Yuyv),
                    b"GREY" => Some(CaptureFormat::Grey),
                    _ => None,
                };

                if let Some(fmt) = actual_fmt {
                    return Ok((actual.width, actual.height, fmt));
                }

                debug!(
                    "Driver returned {:?} instead of requested {:?}",
                    actual.fourcc, cap_fmt
                );
            }
            Err(e) => {
                debug!("Format {fourcc:?} not supported: {e}");
            }
        }
    }

    let current = CaptureTraitImport::format(device)?;
    warn!("Using device default format: {:?}", current.fourcc);

    let cap_fmt = match &current.fourcc.repr {
        b"MJPG" => CaptureFormat::Mjpeg,
        b"YUYV" => CaptureFormat::Yuyv,
        b"GREY" => CaptureFormat::Grey,
        _ => CaptureFormat::Yuyv,
    };

    Ok((current.width, current.height, cap_fmt))
}

fn ffmpeg_input_format(format: CaptureFormat) -> &'static str {
    match format {
        CaptureFormat::Grey => "gray",
        CaptureFormat::Yuyv => "yuyv422",
        CaptureFormat::Mjpeg => "mjpeg",
    }
}

fn ffmpeg_output_pix_fmt(format: CaptureFormat) -> &'static str {
    match format {
        CaptureFormat::Grey => "gray",
        CaptureFormat::Yuyv | CaptureFormat::Mjpeg => "bgr24",
    }
}
