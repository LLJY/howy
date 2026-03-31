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
use std::pin::Pin;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use opencv::{core, imgproc, prelude::*, videoio};
use tracing::{debug, info, warn};
use v4l::buffer::Type as BufType;
use v4l::io::traits::CaptureStream;
use v4l::video::Capture as CaptureTraitImport;

/// Pixel format of a captured frame.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FrameFormat {
    /// 3 bytes per pixel: Blue, Green, Red.
    Bgr,
    /// 1 byte per pixel: grayscale intensity.
    Gray,
}

/// A captured camera frame with format metadata.
pub struct Frame {
    pub data: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub format: FrameFormat,
}

impl Frame {
    /// Convert to BGR data. If already BGR, returns a borrowed view.
    /// If Gray, expands to BGR.
    pub fn to_bgr_data(&self) -> (std::borrow::Cow<'_, [u8]>, u32, u32) {
        match self.format {
            FrameFormat::Bgr => (
                std::borrow::Cow::Borrowed(&self.data),
                self.width,
                self.height,
            ),
            FrameFormat::Gray => {
                let mut bgr = Vec::with_capacity(self.data.len() * 3);
                for &g in &self.data {
                    bgr.push(g);
                    bgr.push(g);
                    bgr.push(g);
                }
                (std::borrow::Cow::Owned(bgr), self.width, self.height)
            }
        }
    }
}

const FRAME_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// Pre-resolved camera parameters with a warm device fd.
/// Computed once at daemon startup. The device fd is kept open (no streaming,
/// no IR LED, no power draw) to skip the ~2-25ms format negotiation on each auth.
pub struct CameraProfile {
    pub device_path: String,
    pub width: u32,
    pub height: u32,
    pub format: CaptureFormat,
    pub fps: i32,
    pub exposure: i32,
    /// Warm device fd. Held open to skip re-negotiation.
    /// Protected by Mutex since Camera::from_profile borrows it from a thread.
    device: Mutex<Option<v4l::Device>>,
}

impl CameraProfile {
    /// Probe the camera once and keep the device fd warm.
    pub fn probe(
        device_path: &str,
        req_width: i32,
        req_height: i32,
        fps: i32,
        exposure: i32,
    ) -> Result<Self> {
        let path = if device_path.is_empty() {
            find_camera_device()?
        } else {
            device_path.to_string()
        };

        info!("Probing camera (one-time): {path}");

        let device = v4l::Device::with_path(&path)
            .context(format!("failed to open camera device: {path}"))?;

        let caps = device.query_caps()?;
        info!("Camera: {} ({})", caps.card, caps.driver);

        let (width, height, format) = negotiate_format(&device, req_width, req_height)?;
        info!("Camera format: {width}x{height} ({format:?})");

        Ok(Self {
            device_path: path,
            width,
            height,
            format,
            fps,
            exposure,
            device: Mutex::new(Some(device)),
        })
    }

    /// Take a warm device fd. Opens a fresh one if already taken.
    /// Returns None only if opening fails.
    pub fn take_device(&self) -> Option<v4l::Device> {
        // Try the cached device first
        if let Ok(mut slot) = self.device.lock() {
            if let Some(dev) = slot.take() {
                return Some(dev);
            }
        }
        // Cached device was already taken — open a fresh one.
        // This is cheaper than the full probe (just fd open + format set).
        match v4l::Device::with_path(&self.device_path) {
            Ok(dev) => {
                let _ = negotiate_format(&dev, self.width as i32, self.height as i32);
                Some(dev)
            }
            Err(e) => {
                debug!("Failed to reopen camera device: {e}");
                None
            }
        }
    }

    /// Return the device fd for reuse by the next auth request.
    pub fn return_device(&self, device: v4l::Device) {
        if let Ok(mut slot) = self.device.lock() {
            *slot = Some(device);
        }
    }
}

/// A camera capture device.
pub struct Camera {
    width: u32,
    height: u32,
    format: CaptureFormat,
    device_path: String,
    fps: i32,
    exposure: i32,
    warm_device: Option<v4l::Device>,
    worker: Option<CaptureWorker>,
}

struct CaptureWorker {
    latest_message: Arc<Mutex<Option<CaptureMessage>>>,
    notify_rx: mpsc::Receiver<()>,
    stop_tx: mpsc::Sender<()>,
    thread_handle: Option<std::thread::JoinHandle<()>>,
}

enum CaptureMessage {
    Frame(Frame),
    Error(String),
}

enum Backend {
    V4l2Mmap(V4l2MmapBackend),
    OpenCv(OpenCvBackend),
    Ffmpeg(FfmpegBackend),
}

/// V4L2 mmap streaming backend — ~70ms faster first-frame than OpenCV.
///
/// Uses raw V4L2 mmap buffers instead of OpenCV's VideoCapture.
/// The `Device` is heap-pinned and the `Stream` borrows it; both are dropped
/// together (stream first) so the borrow is always valid.
struct V4l2MmapBackend {
    // SAFETY: `stream` is dropped before `_device` because fields drop in
    // declaration order. The stream borrows device's handle via Arc, so
    // it remains valid for the stream's lifetime.
    stream: v4l::io::mmap::Stream<'static>,
    _device: Pin<Box<v4l::Device>>,
    width: u32,
    height: u32,
    format: CaptureFormat,
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
    /// Create a camera from a pre-probed profile (skips device probe).
    /// Takes the warm device fd from the profile if available.
    pub fn from_profile(profile: &CameraProfile) -> Self {
        let warm_device = profile.take_device();
        Self {
            width: profile.width,
            height: profile.height,
            format: profile.format,
            device_path: profile.device_path.clone(),
            fps: profile.fps,
            exposure: profile.exposure,
            warm_device,
            worker: None,
        }
    }

    /// Probe a camera device and prepare it for later start.
    ///
    /// This does not open a persistent capture stream yet. `start()` does that,
    /// which keeps the camera cold until an auth request actually begins.
    pub fn open(
        device_path: &str,
        req_width: i32,
        req_height: i32,
        fps: i32,
        exposure: i32,
    ) -> Result<Self> {
        let profile = CameraProfile::probe(device_path, req_width, req_height, fps, exposure)?;
        Ok(Self::from_profile(&profile))
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
        let fps = self.fps;
        let exposure = self.exposure;
        let warm_device = self.warm_device.take();

        let latest_message = Arc::new(Mutex::new(None));
        let latest_message_worker = Arc::clone(&latest_message);
        let (notify_tx, notify_rx) = mpsc::sync_channel(1);
        let (stop_tx, stop_rx) = mpsc::channel();

        let handle = thread::spawn(move || {
            capture_worker_loop(
                device_path,
                width,
                height,
                format,
                fps,
                exposure,
                warm_device,
                latest_message_worker,
                notify_tx,
                stop_rx,
            );
        });

        self.worker = Some(CaptureWorker {
            latest_message,
            notify_rx,
            stop_tx,
            thread_handle: Some(handle),
        });

        Ok(())
    }

    /// Capture a single frame with pixel format metadata.
    pub fn capture_frame(&mut self) -> Result<Frame> {
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
            // Signal the worker to stop and wait for it to fully release
            // the camera device. Without join, the next auth request may
            // race with the kernel releasing the V4L2 device.
            let _ = worker.stop_tx.send(());
            if let Some(handle) = worker.thread_handle {
                let _ = handle.join();
            }
        }
    }
}

fn capture_worker_loop(
    device_path: String,
    width: u32,
    height: u32,
    format: CaptureFormat,
    fps: i32,
    exposure: i32,
    warm_device: Option<v4l::Device>,
    latest_message: Arc<Mutex<Option<CaptureMessage>>>,
    notify_tx: mpsc::SyncSender<()>,
    stop_rx: mpsc::Receiver<()>,
) {
    let mut backend = match start_backend(
        &device_path,
        width,
        height,
        format,
        fps,
        exposure,
        warm_device,
    ) {
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

        let can_fallback = matches!(&backend, Backend::V4l2Mmap(_) | Backend::OpenCv(_));
        let frame_result = match &mut backend {
            Backend::V4l2Mmap(backend) => backend.next_frame(),
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
            Err(e) if can_fallback => {
                warn!("Capture failed ({e:#}); falling back to next backend");
                // Try OpenCV first, then ffmpeg
                match OpenCvBackend::new(&device_path, width, height, fps, exposure) {
                    Ok(opencv_backend) => {
                        info!("Fell back to OpenCV camera backend");
                        backend = Backend::OpenCv(opencv_backend);
                        continue;
                    }
                    Err(opencv_err) => {
                        debug!("OpenCV fallback failed: {opencv_err:#}");
                    }
                }
                match FfmpegBackend::new(&device_path, width, height, format, fps) {
                    Ok(ffmpeg_backend) => {
                        info!("Fell back to ffmpeg camera backend");
                        backend = Backend::Ffmpeg(ffmpeg_backend);
                    }
                    Err(fallback_error) => {
                        warn!("All backends failed: {e:#}; ffmpeg: {fallback_error:#}");
                        let _ = publish_message(
                            &latest_message,
                            &notify_tx,
                            CaptureMessage::Error(format!(
                                "All capture backends failed: {e:#}; ffmpeg: {fallback_error:#}"
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
    fps: i32,
    exposure: i32,
    warm_device: Option<v4l::Device>,
) -> Result<Backend> {
    // Priority: warm V4L2 mmap (fastest) → cold V4L2 mmap → OpenCV → ffmpeg
    if let Some(dev) = warm_device {
        match V4l2MmapBackend::from_device(dev, width, height, format) {
            Ok(backend) => {
                debug!("Using V4L2 mmap backend (warm device fd)");
                return Ok(Backend::V4l2Mmap(backend));
            }
            Err(e) => {
                debug!("V4L2 mmap warm path failed: {e:#}; trying cold open");
            }
        }
    }

    match V4l2MmapBackend::new(device_path, width, height, format) {
        Ok(backend) => {
            return Ok(Backend::V4l2Mmap(backend));
        }
        Err(e) => {
            debug!("V4L2 mmap backend unavailable: {e:#}; trying OpenCV");
        }
    }

    match OpenCvBackend::new(device_path, width, height, fps, exposure) {
        Ok(backend) => {
            debug!("Using OpenCV CAP_V4L camera backend");
            Ok(Backend::OpenCv(backend))
        }
        Err(e) => {
            warn!("OpenCV backend unavailable: {e:#}; falling back to ffmpeg");
            let backend = FfmpegBackend::new(device_path, width, height, format, fps)?;
            debug!("Using ffmpeg camera backend");
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

fn decode_capture_message(message: CaptureMessage) -> Result<Frame> {
    match message {
        CaptureMessage::Frame(frame) => Ok(frame),
        CaptureMessage::Error(message) => Err(anyhow!(message)),
    }
}

impl V4l2MmapBackend {
    /// Create from an existing pre-opened device (warm path).
    fn from_device(
        dev: v4l::Device,
        width: u32,
        height: u32,
        format: CaptureFormat,
    ) -> Result<Self> {
        let device = Box::pin(dev);
        Self::create_stream(device, width, height, format)
    }

    /// Create by opening a fresh device (cold path / fallback).
    fn new(device_path: &str, width: u32, height: u32, format: CaptureFormat) -> Result<Self> {
        use v4l::format::Format;
        use v4l::FourCC;

        let dev =
            v4l::Device::with_path(device_path).context("failed to open V4L2 device for mmap")?;

        let fourcc = match format {
            CaptureFormat::Grey => FourCC::new(b"GREY"),
            CaptureFormat::Yuyv => FourCC::new(b"YUYV"),
            CaptureFormat::Mjpeg => FourCC::new(b"MJPG"),
        };
        let fmt = Format::new(width, height, fourcc);
        let _actual = CaptureTraitImport::set_format(&dev, &fmt)
            .context("V4L2 mmap: failed to set format")?;

        let device = Box::pin(dev);
        Self::create_stream(device, width, height, format)
    }

    fn create_stream(
        device: Pin<Box<v4l::Device>>,
        width: u32,
        height: u32,
        format: CaptureFormat,
    ) -> Result<Self> {
        // SAFETY: We transmute the stream lifetime to 'static. This is safe
        // because the stream is stored in the same struct as the device and
        // fields drop in declaration order (stream before _device). The stream
        // only holds an Arc<Handle> cloned from the device, not a direct reference.
        let stream = unsafe {
            let dev_ref: &v4l::Device = &*device;
            let dev_ref_static: &'static v4l::Device = std::mem::transmute(dev_ref);
            v4l::io::mmap::Stream::with_buffers(dev_ref_static, BufType::VideoCapture, 2)
                .context("V4L2 mmap: failed to create stream")?
        };

        debug!("Using V4L2 mmap backend: {width}x{height} ({format:?})");

        Ok(Self {
            stream,
            _device: device,
            width,
            height,
            format,
        })
    }

    fn next_frame(&mut self) -> Result<Frame> {
        let (buf, _meta) = self
            .stream
            .next()
            .context("V4L2 mmap: failed to read frame")?;

        match self.format {
            CaptureFormat::Grey => Ok(Frame {
                data: buf.to_vec(),
                width: self.width,
                height: self.height,
                format: FrameFormat::Gray,
            }),
            CaptureFormat::Yuyv => {
                // YUYV → BGR conversion: each 4 bytes = 2 pixels
                let npixels = (self.width * self.height) as usize;
                let mut bgr = Vec::with_capacity(npixels * 3);
                for chunk in buf.chunks_exact(4) {
                    let y0 = chunk[0] as f32;
                    let u = chunk[1] as f32 - 128.0;
                    let y1 = chunk[2] as f32;
                    let v = chunk[3] as f32 - 128.0;
                    for y in [y0, y1] {
                        let r = (y + 1.402 * v).clamp(0.0, 255.0) as u8;
                        let g = (y - 0.344 * u - 0.714 * v).clamp(0.0, 255.0) as u8;
                        let b = (y + 1.772 * u).clamp(0.0, 255.0) as u8;
                        bgr.push(b);
                        bgr.push(g);
                        bgr.push(r);
                    }
                }
                Ok(Frame {
                    data: bgr,
                    width: self.width,
                    height: self.height,
                    format: FrameFormat::Bgr,
                })
            }
            CaptureFormat::Mjpeg => {
                // Decode MJPEG via OpenCV
                let mat = core::Mat::from_slice(buf)
                    .context("V4L2 mmap: failed to create Mat from MJPEG")?;
                let decoded = opencv::imgcodecs::imdecode(&mat, opencv::imgcodecs::IMREAD_COLOR)
                    .context("V4L2 mmap: MJPEG decode failed")?;
                if decoded.empty() {
                    bail!("V4L2 mmap: MJPEG decode returned empty frame");
                }
                Ok(Frame {
                    data: decoded.data_bytes()?.to_vec(),
                    width: decoded.cols() as u32,
                    height: decoded.rows() as u32,
                    format: FrameFormat::Bgr,
                })
            }
        }
    }
}

impl OpenCvBackend {
    fn new(device: &str, width: u32, height: u32, fps: i32, exposure: i32) -> Result<Self> {
        let mut cap = videoio::VideoCapture::from_file(device, videoio::CAP_V4L)
            .context("failed to open device with OpenCV CAP_V4L")?;

        if !cap.is_opened()? {
            bail!("OpenCV could not open device {device}");
        }

        // Best-effort low-latency knobs. Some drivers ignore these.
        let _ = cap.set(videoio::CAP_PROP_FRAME_WIDTH, width as f64);
        let _ = cap.set(videoio::CAP_PROP_FRAME_HEIGHT, height as f64);
        let _ = cap.set(videoio::CAP_PROP_BUFFERSIZE, 1.0);

        if fps > 0 {
            let _ = cap.set(videoio::CAP_PROP_FPS, fps as f64);
        }
        // fps < 0: leave at device default (don't force 30fps — some IR
        // emitters need specific frame rates).

        if exposure >= 0 {
            // Disable auto-exposure (V4L2_EXPOSURE_MANUAL = 1)
            let _ = cap.set(videoio::CAP_PROP_AUTO_EXPOSURE, 1.0);
            let _ = cap.set(videoio::CAP_PROP_EXPOSURE, exposure as f64);
        } else {
            // Explicitly request auto-exposure (V4L2_EXPOSURE_APERTURE_PRIORITY = 3)
            let _ = cap.set(videoio::CAP_PROP_AUTO_EXPOSURE, 3.0);
        }

        Ok(Self { cap })
    }

    fn next_frame(&mut self) -> Result<Frame> {
        let mut frame = core::Mat::default();
        self.cap.read(&mut frame).context("OpenCV read() failed")?;
        if frame.empty() {
            bail!("OpenCV returned empty frame");
        }

        let rows = frame.rows();
        let cols = frame.cols();
        let channels = frame.channels();

        match channels {
            1 => {
                // Return grayscale directly — no BGR expansion needed.
                Ok(Frame {
                    data: frame.data_bytes()?.to_vec(),
                    width: cols as u32,
                    height: rows as u32,
                    format: FrameFormat::Gray,
                })
            }
            3 => Ok(Frame {
                data: frame.data_bytes()?.to_vec(),
                width: cols as u32,
                height: rows as u32,
                format: FrameFormat::Bgr,
            }),
            4 => {
                let mut converted = core::Mat::default();
                imgproc::cvt_color_def(&frame, &mut converted, imgproc::COLOR_BGRA2BGR)
                    .context("OpenCV BGRA2BGR conversion failed")?;
                Ok(Frame {
                    data: converted.data_bytes()?.to_vec(),
                    width: cols as u32,
                    height: rows as u32,
                    format: FrameFormat::Bgr,
                })
            }
            other => bail!("unsupported OpenCV channel count: {other}"),
        }
    }
}

impl FfmpegBackend {
    fn new(device: &str, width: u32, height: u32, format: CaptureFormat, fps: i32) -> Result<Self> {
        let input_format = ffmpeg_input_format(format);
        let output_pix_fmt = ffmpeg_output_pix_fmt(format);
        let fps_str = if fps > 0 {
            fps.to_string()
        } else {
            "30".to_string()
        };

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
                &fps_str,
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

    fn next_frame(&mut self) -> Result<Frame> {
        match self.format {
            CaptureFormat::Grey => {
                let frame_size = (self.width * self.height) as usize;
                let mut gray = vec![0u8; frame_size];
                self.stdout
                    .read_exact(&mut gray)
                    .context("failed to read gray frame from ffmpeg")?;
                Ok(Frame {
                    data: gray,
                    width: self.width,
                    height: self.height,
                    format: FrameFormat::Gray,
                })
            }
            CaptureFormat::Mjpeg | CaptureFormat::Yuyv => {
                let frame_size = (self.width * self.height * 3) as usize;
                let mut bgr = vec![0u8; frame_size];
                self.stdout
                    .read_exact(&mut bgr)
                    .context("failed to read bgr frame from ffmpeg")?;
                Ok(Frame {
                    data: bgr,
                    width: self.width,
                    height: self.height,
                    format: FrameFormat::Bgr,
                })
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
