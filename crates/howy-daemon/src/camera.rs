//! Camera capture backend for howy.
//!
//! Design goals:
//! - Keep the camera cold until authentication starts
//! - Prefer direct V4L2 mmap capture
//! - Optionally fall back to a persistent ffmpeg rawvideo sidecar for awkward IR devices
//! - Never write frames to disk in the real pipeline
//!
//! Notes on performance:
//! - Models stay hot in memory / GPU
//! - Camera is opened only for the auth window
//! - For GREY/IR devices we keep capture grayscale as long as possible, then
//!   expand to BGR immediately before inference because the current inference
//!   stack expects 3-channel BGR input.

use std::collections::VecDeque;
use std::io::{self, Cursor, Read};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::pin::Pin;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
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

// 128 MiB accommodates tightly packed 8K BGR output (~95 MiB) and 8K YUYV
// capture (~63 MiB), while preventing a malformed format from requesting
// multi-gigabyte mappings or normalized frames in this authentication daemon.
const MAX_MAPPED_BUFFER_BYTES: usize = 128 * 1024 * 1024;
const MAX_NORMALIZED_FRAME_BYTES: usize = 128 * 1024 * 1024;

// MJPEG has a tighter decoder envelope than raw capture. These limits admit
// DCI-4K (4096x2160, including portrait rotation) while bounding zune-jpeg's
// encoded-input copy, progressive coefficient storage, upsampling scratch, and
// decoded output to a conservative daemon-scale working set. image::Limits is
// still applied as defense in depth, but max_alloc is not an aggregate cap.
const MAX_MJPEG_ENCODED_BYTES: usize = 16 * 1024 * 1024;
const MAX_MJPEG_DIMENSION: u32 = 4096;
const MAX_MJPEG_PIXELS: usize = 4096 * 2160;

const FFMPEG_STDERR_TAIL_BYTES: usize = 16 * 1024;

/// Pre-resolved camera parameters.
/// Computed once at daemon startup or lazily on first camera use.
pub struct CameraProfile {
    device_path: String,
    width: u32,
    height: u32,
    format: CaptureFormat,
    fps: i32,
    exposure: i32,
}

impl CameraProfile {
    /// Probe the camera once and cache the negotiated settings.
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

        let (negotiated, format) = negotiate_format(&device, req_width, req_height)?;
        let width = negotiated.width;
        let height = negotiated.height;
        info!("Camera format: {width}x{height} ({format:?})");
        debug!(
            fourcc = ?negotiated.fourcc,
            stride = negotiated.stride,
            size_image = negotiated.size,
            "Negotiated V4L2 format details"
        );

        Ok(Self {
            device_path: path,
            width,
            height,
            format,
            fps,
            exposure,
        })
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
    Ffmpeg(FfmpegBackend),
}

trait BackendCapture {
    fn next_frame(&mut self) -> Result<Frame>;
    fn supports_fallback(&self) -> bool;
}

impl BackendCapture for Backend {
    fn next_frame(&mut self) -> Result<Frame> {
        match self {
            Backend::V4l2Mmap(backend) => backend.next_frame(),
            Backend::Ffmpeg(backend) => backend.next_frame(),
        }
    }

    fn supports_fallback(&self) -> bool {
        matches!(self, Backend::V4l2Mmap(_))
    }
}

enum BackendEvent {
    Frame(Frame),
    FellBack(anyhow::Error),
}

/// V4L2 mmap streaming backend.
///
/// Uses raw V4L2 mmap buffers without an intermediary capture framework.
/// The `Device` is heap-pinned and the `Stream` borrows it; both are dropped
/// together (stream first) so the borrow is always valid.
struct V4l2MmapBackend {
    // SAFETY: `stream` is dropped before `_device` because fields drop in
    // declaration order. The stream borrows device's handle via Arc, so
    // it remains valid for the stream's lifetime.
    stream: v4l::io::mmap::Stream<'static>,
    _device: Pin<Box<v4l::Device>>,
    negotiated: v4l::format::Format,
}

struct FfmpegBackend {
    child: Child,
    stdout: ChildStdout,
    stderr: StderrDrainer,
    width: u32,
    height: u32,
    format: CaptureFormat,
    frame_size: usize,
}

struct StderrDrainer {
    tail: Arc<Mutex<StderrTail>>,
    handle: Option<thread::JoinHandle<()>>,
}

struct StderrTail {
    bytes: VecDeque<u8>,
    capacity: usize,
}

impl StderrTail {
    fn new(capacity: usize) -> Self {
        Self {
            bytes: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        if self.capacity == 0 {
            return;
        }
        if bytes.len() >= self.capacity {
            self.bytes.clear();
            self.bytes
                .extend(bytes[bytes.len() - self.capacity..].iter().copied());
            return;
        }
        let overflow = self
            .bytes
            .len()
            .saturating_add(bytes.len())
            .saturating_sub(self.capacity);
        self.bytes.drain(..overflow);
        self.bytes.extend(bytes.iter().copied());
    }

    fn snapshot(&self) -> String {
        let bytes = self.bytes.iter().copied().collect::<Vec<_>>();
        String::from_utf8_lossy(&bytes).trim().to_string()
    }
}

impl StderrDrainer {
    fn spawn<R>(mut stderr: R) -> Self
    where
        R: Read + Send + 'static,
    {
        let tail = Arc::new(Mutex::new(StderrTail::new(FFMPEG_STDERR_TAIL_BYTES)));
        let tail_worker = Arc::clone(&tail);
        let handle = thread::spawn(move || {
            let mut chunk = [0_u8; 4096];
            loop {
                match stderr.read(&mut chunk) {
                    Ok(0) => return,
                    Ok(read) => {
                        let mut tail = match tail_worker.lock() {
                            Ok(tail) => tail,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        tail.push(&chunk[..read]);
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => return,
                }
            }
        });
        Self {
            tail,
            handle: Some(handle),
        }
    }

    fn snapshot(&self) -> String {
        let tail = match self.tail.lock() {
            Ok(tail) => tail,
            Err(poisoned) => poisoned.into_inner(),
        };
        tail.snapshot()
    }

    fn finish(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum TimedReadFailure {
    Timeout {
        received: usize,
    },
    Eof {
        received: usize,
    },
    Io {
        received: usize,
        kind: io::ErrorKind,
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum CaptureFormat {
    Mjpeg,
    Yuyv,
    Grey,
}

impl Camera {
    /// Create a camera from a pre-probed profile (skips device probe).
    pub fn from_profile(profile: &CameraProfile) -> Self {
        Self {
            width: profile.width,
            height: profile.height,
            format: profile.format,
            device_path: profile.device_path.clone(),
            fps: profile.fps,
            exposure: profile.exposure,
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
    /// 1. Try V4L2 mmap first
    /// 2. Fall back to an optional persistent ffmpeg sidecar
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

    /// Stop the active capture worker, if any.
    pub fn stop(&mut self) {
        if let Some(worker) = self.worker.take() {
            // Signal the worker to stop and wait with a bounded timeout.
            // If the worker is stuck on blocking I/O, we don't want to
            // wedge the auth thread (and hold the camera lock) forever.
            let _ = worker.stop_tx.send(());
            if let Some(handle) = worker.thread_handle {
                // Park for up to 500ms for a clean shutdown.
                let deadline = std::time::Instant::now() + Duration::from_millis(500);
                loop {
                    if handle.is_finished() {
                        let _ = handle.join();
                        break;
                    }
                    if std::time::Instant::now() >= deadline {
                        warn!("Camera worker did not stop within 500ms; abandoning join");
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
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
        self.stop();
    }
}

fn capture_worker_loop(
    device_path: String,
    width: u32,
    height: u32,
    format: CaptureFormat,
    fps: i32,
    exposure: i32,
    latest_message: Arc<Mutex<Option<CaptureMessage>>>,
    notify_tx: mpsc::SyncSender<()>,
    stop_rx: mpsc::Receiver<()>,
) {
    let backend = match start_backend(&device_path, width, height, format, fps, exposure) {
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
    let mut backend = Some(backend);

    loop {
        match stop_rx.try_recv() {
            Ok(()) | Err(mpsc::TryRecvError::Disconnected) => {
                debug!("Camera capture worker stopping");
                return;
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }

        let event = capture_backend_once(&mut backend, || {
            FfmpegBackend::new(&device_path, width, height, format, fps, exposure)
                .map(Backend::Ffmpeg)
        });
        match event {
            Ok(BackendEvent::Frame(frame)) => {
                if !publish_message(&latest_message, &notify_tx, CaptureMessage::Frame(frame)) {
                    debug!("Camera frame receiver dropped");
                    return;
                }
            }
            Ok(BackendEvent::FellBack(error)) => {
                warn!("V4L2 capture failed ({error:#}); fell back to FFmpeg");
                info!("Fell back to ffmpeg camera backend");
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
) -> Result<Backend> {
    start_backend_with(
        || {
            V4l2MmapBackend::new(device_path, width, height, format, fps, exposure)
                .map(Backend::V4l2Mmap)
        },
        || {
            FfmpegBackend::new(device_path, width, height, format, fps, exposure)
                .map(Backend::Ffmpeg)
        },
    )
}

fn start_backend_with<T>(
    try_v4l2: impl FnOnce() -> Result<T>,
    try_ffmpeg: impl FnOnce() -> Result<T>,
) -> Result<T> {
    match try_v4l2() {
        Ok(backend) => Ok(backend),
        Err(v4l2_error) => {
            debug!("V4L2 mmap backend unavailable: {v4l2_error:#}; trying optional FFmpeg");
            match try_ffmpeg() {
                Ok(backend) => Ok(backend),
                Err(ffmpeg_error) => Err(anyhow!(
                    "V4L2 mmap backend failed: {v4l2_error:#}; optional FFmpeg fallback failed: {ffmpeg_error:#}"
                )),
            }
        }
    }
}

fn construct_fallback_after_release<T, U>(
    failed_backend: &mut Option<T>,
    construct: impl FnOnce() -> Result<U>,
) -> Result<U> {
    drop(failed_backend.take());
    construct()
}

fn capture_backend_once<B>(
    backend: &mut Option<B>,
    construct_fallback: impl FnOnce() -> Result<B>,
) -> Result<BackendEvent>
where
    B: BackendCapture,
{
    let supports_fallback = backend
        .as_ref()
        .context("capture backend missing")?
        .supports_fallback();
    let frame_result = backend
        .as_mut()
        .context("capture backend missing")?
        .next_frame();

    match frame_result {
        Ok(frame) => Ok(BackendEvent::Frame(frame)),
        Err(capture_error) if supports_fallback => {
            let fallback = construct_fallback_after_release(backend, construct_fallback).map_err(
                |fallback_error| {
                    anyhow!(
                        "V4L2 capture failed: {capture_error:#}; optional FFmpeg fallback failed: {fallback_error:#}"
                    )
                },
            )?;
            *backend = Some(fallback);
            Ok(BackendEvent::FellBack(capture_error))
        }
        Err(error) => Err(error),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CaptureSettingsPlan {
    fps: Option<u32>,
    exposure: ExposurePlan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExposurePlan {
    Manual(i64),
    AperturePriority,
}

fn capture_settings_plan(fps: i32, exposure: i32) -> CaptureSettingsPlan {
    CaptureSettingsPlan {
        fps: u32::try_from(fps).ok().filter(|fps| *fps > 0),
        exposure: if exposure >= 0 {
            ExposurePlan::Manual(i64::from(exposure))
        } else {
            ExposurePlan::AperturePriority
        },
    }
}

fn exposure_controls(plan: ExposurePlan) -> Vec<v4l::control::Control> {
    use v4l::control::{Control, Value};
    use v4l::v4l_sys::{
        V4L2_CID_EXPOSURE_ABSOLUTE, V4L2_CID_EXPOSURE_AUTO,
        v4l2_exposure_auto_type_V4L2_EXPOSURE_APERTURE_PRIORITY,
        v4l2_exposure_auto_type_V4L2_EXPOSURE_MANUAL,
    };

    match plan {
        ExposurePlan::Manual(value) => vec![
            Control {
                id: V4L2_CID_EXPOSURE_AUTO,
                value: Value::Integer(i64::from(v4l2_exposure_auto_type_V4L2_EXPOSURE_MANUAL)),
            },
            Control {
                id: V4L2_CID_EXPOSURE_ABSOLUTE,
                value: Value::Integer(value),
            },
        ],
        ExposurePlan::AperturePriority => vec![Control {
            id: V4L2_CID_EXPOSURE_AUTO,
            value: Value::Integer(i64::from(
                v4l2_exposure_auto_type_V4L2_EXPOSURE_APERTURE_PRIORITY,
            )),
        }],
    }
}

fn apply_v4l2_settings(device: &v4l::Device, fps: i32, exposure: i32) {
    let plan = capture_settings_plan(fps, exposure);

    if let Some(fps) = plan.fps {
        let params = v4l::video::capture::Parameters::with_fps(fps);
        match CaptureTraitImport::set_params(device, &params) {
            Ok(actual) => debug!(
                requested_fps = fps,
                actual_interval = %actual.interval,
                "Applied V4L2 frame rate"
            ),
            Err(error) => debug!(
                requested_fps = fps,
                %error,
                "V4L2 frame-rate control unsupported; retaining driver setting"
            ),
        }
    }

    for control in exposure_controls(plan.exposure) {
        let id = control.id;
        let value = match &control.value {
            v4l::control::Value::Integer(value) => *value,
            _ => unreachable!("exposure control plan only contains integer controls"),
        };
        match device.set_control(control) {
            Ok(()) => debug!(control_id = id, value, "Applied V4L2 exposure control"),
            Err(error) => debug!(
                control_id = id,
                value,
                %error,
                "V4L2 exposure control unsupported; retaining driver setting"
            ),
        }
    }
}

fn apply_v4l2_settings_before_ffmpeg(device_path: &str, fps: i32, exposure: i32) {
    match v4l::Device::with_path(device_path) {
        Ok(device) => {
            apply_v4l2_settings(&device, fps, exposure);
            drop(device);
        }
        Err(error) => debug!(
            device = device_path,
            %error,
            "Could not pre-apply V4L2 FPS/exposure before FFmpeg; FFmpeg will use driver state"
        ),
    }
}

impl V4l2MmapBackend {
    /// Create by opening a fresh device.
    fn new(
        device_path: &str,
        width: u32,
        height: u32,
        _format: CaptureFormat,
        fps: i32,
        exposure: i32,
    ) -> Result<Self> {
        let dev =
            v4l::Device::with_path(device_path).context("failed to open V4L2 device for mmap")?;

        let (negotiated, _) = negotiate_format(&dev, width as i32, height as i32)
            .context("V4L2 mmap: failed to set format")?;
        apply_v4l2_settings(&dev, fps, exposure);

        let device = Box::pin(dev);
        Self::create_stream(device, negotiated)
    }

    fn create_stream(
        device: Pin<Box<v4l::Device>>,
        negotiated: v4l::format::Format,
    ) -> Result<Self> {
        validate_negotiated_format(&negotiated).context("V4L2 mmap: invalid negotiated format")?;

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

        debug!(
            width = negotiated.width,
            height = negotiated.height,
            fourcc = ?negotiated.fourcc,
            stride = negotiated.stride,
            size_image = negotiated.size,
            colorspace = %negotiated.colorspace,
            quantization = %negotiated.quantization,
            "Using V4L2 mmap backend"
        );
        if matches!(&negotiated.fourcc.repr, b"YUYV") {
            debug!(
                resolved_quantization = ?yuyv_quantization(&negotiated),
                "YUYV conversion uses BT.601 coefficients; v4l 0.14 does not expose the negotiated YCbCr encoding"
            );
        }

        Ok(Self {
            stream,
            _device: device,
            negotiated,
        })
    }

    fn next_frame(&mut self) -> Result<Frame> {
        let (buf, meta) = self
            .stream
            .next()
            .context("V4L2 mmap: failed to read frame")?;

        match normalize_mmap_payload(buf, meta.bytesused, &self.negotiated)? {
            NormalizedMmapPayload::Frame(frame) => Ok(frame),
            NormalizedMmapPayload::Mjpeg(payload) => decode_mjpeg(payload, &self.negotiated),
        }
    }
}

enum NormalizedMmapPayload<'a> {
    Frame(Frame),
    Mjpeg(&'a [u8]),
}

/// Validate a V4L2 mmap payload and normalize raw formats into tightly packed data.
///
/// This boundary is deliberately independent of a camera device so malformed
/// driver metadata and padded raw rows can be covered with pure unit tests.
fn normalize_mmap_payload<'a>(
    mapped: &'a [u8],
    bytesused: u32,
    format: &v4l::format::Format,
) -> Result<NormalizedMmapPayload<'a>> {
    let bytesused = usize::try_from(bytesused).context("V4L2 bytesused does not fit usize")?;
    if bytesused == 0 {
        bail!("V4L2 mmap: frame payload is empty");
    }
    if bytesused > mapped.len() {
        bail!(
            "V4L2 mmap: bytesused {bytesused} exceeds mapped buffer length {}",
            mapped.len()
        );
    }
    let capture_format = capture_format_from_fourcc(format.fourcc)?;
    if matches!(capture_format, CaptureFormat::Mjpeg) {
        validate_mjpeg_payload_len(bytesused, format.size)?;
    }
    let payload = &mapped[..bytesused];

    match capture_format {
        CaptureFormat::Mjpeg => Ok(NormalizedMmapPayload::Mjpeg(payload)),
        CaptureFormat::Grey => normalize_grey(payload, format).map(NormalizedMmapPayload::Frame),
        CaptureFormat::Yuyv => normalize_yuyv(payload, format).map(NormalizedMmapPayload::Frame),
    }
}

fn validate_mjpeg_payload_len(payload_len: usize, size_image: u32) -> Result<()> {
    validate_mjpeg_encoded_len(payload_len)?;

    let size_image =
        usize::try_from(size_image).context("V4L2 MJPEG sizeimage does not fit usize")?;
    if size_image == 0 {
        bail!("V4L2 MJPEG sizeimage must be nonzero");
    }
    validate_mjpeg_encoded_len(size_image)
        .context("V4L2 MJPEG negotiated sizeimage exceeds decoder envelope")?;
    if payload_len > size_image {
        bail!("V4L2 MJPEG payload {payload_len} exceeds negotiated sizeimage {size_image}");
    }
    Ok(())
}

fn validate_mjpeg_encoded_len(encoded_len: usize) -> Result<()> {
    if encoded_len == 0 {
        bail!("V4L2 MJPEG encoded payload must be nonzero");
    }
    if encoded_len > MAX_MJPEG_ENCODED_BYTES {
        bail!(
            "V4L2 MJPEG encoded payload exceeds the {MAX_MJPEG_ENCODED_BYTES}-byte decoder limit: {encoded_len} bytes"
        );
    }
    Ok(())
}

fn validate_mjpeg_header(
    payload: &[u8],
    size_image: u32,
    negotiated_width: u32,
    negotiated_height: u32,
) -> Result<(u32, u32)> {
    if payload.is_empty() {
        bail!("V4L2 mmap: MJPEG payload is empty");
    }
    validate_mjpeg_payload_len(payload.len(), size_image)?;
    // The decoded header must equal these negotiated dimensions, so validate
    // their per-axis and pixel ceilings before ImageReader buffers the input.
    validate_mjpeg_geometry(negotiated_width, negotiated_height)?;

    // ImageReader may buffer the encoded input, so payload and sizeimage limits
    // are enforced above before constructing it. It does not decode the full
    // pixel image for this dimensions-only operation.
    let dimensions =
        image::ImageReader::with_format(Cursor::new(payload), image::ImageFormat::Jpeg)
            .into_dimensions()
            .context("V4L2 mmap: malformed MJPEG header")?;
    validate_mjpeg_dimensions(
        dimensions.0,
        dimensions.1,
        negotiated_width,
        negotiated_height,
    )?;
    Ok(dimensions)
}

fn validate_mjpeg_dimensions(
    width: u32,
    height: u32,
    negotiated_width: u32,
    negotiated_height: u32,
) -> Result<()> {
    validate_mjpeg_geometry(width, height)?;
    if width != negotiated_width || height != negotiated_height {
        bail!(
            "V4L2 mmap: MJPEG dimensions {width}x{height} do not match negotiated dimensions {negotiated_width}x{negotiated_height}"
        );
    }
    Ok(())
}

fn validate_mjpeg_geometry(width: u32, height: u32) -> Result<()> {
    validate_dimensions(width, height, "MJPEG")?;
    if width > MAX_MJPEG_DIMENSION || height > MAX_MJPEG_DIMENSION {
        bail!(
            "V4L2 MJPEG dimensions {width}x{height} exceed the {MAX_MJPEG_DIMENSION}-pixel per-axis decoder limit"
        );
    }
    let pixels = usize::try_from(width)
        .ok()
        .and_then(|width| {
            usize::try_from(height)
                .ok()
                .and_then(|height| width.checked_mul(height))
        })
        .context("V4L2 MJPEG pixel count overflow")?;
    if pixels > MAX_MJPEG_PIXELS {
        bail!("V4L2 MJPEG pixel count {pixels} exceeds the {MAX_MJPEG_PIXELS}-pixel decoder limit");
    }
    checked_frame_len(width, height, 3, "MJPEG")?;
    Ok(())
}

fn decode_mjpeg(payload: &[u8], format: &v4l::format::Format) -> Result<Frame> {
    validate_mjpeg_header(payload, format.size, format.width, format.height)?;

    let mut limits = image::Limits::default();
    limits.max_image_width = Some(format.width);
    limits.max_image_height = Some(format.height);
    // Best-effort decoder-local guard only; explicit encoded/dimension/pixel
    // ceilings above define the conservative envelope.
    limits.max_alloc = Some(MAX_NORMALIZED_FRAME_BYTES as u64);

    let mut reader =
        image::ImageReader::with_format(Cursor::new(payload), image::ImageFormat::Jpeg);
    reader.limits(limits);
    let decoded = reader.decode().context("V4L2 mmap: MJPEG decode failed")?;

    decoded_mjpeg_to_frame(decoded, format.width, format.height)
}

fn decoded_mjpeg_to_frame(
    decoded: image::DynamicImage,
    negotiated_width: u32,
    negotiated_height: u32,
) -> Result<Frame> {
    match decoded {
        image::DynamicImage::ImageLuma8(image) => {
            let width = image.width();
            let height = image.height();
            validate_mjpeg_dimensions(width, height, negotiated_width, negotiated_height)?;
            let expected = checked_frame_len(width, height, 1, "MJPEG grayscale")?;
            let data = image.into_raw();
            validate_decoded_mjpeg_len(data.len(), expected)?;
            Ok(Frame {
                data,
                width,
                height,
                format: FrameFormat::Gray,
            })
        }
        image::DynamicImage::ImageRgb8(image) => {
            let width = image.width();
            let height = image.height();
            validate_mjpeg_dimensions(width, height, negotiated_width, negotiated_height)?;
            let expected = checked_frame_len(width, height, 3, "MJPEG RGB")?;
            let mut data = image.into_raw();
            validate_decoded_mjpeg_len(data.len(), expected)?;
            rgb_to_bgr_in_place(&mut data);
            Ok(Frame {
                data,
                width,
                height,
                format: FrameFormat::Bgr,
            })
        }
        unsupported => bail!(
            "V4L2 mmap: unsupported decoded MJPEG color type {:?}; expected L8 or RGB8",
            unsupported.color()
        ),
    }
}

fn validate_decoded_mjpeg_len(actual: usize, expected: usize) -> Result<()> {
    if actual == 0 || actual != expected {
        bail!("V4L2 mmap: decoded MJPEG data length {actual} does not match expected {expected}");
    }
    Ok(())
}

fn rgb_to_bgr_in_place(data: &mut [u8]) {
    for pixel in data.chunks_exact_mut(3) {
        pixel.swap(0, 2);
    }
}

fn normalize_grey(payload: &[u8], format: &v4l::format::Format) -> Result<Frame> {
    validate_dimensions(format.width, format.height, "GREY")?;

    let width = usize::try_from(format.width).context("GREY width does not fit usize")?;
    let height = usize::try_from(format.height).context("GREY height does not fit usize")?;
    let stride = effective_stride(format.stride, width, "GREY")?;

    let output_len = checked_frame_len(format.width, format.height, 1, "GREY")?;
    validate_raw_payload(payload, height, stride, width, format.size, "GREY")?;

    let mut gray = Vec::new();
    gray.try_reserve_exact(output_len)
        .context("V4L2 GREY output allocation is too large")?;
    for row in 0..height {
        let start = row
            .checked_mul(stride)
            .context("V4L2 GREY row offset overflow")?;
        let end = start
            .checked_add(width)
            .context("V4L2 GREY row end overflow")?;
        gray.extend_from_slice(&payload[start..end]);
    }

    Ok(Frame {
        data: gray,
        width: format.width,
        height: format.height,
        format: FrameFormat::Gray,
    })
}

fn normalize_yuyv(payload: &[u8], format: &v4l::format::Format) -> Result<Frame> {
    validate_dimensions(format.width, format.height, "YUYV")?;
    if format.width % 2 != 0 {
        bail!("V4L2 YUYV width {} must be even", format.width);
    }

    let width = usize::try_from(format.width).context("YUYV width does not fit usize")?;
    let height = usize::try_from(format.height).context("YUYV height does not fit usize")?;
    let active_row_bytes = width
        .checked_mul(2)
        .context("V4L2 YUYV active row size overflow")?;
    let stride = effective_stride(format.stride, active_row_bytes, "YUYV")?;
    let quantization = yuyv_quantization(format);

    let output_len = checked_frame_len(format.width, format.height, 3, "YUYV")?;
    validate_raw_payload(
        payload,
        height,
        stride,
        active_row_bytes,
        format.size,
        "YUYV",
    )?;

    let mut bgr = Vec::new();
    bgr.try_reserve_exact(output_len)
        .context("V4L2 YUYV output allocation is too large")?;
    for row in 0..height {
        let start = row
            .checked_mul(stride)
            .context("V4L2 YUYV row offset overflow")?;
        let end = start
            .checked_add(active_row_bytes)
            .context("V4L2 YUYV row end overflow")?;
        for chunk in payload[start..end].chunks_exact(4) {
            for y in [chunk[0], chunk[2]] {
                bgr.extend_from_slice(&yuyv_to_bgr_bt601(y, chunk[1], chunk[3], quantization));
            }
        }
    }

    Ok(Frame {
        data: bgr,
        width: format.width,
        height: format.height,
        format: FrameFormat::Bgr,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum YuyvQuantization {
    FullRange,
    LimitedRange,
}

fn yuyv_quantization(format: &v4l::format::Format) -> YuyvQuantization {
    use v4l::format::{Colorspace, Quantization};

    match format.quantization {
        Quantization::FullRange => YuyvQuantization::FullRange,
        Quantization::LimitedRange => YuyvQuantization::LimitedRange,
        // Per V4L2's non-RGB default mapping, JPEG YCbCr is full-range and
        // other webcam YUV colorspaces are limited-range.
        Quantization::Default if matches!(format.colorspace, Colorspace::JPEG) => {
            YuyvQuantization::FullRange
        }
        Quantization::Default => YuyvQuantization::LimitedRange,
    }
}

/// Convert one YUYV pixel to BGR using BT.601 coefficients.
///
/// `v4l` 0.14 does not expose `ycbcr_enc`, so this intentionally retains the
/// daemon's BT.601-compatible matrix rather than claiming Rec.709/2020 support.
fn yuyv_to_bgr_bt601(y: u8, u: u8, v: u8, quantization: YuyvQuantization) -> [u8; 3] {
    let u = u as f32 - 128.0;
    let v = v as f32 - 128.0;
    let (y, r, g, b) = match quantization {
        YuyvQuantization::FullRange => {
            let y = y as f32;
            (y, 1.402 * v, -0.344 * u - 0.714 * v, 1.772 * u)
        }
        YuyvQuantization::LimitedRange => {
            let y = (255.0 / 219.0) * (y as f32 - 16.0);
            (
                y,
                1.596_027 * v,
                -0.391_762 * u - 0.812_968 * v,
                2.017_232 * u,
            )
        }
    };

    [
        (y + b).clamp(0.0, 255.0) as u8,
        (y + g).clamp(0.0, 255.0) as u8,
        (y + r).clamp(0.0, 255.0) as u8,
    ]
}

fn validate_dimensions(width: u32, height: u32, name: &str) -> Result<()> {
    if width == 0 || height == 0 {
        bail!("V4L2 {name} dimensions must be nonzero, got {width}x{height}");
    }
    Ok(())
}

fn checked_frame_len(width: u32, height: u32, bytes_per_pixel: usize, name: &str) -> Result<usize> {
    let width = usize::try_from(width).context("V4L2 frame width does not fit usize")?;
    let height = usize::try_from(height).context("V4L2 frame height does not fit usize")?;
    let len = width
        .checked_mul(height)
        .and_then(|pixels| pixels.checked_mul(bytes_per_pixel))
        .with_context(|| format!("V4L2 {name} output size overflow"))?;
    if len > MAX_NORMALIZED_FRAME_BYTES {
        bail!(
            "V4L2 {name} output exceeds the {MAX_NORMALIZED_FRAME_BYTES}-byte daemon limit: {len} bytes"
        );
    }
    Ok(len)
}

fn effective_stride(reported_stride: u32, active_row_bytes: usize, name: &str) -> Result<usize> {
    let reported = usize::try_from(reported_stride)
        .with_context(|| format!("V4L2 {name} stride does not fit usize"))?;
    Ok(reported.max(active_row_bytes))
}

fn checked_raw_payload_len(
    height: usize,
    stride: usize,
    active_row_bytes: usize,
    name: &str,
) -> Result<usize> {
    let last_row = height
        .checked_sub(1)
        .context("V4L2 raw frame height is zero")?;
    let required = last_row
        .checked_mul(stride)
        .and_then(|offset| offset.checked_add(active_row_bytes))
        .with_context(|| format!("V4L2 {name} payload size overflow"))?;
    if required > MAX_MAPPED_BUFFER_BYTES {
        bail!(
            "V4L2 {name} payload exceeds the {MAX_MAPPED_BUFFER_BYTES}-byte daemon limit: {required} bytes"
        );
    }
    Ok(required)
}

fn validate_raw_payload(
    payload: &[u8],
    height: usize,
    stride: usize,
    active_row_bytes: usize,
    size_image: u32,
    name: &str,
) -> Result<()> {
    let required = checked_raw_payload_len(height, stride, active_row_bytes, name)?;
    if payload.len() < required {
        bail!(
            "V4L2 {name} payload is truncated: bytesused {}, need at least {required} (sizeimage {size_image})",
            payload.len()
        );
    }
    Ok(())
}

fn validate_negotiated_format(format: &v4l::format::Format) -> Result<()> {
    let capture_format = capture_format_from_fourcc(format.fourcc)?;
    validate_dimensions(format.width, format.height, "frame")?;

    let size_image = usize::try_from(format.size).context("V4L2 sizeimage does not fit usize")?;
    if size_image == 0 {
        bail!("V4L2 {:?} sizeimage must be nonzero", format.fourcc);
    }
    if size_image > MAX_MAPPED_BUFFER_BYTES {
        bail!(
            "V4L2 sizeimage exceeds the {MAX_MAPPED_BUFFER_BYTES}-byte mapped-buffer limit: {size_image} bytes"
        );
    }

    match capture_format {
        CaptureFormat::Mjpeg => {
            validate_mjpeg_encoded_len(size_image)
                .context("V4L2 MJPEG sizeimage exceeds decoder envelope")?;
            validate_mjpeg_geometry(format.width, format.height)?;
        }
        CaptureFormat::Grey => {
            validate_negotiated_raw_format(format, 1, "GREY", size_image)?;
            checked_frame_len(format.width, format.height, 3, "GREY BGR expansion")?;
        }
        CaptureFormat::Yuyv => {
            if format.width % 2 != 0 {
                bail!("V4L2 YUYV width {} must be even", format.width);
            }
            validate_negotiated_raw_format(format, 2, "YUYV", size_image)?;
        }
    }

    Ok(())
}

fn validate_negotiated_raw_format(
    format: &v4l::format::Format,
    input_bytes_per_pixel: usize,
    name: &str,
    size_image: usize,
) -> Result<()> {
    let width = usize::try_from(format.width).context("V4L2 width does not fit usize")?;
    let height = usize::try_from(format.height).context("V4L2 height does not fit usize")?;
    let active_row_bytes = width
        .checked_mul(input_bytes_per_pixel)
        .with_context(|| format!("V4L2 {name} active row size overflow"))?;
    let stride = effective_stride(format.stride, active_row_bytes, name)?;
    let required = checked_raw_payload_len(height, stride, active_row_bytes, name)?;
    if size_image < required {
        bail!("V4L2 {name} sizeimage {size_image} is smaller than the required payload {required}");
    }
    let output_bytes_per_pixel = if input_bytes_per_pixel == 1 { 1 } else { 3 };
    checked_frame_len(format.width, format.height, output_bytes_per_pixel, name)?;
    Ok(())
}

impl FfmpegBackend {
    /// Start the optional compatibility fallback.
    ///
    /// FFmpeg receives an explicit positive FPS when configured, but a
    /// non-positive FPS is left to the V4L2 device. FPS and exposure are first
    /// applied best-effort through a temporary V4L2 handle, which is dropped
    /// before FFmpeg starts; no non-portable FFmpeg exposure flags are invented.
    fn new(
        device: &str,
        width: u32,
        height: u32,
        format: CaptureFormat,
        fps: i32,
        exposure: i32,
    ) -> Result<Self> {
        let output_bytes_per_pixel = if matches!(format, CaptureFormat::Grey) {
            1
        } else {
            3
        };
        let frame_size =
            checked_frame_len(width, height, output_bytes_per_pixel, "FFmpeg fallback")?;
        if matches!(format, CaptureFormat::Grey) {
            checked_frame_len(width, height, 3, "FFmpeg GREY BGR expansion")?;
        }
        apply_v4l2_settings_before_ffmpeg(device, fps, exposure);
        let args = ffmpeg_args(device, width, height, format, fps);
        let mut child = Command::new("ffmpeg")
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| {
                format!(
                    "failed to spawn optional FFmpeg camera fallback for {device}; ensure ffmpeg is installed"
                )
            })?;

        let stdout = child.stdout.take().context("ffmpeg stdout missing")?;
        let stderr = child.stderr.take().context("ffmpeg stderr missing")?;
        Ok(Self {
            child,
            stdout,
            stderr: StderrDrainer::spawn(stderr),
            width,
            height,
            format,
            frame_size,
        })
    }

    fn next_frame(&mut self) -> Result<Frame> {
        match self.format {
            CaptureFormat::Grey => {
                let mut gray = vec![0u8; self.frame_size];
                self.read_frame(&mut gray, "grayscale")?;
                Ok(Frame {
                    data: gray,
                    width: self.width,
                    height: self.height,
                    format: FrameFormat::Gray,
                })
            }
            CaptureFormat::Mjpeg | CaptureFormat::Yuyv => {
                let mut bgr = vec![0u8; self.frame_size];
                self.read_frame(&mut bgr, "BGR")?;
                Ok(Frame {
                    data: bgr,
                    width: self.width,
                    height: self.height,
                    format: FrameFormat::Bgr,
                })
            }
        }
    }

    fn read_frame(&mut self, frame: &mut [u8], description: &str) -> Result<()> {
        self.read_frame_with_timeout(frame, description, FRAME_READ_TIMEOUT)
    }

    fn read_frame_with_timeout(
        &mut self,
        frame: &mut [u8],
        description: &str,
        timeout: Duration,
    ) -> Result<()> {
        let deadline = Instant::now() + timeout;
        let stdout_fd = self.stdout.as_raw_fd();
        match read_exact_until(&mut self.stdout, frame, deadline, |deadline| {
            wait_for_fd_until(stdout_fd, deadline)
        }) {
            Ok(()) => Ok(()),
            Err(TimedReadFailure::Timeout { received }) => Err(self.with_stderr_tail(format!(
                "timed out after {}ms waiting for {description} frame from FFmpeg ({received}/{} bytes)",
                timeout.as_millis(),
                frame.len()
            ))),
            Err(TimedReadFailure::Eof { received }) => {
                Err(self.output_failure(description, received, frame.len()))
            }
            Err(TimedReadFailure::Io {
                received,
                kind,
                message,
            }) => Err(self.with_stderr_tail(format!(
                "failed reading {description} frame from FFmpeg ({received}/{} bytes): {kind:?}: {message}",
                frame.len()
            ))),
        }
    }

    fn output_failure(
        &mut self,
        description: &str,
        received: usize,
        expected: usize,
    ) -> anyhow::Error {
        match self.child.try_wait() {
            Ok(Some(status)) => {
                self.stderr.finish();
                self.with_stderr_tail(format!(
                    "FFmpeg exited {status} before a complete {description} frame was read ({received}/{expected} bytes)"
                ))
            }
            Ok(None) => self.with_stderr_tail(format!(
                "FFmpeg closed its output before a complete {description} frame was read ({received}/{expected} bytes)"
            )),
            Err(error) => self.with_stderr_tail(format!(
                "FFmpeg output ended after {received}/{expected} bytes and process status failed: {error}"
            )),
        }
    }

    fn with_stderr_tail(&self, message: String) -> anyhow::Error {
        let stderr = self.stderr.snapshot();
        if stderr.is_empty() {
            anyhow!(message)
        } else {
            anyhow!("{message}; FFmpeg stderr tail: {stderr}")
        }
    }
}

fn read_exact_until<R>(
    reader: &mut R,
    frame: &mut [u8],
    deadline: Instant,
    mut wait: impl FnMut(Instant) -> io::Result<bool>,
) -> std::result::Result<(), TimedReadFailure>
where
    R: Read,
{
    let mut offset = 0;
    while offset < frame.len() {
        if Instant::now() >= deadline {
            return Err(TimedReadFailure::Timeout { received: offset });
        }
        match wait(deadline) {
            Ok(true) => {}
            Ok(false) => return Err(TimedReadFailure::Timeout { received: offset }),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(TimedReadFailure::Io {
                    received: offset,
                    kind: error.kind(),
                    message: error.to_string(),
                });
            }
        }
        match reader.read(&mut frame[offset..]) {
            Ok(0) => return Err(TimedReadFailure::Eof { received: offset }),
            Ok(read) => offset += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(TimedReadFailure::Io {
                    received: offset,
                    kind: error.kind(),
                    message: error.to_string(),
                });
            }
        }
    }
    Ok(())
}

fn wait_for_fd_until(fd: i32, deadline: Instant) -> io::Result<bool> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }
        let timeout_ms = remaining
            .as_millis()
            .saturating_add(1)
            .min(i32::MAX as u128) as i32;
        let mut poll_fd = libc::pollfd {
            fd,
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        // SAFETY: poll_fd points to one valid pollfd for the duration of the call.
        let result = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
        if result > 0 {
            return Ok(true);
        }
        if result == 0 {
            return Ok(false);
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(error);
    }
}

fn cleanup_ffmpeg_process(child: &mut Child, stderr: &mut StderrDrainer) {
    if matches!(child.try_wait(), Ok(None)) {
        let _ = child.kill();
    }
    let _ = child.wait();
    stderr.finish();
}

impl Drop for FfmpegBackend {
    fn drop(&mut self) {
        cleanup_ffmpeg_process(&mut self.child, &mut self.stderr);
    }
}

/// Auto-detect a suitable camera device.
fn find_camera_device() -> Result<String> {
    let by_path = Path::new("/dev/v4l/by-path");
    if by_path.is_dir() {
        let mut entries: Vec<_> = std::fs::read_dir(by_path)
            .context("failed to read /dev/v4l/by-path")?
            .flatten()
            .collect();
        entries.sort_by(|a, b| {
            a.file_name()
                .to_string_lossy()
                .cmp(&b.file_name().to_string_lossy())
        });

        if !entries.is_empty() {
            for entry in &entries {
                let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
                let path = entry.path();
                if (name.contains("ir") || name.contains("infrared"))
                    && is_video_capture_device(&path)
                {
                    return Ok(path.to_string_lossy().to_string());
                }
            }

            for entry in entries {
                let path = entry.path();
                if is_video_capture_device(&path) {
                    return Ok(path.to_string_lossy().to_string());
                }
            }

            bail!(
                "No usable capture device found in /dev/v4l/by-path. Set video.device_path in config."
            );
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

fn is_video_capture_device(path: &Path) -> bool {
    match v4l::Device::with_path(path) {
        Ok(dev) => match dev.query_caps() {
            Ok(caps) => caps
                .capabilities
                .contains(v4l::capability::Flags::VIDEO_CAPTURE),
            Err(_) => false,
        },
        Err(_) => false,
    }
}

/// Negotiate the best capture format.
fn negotiate_format(
    device: &v4l::Device,
    req_width: i32,
    req_height: i32,
) -> Result<(v4l::format::Format, CaptureFormat)> {
    use v4l::FourCC;
    use v4l::format::Format;

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
                if let Ok(actual_fmt) = capture_format_from_fourcc(actual.fourcc) {
                    return Ok((actual, actual_fmt));
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

    let cap_fmt = capture_format_from_fourcc(current.fourcc)?;

    Ok((current, cap_fmt))
}

fn capture_format_from_fourcc(fourcc: v4l::FourCC) -> Result<CaptureFormat> {
    match &fourcc.repr {
        b"MJPG" => Ok(CaptureFormat::Mjpeg),
        b"YUYV" => Ok(CaptureFormat::Yuyv),
        b"GREY" => Ok(CaptureFormat::Grey),
        _ => bail!("unsupported V4L2 FourCC: {fourcc:?}"),
    }
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

fn ffmpeg_args(
    device: &str,
    width: u32,
    height: u32,
    format: CaptureFormat,
    fps: i32,
) -> Vec<String> {
    let mut args = [
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
        ffmpeg_input_format(format),
        "-video_size",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    args.push(format!("{width}x{height}"));

    // A non-positive FPS means "use the device/default policy". FFmpeg's V4L2
    // input accepts an omitted -framerate, so do not silently force 30 FPS.
    if fps > 0 {
        args.push("-framerate".to_string());
        args.push(fps.to_string());
    }

    args.extend(
        [
            "-i",
            device,
            "-pix_fmt",
            ffmpeg_output_pix_fmt(format),
            "-f",
            "rawvideo",
            "-",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    args
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::ImageEncoder;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    fn format(width: u32, height: u32, fourcc: &[u8; 4], stride: u32) -> v4l::format::Format {
        let mut format = v4l::format::Format::new(width, height, v4l::FourCC::new(fourcc));
        format.stride = stride;
        format.size = stride.checked_mul(height).unwrap_or(u32::MAX);
        format
    }

    fn normalized_frame(mapped: &[u8], bytesused: u32, format: &v4l::format::Format) -> Frame {
        match normalize_mmap_payload(mapped, bytesused, format).unwrap() {
            NormalizedMmapPayload::Frame(frame) => frame,
            NormalizedMmapPayload::Mjpeg(_) => panic!("expected normalized raw frame"),
        }
    }

    fn synthetic_jpeg(width: u32, height: u32) -> Vec<u8> {
        synthetic_rgb_jpeg(width, height, [42, 42, 42])
    }

    fn synthetic_rgb_jpeg(width: u32, height: u32, rgb: [u8; 3]) -> Vec<u8> {
        let pixel_count = usize::try_from(width.checked_mul(height).unwrap()).unwrap();
        let pixels = rgb.repeat(pixel_count);
        let mut encoded = Vec::new();
        image::codecs::jpeg::JpegEncoder::new_with_quality(&mut encoded, 90)
            .write_image(&pixels, width, height, image::ExtendedColorType::Rgb8)
            .unwrap();
        encoded
    }

    fn synthetic_gray_jpeg(width: u32, height: u32, gray: u8) -> Vec<u8> {
        let pixel_count = usize::try_from(width.checked_mul(height).unwrap()).unwrap();
        let pixels = vec![gray; pixel_count];
        let mut encoded = Vec::new();
        image::codecs::jpeg::JpegEncoder::new_with_quality(&mut encoded, 90)
            .write_image(&pixels, width, height, image::ExtendedColorType::L8)
            .unwrap();
        encoded
    }

    fn fake_ffmpeg_backend(script: &str, frame_size: usize) -> FfmpegBackend {
        let mut child = Command::new("sh")
            .args(["-c", script])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        FfmpegBackend {
            child,
            stdout,
            stderr: StderrDrainer::spawn(stderr),
            width: u32::try_from(frame_size).unwrap(),
            height: 1,
            format: CaptureFormat::Grey,
            frame_size,
        }
    }

    #[test]
    fn normalizes_exact_grey_rows() {
        let format = format(3, 2, b"GREY", 3);
        let frame = normalized_frame(&[1, 2, 3, 4, 5, 6], 6, &format);

        assert_eq!(frame.data, [1, 2, 3, 4, 5, 6]);
        assert_eq!((frame.width, frame.height), (3, 2));
        assert_eq!(frame.format, FrameFormat::Gray);
    }

    #[test]
    fn strips_grey_row_padding() {
        let format = format(2, 2, b"GREY", 4);
        let frame = normalized_frame(&[1, 2, 90, 91, 3, 4, 92, 93], 8, &format);

        assert_eq!(frame.data, [1, 2, 3, 4]);
    }

    #[test]
    fn accepts_grey_payload_without_final_row_padding() {
        let format = format(2, 2, b"GREY", 4);
        let frame = normalized_frame(&[1, 2, 90, 91, 3, 4], 6, &format);

        assert_eq!(frame.data, [1, 2, 3, 4]);
    }

    #[test]
    fn converts_full_range_yuyv_chroma_to_bgr() {
        let mut format = format(2, 1, b"YUYV", 4);
        format.quantization = v4l::format::Quantization::FullRange;
        let frame = normalized_frame(&[100, 90, 150, 240], 4, &format);

        assert_eq!(frame.data, [32, 33, 255, 82, 83, 255]);
        assert_eq!(frame.format, FrameFormat::Bgr);
    }

    #[test]
    fn converts_limited_range_yuyv_chroma_to_bgr() {
        let mut format = format(2, 1, b"YUYV", 4);
        format.quantization = v4l::format::Quantization::LimitedRange;
        let frame = normalized_frame(&[100, 90, 150, 240], 4, &format);

        assert_eq!(frame.data, [21, 21, 255, 79, 79, 255]);
    }

    #[test]
    fn converts_full_range_neutral_black_and_white() {
        let mut format = format(2, 1, b"YUYV", 4);
        format.quantization = v4l::format::Quantization::FullRange;
        let frame = normalized_frame(&[0, 128, 255, 128], 4, &format);

        assert_eq!(frame.data, [0, 0, 0, 255, 255, 255]);
    }

    #[test]
    fn converts_limited_range_neutral_black_and_white() {
        let mut format = format(2, 1, b"YUYV", 4);
        format.quantization = v4l::format::Quantization::LimitedRange;
        let frame = normalized_frame(&[16, 128, 235, 128], 4, &format);

        assert_eq!(frame.data, [0, 0, 0, 255, 255, 255]);
    }

    #[test]
    fn resolves_default_yuyv_quantization_from_colorspace() {
        let mut jpeg = format(2, 1, b"YUYV", 4);
        jpeg.colorspace = v4l::format::Colorspace::JPEG;
        assert_eq!(yuyv_quantization(&jpeg), YuyvQuantization::FullRange);

        let mut webcam = format(2, 1, b"YUYV", 4);
        webcam.colorspace = v4l::format::Colorspace::SRGB;
        assert_eq!(yuyv_quantization(&webcam), YuyvQuantization::LimitedRange);

        let unspecified = format(2, 1, b"YUYV", 4);
        assert_eq!(
            yuyv_quantization(&unspecified),
            YuyvQuantization::LimitedRange
        );
    }

    #[test]
    fn converts_yuyv_rows_without_reading_padding() {
        let mut format = format(2, 2, b"YUYV", 6);
        format.quantization = v4l::format::Quantization::FullRange;
        let frame = normalized_frame(
            &[100, 90, 150, 240, 1, 2, 50, 240, 200, 90, 3, 4],
            12,
            &format,
        );

        assert_eq!(
            frame.data,
            [32, 33, 255, 82, 83, 255, 248, 38, 0, 255, 188, 146]
        );
    }

    #[test]
    fn accepts_yuyv_payload_without_final_row_padding() {
        let mut format = format(2, 2, b"YUYV", 6);
        format.quantization = v4l::format::Quantization::FullRange;
        let frame = normalized_frame(&[10, 128, 20, 128, 90, 91, 30, 128, 40, 128], 10, &format);

        assert_eq!(frame.data, [10, 10, 10, 20, 20, 20, 30, 30, 30, 40, 40, 40]);
    }

    #[test]
    fn rejects_bytesused_larger_than_mapping() {
        let format = format(2, 1, b"GREY", 2);
        let error = normalize_mmap_payload(&[1, 2], 3, &format)
            .err()
            .expect("oversized bytesused should fail");

        assert!(error.to_string().contains("exceeds mapped buffer length"));
    }

    #[test]
    fn rejects_empty_and_truncated_payloads() {
        let grey = format(2, 2, b"GREY", 2);
        assert!(normalize_mmap_payload(&[0; 4], 0, &grey).is_err());
        assert!(normalize_mmap_payload(&[1, 2, 3], 3, &grey).is_err());

        let yuyv = format(2, 2, b"YUYV", 4);
        assert!(normalize_mmap_payload(&[0; 7], 7, &yuyv).is_err());
    }

    #[test]
    fn decodes_zero_and_short_raw_strides_as_tightly_packed() {
        let mut zero_stride = format(2, 2, b"GREY", 0);
        zero_stride.size = 4;
        let grey = normalized_frame(&[1, 2, 3, 4], 4, &zero_stride);
        assert_eq!(grey.data, [1, 2, 3, 4]);

        let mut short_stride = format(2, 1, b"YUYV", 3);
        short_stride.size = 4;
        short_stride.quantization = v4l::format::Quantization::FullRange;
        let yuyv = normalized_frame(&[100, 90, 150, 240], 4, &short_stride);
        assert_eq!(yuyv.data, [32, 33, 255, 82, 83, 255]);
    }

    #[test]
    fn rejects_zero_dimensions() {
        let zero_width = format(0, 1, b"GREY", 1);
        assert!(normalize_mmap_payload(&[1], 1, &zero_width).is_err());

        let zero_height = format(2, 0, b"GREY", 2);
        assert!(normalize_mmap_payload(&[1, 2], 2, &zero_height).is_err());
    }

    #[test]
    fn rejects_odd_width_yuyv() {
        let format = format(3, 1, b"YUYV", 6);
        assert!(normalize_mmap_payload(&[0; 6], 6, &format).is_err());
    }

    #[test]
    fn rejects_output_over_daemon_limit_architecture_neutrally() {
        let width = u32::try_from(MAX_NORMALIZED_FRAME_BYTES + 1).unwrap();
        let format = format(width, 1, b"GREY", width);
        let error = normalize_mmap_payload(&[1], 1, &format)
            .err()
            .expect("oversized output should fail");

        assert!(error.to_string().contains("daemon limit"));
    }

    #[test]
    fn validates_negotiated_resource_limits_before_mapping() {
        let mjpeg_without_size = format(640, 480, b"MJPG", 0);
        assert!(validate_negotiated_format(&mjpeg_without_size).is_err());

        let mut oversized_mjpeg = format(640, 480, b"MJPG", 0);
        oversized_mjpeg.size = u32::try_from(MAX_MAPPED_BUFFER_BYTES + 1).unwrap();
        assert!(validate_negotiated_format(&oversized_mjpeg).is_err());

        let mut undersized_raw = format(2, 2, b"GREY", 2);
        undersized_raw.size = 3;
        assert!(validate_negotiated_format(&undersized_raw).is_err());

        let eight_k_yuyv = format(7680, 4320, b"YUYV", 15_360);
        assert!(validate_negotiated_format(&eight_k_yuyv).is_ok());
    }

    #[test]
    fn bounds_grey_eventual_bgr_expansion() {
        let eight_k_grey = format(7680, 4320, b"GREY", 7680);
        assert!(validate_negotiated_format(&eight_k_grey).is_ok());

        let width = u32::try_from(MAX_NORMALIZED_FRAME_BYTES / 3 + 1).unwrap();
        let expansion_too_large = format(width, 1, b"GREY", width);
        let error = validate_negotiated_format(&expansion_too_large)
            .expect_err("eventual GREY-to-BGR expansion should be bounded");
        assert!(error.to_string().contains("GREY BGR expansion"));
    }

    #[test]
    fn validates_synthetic_mjpeg_header_dimensions() {
        let jpeg = synthetic_jpeg(2, 2);
        let size_image = u32::try_from(jpeg.len()).unwrap();

        assert_eq!(
            validate_mjpeg_header(&jpeg, size_image, 2, 2).unwrap(),
            (2, 2)
        );
    }

    #[test]
    fn decodes_grayscale_mjpeg_as_gray() {
        let jpeg = synthetic_gray_jpeg(2, 2, 80);
        let mut format = format(2, 2, b"MJPG", 0);
        format.size = u32::try_from(jpeg.len()).unwrap();

        let frame = decode_mjpeg(&jpeg, &format).unwrap();
        assert_eq!((frame.width, frame.height), (2, 2));
        assert_eq!(frame.format, FrameFormat::Gray);
        assert_eq!(frame.data.len(), 4);
    }

    #[test]
    fn decodes_rgb_mjpeg_as_bgr() {
        let jpeg = synthetic_rgb_jpeg(2, 2, [10, 60, 200]);
        let mut format = format(2, 2, b"MJPG", 0);
        format.size = u32::try_from(jpeg.len()).unwrap();

        let frame = decode_mjpeg(&jpeg, &format).unwrap();
        assert_eq!((frame.width, frame.height), (2, 2));
        assert_eq!(frame.format, FrameFormat::Bgr);
        assert_eq!(frame.data.len(), 12);
        for pixel in frame.data.chunks_exact(3) {
            assert!(pixel[0] > pixel[2], "expected BGR, got {pixel:?}");
        }
    }

    #[test]
    fn swaps_rgb_to_bgr_exactly_once() {
        let mut pixels = [1, 2, 3, 4, 5, 6];
        rgb_to_bgr_in_place(&mut pixels);
        assert_eq!(pixels, [3, 2, 1, 6, 5, 4]);
    }

    #[test]
    fn rejects_unsupported_decoded_mjpeg_color_type() {
        let rgba = image::RgbaImage::from_pixel(1, 1, image::Rgba([1, 2, 3, 4]));
        assert!(decoded_mjpeg_to_frame(image::DynamicImage::ImageRgba8(rgba), 1, 1).is_err());
    }

    #[test]
    fn rejects_mjpeg_header_dimension_mismatch() {
        let jpeg = synthetic_jpeg(2, 2);
        let size_image = u32::try_from(jpeg.len()).unwrap();

        assert!(validate_mjpeg_header(&jpeg, size_image, 3, 2).is_err());
    }

    #[test]
    fn rejects_malformed_mjpeg_header() {
        assert!(validate_mjpeg_header(b"not a jpeg", 10, 2, 2).is_err());
    }

    #[test]
    fn rejects_malformed_and_truncated_mjpeg_decode() {
        let mut malformed_format = format(2, 2, b"MJPG", 0);
        malformed_format.size = 10;
        assert!(decode_mjpeg(b"not a jpeg", &malformed_format).is_err());

        let jpeg = synthetic_rgb_jpeg(2, 2, [10, 60, 200]);
        let truncated = &jpeg[..jpeg.len() / 2];
        let mut truncated_format = format(2, 2, b"MJPG", 0);
        truncated_format.size = u32::try_from(truncated.len()).unwrap();
        assert!(decode_mjpeg(truncated, &truncated_format).is_err());
    }

    #[test]
    fn rejects_zero_and_oversized_mjpeg_dimensions_without_large_fixture() {
        assert!(validate_mjpeg_dimensions(0, 1, 0, 1).is_err());
        assert!(validate_mjpeg_dimensions(65_535, 65_535, 65_535, 65_535).is_err());
    }

    #[test]
    fn enforces_mjpeg_decoder_envelope_without_allocating() {
        assert!(validate_mjpeg_encoded_len(MAX_MJPEG_ENCODED_BYTES).is_ok());
        assert!(validate_mjpeg_encoded_len(MAX_MJPEG_ENCODED_BYTES + 1).is_err());

        assert!(validate_mjpeg_geometry(4096, 2160).is_ok());
        assert!(validate_mjpeg_geometry(MAX_MJPEG_DIMENSION + 1, 1).is_err());
        assert!(validate_mjpeg_geometry(4096, 2161).is_err());
    }

    #[test]
    fn rejects_mjpeg_payload_length_over_daemon_limit_without_allocating() {
        let payload_len = MAX_MAPPED_BUFFER_BYTES + 1;
        assert!(validate_mjpeg_payload_len(payload_len, u32::MAX).is_err());
    }

    #[test]
    fn rejects_mjpeg_payload_larger_than_negotiated_sizeimage() {
        assert!(validate_mjpeg_payload_len(5, 4).is_err());
    }

    #[test]
    fn rejects_unsupported_fourcc() {
        assert!(capture_format_from_fourcc(v4l::FourCC::new(b"RGB3")).is_err());

        let format = format(1, 1, b"RGB3", 3);
        assert!(normalize_mmap_payload(&[0; 3], 3, &format).is_err());
    }

    #[test]
    fn limits_mjpeg_to_bytesused() {
        let mut format = format(2, 1, b"MJPG", 0);
        format.size = 5;
        let mapped = [1, 2, 3, 99, 100];

        match normalize_mmap_payload(&mapped, 3, &format).unwrap() {
            NormalizedMmapPayload::Mjpeg(payload) => assert_eq!(payload, [1, 2, 3]),
            NormalizedMmapPayload::Frame(_) => panic!("expected MJPEG payload"),
        }
    }

    #[test]
    fn startup_backend_order_is_v4l2_then_ffmpeg() {
        let order = RefCell::new(Vec::new());
        let selected = start_backend_with(
            || {
                order.borrow_mut().push("v4l2");
                Err(anyhow!("unavailable"))
            },
            || {
                order.borrow_mut().push("ffmpeg");
                Ok("ffmpeg")
            },
        )
        .unwrap();

        assert_eq!(selected, "ffmpeg");
        assert_eq!(*order.borrow(), ["v4l2", "ffmpeg"]);
    }

    #[test]
    fn successful_v4l2_start_does_not_try_ffmpeg() {
        let ffmpeg_called = Cell::new(false);
        let selected = start_backend_with(
            || Ok("v4l2"),
            || {
                ffmpeg_called.set(true);
                Ok("ffmpeg")
            },
        )
        .unwrap();

        assert_eq!(selected, "v4l2");
        assert!(!ffmpeg_called.get());
    }

    #[test]
    fn production_fallback_step_drops_failed_backend_before_construction() {
        struct FakeBackend {
            fail: bool,
            can_fallback: bool,
            dropped: Rc<Cell<bool>>,
        }
        impl BackendCapture for FakeBackend {
            fn next_frame(&mut self) -> Result<Frame> {
                if self.fail {
                    Err(anyhow!("capture failed"))
                } else {
                    Ok(Frame {
                        data: vec![1],
                        width: 1,
                        height: 1,
                        format: FrameFormat::Gray,
                    })
                }
            }

            fn supports_fallback(&self) -> bool {
                self.can_fallback
            }
        }
        impl Drop for FakeBackend {
            fn drop(&mut self) {
                self.dropped.set(true);
            }
        }

        let dropped = Rc::new(Cell::new(false));
        let fallback_dropped = Rc::new(Cell::new(false));
        let mut backend = Some(FakeBackend {
            fail: true,
            can_fallback: true,
            dropped: Rc::clone(&dropped),
        });
        let event = capture_backend_once(&mut backend, || {
            assert!(dropped.get(), "failed owner must be dropped first");
            Ok(FakeBackend {
                fail: false,
                can_fallback: false,
                dropped: Rc::clone(&fallback_dropped),
            })
        })
        .unwrap();

        assert!(matches!(event, BackendEvent::FellBack(_)));
        assert!(backend.is_some());
    }

    #[test]
    fn releases_failed_backend_before_constructing_fallback() {
        struct DropProbe(Rc<Cell<bool>>);
        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }

        let dropped = Rc::new(Cell::new(false));
        let mut failed = Some(DropProbe(Rc::clone(&dropped)));
        let fallback = construct_fallback_after_release(&mut failed, || {
            assert!(dropped.get());
            Ok("ffmpeg")
        })
        .unwrap();

        assert_eq!(fallback, "ffmpeg");
        assert!(failed.is_none());
    }

    #[test]
    fn ffmpeg_args_omit_default_fps_and_include_positive_fps() {
        let default_args = ffmpeg_args("/dev/video0", 640, 480, CaptureFormat::Grey, -1);
        assert!(!default_args.iter().any(|arg| arg == "-framerate"));

        let positive_args = ffmpeg_args("/dev/video0", 640, 480, CaptureFormat::Grey, 25);
        let fps_index = positive_args
            .iter()
            .position(|arg| arg == "-framerate")
            .unwrap();
        assert_eq!(
            positive_args.get(fps_index + 1).map(String::as_str),
            Some("25")
        );
    }

    #[test]
    fn builds_v4l2_fps_and_exposure_control_plans() {
        use v4l::control::Value;
        use v4l::v4l_sys::{
            V4L2_CID_EXPOSURE_ABSOLUTE, V4L2_CID_EXPOSURE_AUTO,
            v4l2_exposure_auto_type_V4L2_EXPOSURE_APERTURE_PRIORITY,
            v4l2_exposure_auto_type_V4L2_EXPOSURE_MANUAL,
        };

        let manual = capture_settings_plan(25, 123);
        assert_eq!(manual.fps, Some(25));
        assert_eq!(manual.exposure, ExposurePlan::Manual(123));
        let controls = exposure_controls(manual.exposure);
        assert_eq!(controls.len(), 2);
        assert_eq!(controls[0].id, V4L2_CID_EXPOSURE_AUTO);
        assert_eq!(
            controls[0].value,
            Value::Integer(i64::from(v4l2_exposure_auto_type_V4L2_EXPOSURE_MANUAL))
        );
        assert_eq!(controls[1].id, V4L2_CID_EXPOSURE_ABSOLUTE);
        assert_eq!(controls[1].value, Value::Integer(123));

        let auto = capture_settings_plan(-1, -1);
        assert_eq!(auto.fps, None);
        let controls = exposure_controls(auto.exposure);
        assert_eq!(controls.len(), 1);
        assert_eq!(controls[0].id, V4L2_CID_EXPOSURE_AUTO);
        assert_eq!(
            controls[0].value,
            Value::Integer(i64::from(
                v4l2_exposure_auto_type_V4L2_EXPOSURE_APERTURE_PRIORITY
            ))
        );
    }

    #[test]
    fn timed_reader_reports_partial_and_timeout_with_absolute_deadline() {
        let mut partial = Cursor::new(vec![1_u8]);
        let mut frame = [0_u8; 2];
        let error = read_exact_until(
            &mut partial,
            &mut frame,
            Instant::now() + Duration::from_secs(1),
            |_| Ok(true),
        )
        .unwrap_err();
        assert_eq!(error, TimedReadFailure::Eof { received: 1 });

        let mut unread = Cursor::new(vec![1_u8, 2]);
        let error = read_exact_until(
            &mut unread,
            &mut frame,
            Instant::now() + Duration::from_secs(1),
            |_| Ok(false),
        )
        .unwrap_err();
        assert_eq!(error, TimedReadFailure::Timeout { received: 0 });

        let calls = Cell::new(0);
        let deadline = Instant::now() + Duration::from_secs(1);
        let error = read_exact_until(&mut unread, &mut frame, deadline, |seen_deadline| {
            assert_eq!(seen_deadline, deadline);
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                Err(io::Error::from(io::ErrorKind::Interrupted))
            } else {
                Ok(false)
            }
        })
        .unwrap_err();
        assert_eq!(calls.get(), 2);
        assert_eq!(error, TimedReadFailure::Timeout { received: 0 });
    }

    #[test]
    fn stderr_drainer_caps_tail_under_flood() {
        let flood = vec![b'x'; FFMPEG_STDERR_TAIL_BYTES * 4];
        let mut drainer = StderrDrainer::spawn(Cursor::new(flood));
        drainer.finish();
        assert_eq!(drainer.snapshot().len(), FFMPEG_STDERR_TAIL_BYTES);

        let mut tail = StderrTail::new(8);
        tail.push(b"abc");
        tail.push(b"0123456789");
        assert_eq!(tail.snapshot(), "23456789");
    }

    #[test]
    fn ffmpeg_errors_include_stderr_for_partial_exit_and_timeout() {
        let mut early = fake_ffmpeg_backend("printf early-device-busy >&2; exit 7", 1);
        let _ = early.child.wait();
        early.stderr.finish();
        let error = early
            .next_frame()
            .err()
            .expect("early FFmpeg exit should fail");
        let message = error.to_string();
        assert!(message.contains("0/1 bytes"));
        assert!(message.contains("early-device-busy"));

        let mut partial =
            fake_ffmpeg_backend("printf x; printf partial-device-busy >&2; exit 3", 2);
        let _ = partial.child.wait();
        partial.stderr.finish();
        let error = partial
            .next_frame()
            .err()
            .expect("partial FFmpeg frame should fail");
        let message = error.to_string();
        assert!(message.contains("1/2 bytes"));
        assert!(message.contains("partial-device-busy"));

        let mut timeout = fake_ffmpeg_backend("printf timeout-device-busy >&2; exec sleep 5", 1);
        thread::sleep(Duration::from_millis(10));
        let mut frame = [0_u8; 1];
        let error = timeout
            .read_frame_with_timeout(&mut frame, "test", Duration::from_millis(20))
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("timed out"));
        assert!(message.contains("timeout-device-busy"));
    }

    #[test]
    fn ffmpeg_cleanup_reaps_child_and_joins_drainer() {
        let mut child = Command::new("sh")
            .args(["-c", "exec sleep 5"])
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let mut drainer = StderrDrainer::spawn(stderr);

        cleanup_ffmpeg_process(&mut child, &mut drainer);

        assert!(child.try_wait().unwrap().is_some());
        assert!(drainer.handle.is_none());
    }
}
