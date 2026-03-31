use std::io::{BufReader, Read};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::Instant;

use anyhow::{bail, Context, Result};
use howy_common::config::HowyConfig;
use howy_daemon::inference::InferenceEngine;
use opencv::{core, imgproc, prelude::*, videoio};

const MODEL_DIR: &str = "dist/howdy_onnx/_internal/onnx-data";
const DEVICE: &str = "/dev/video2";
const WIDTH: u32 = 640;
const HEIGHT: u32 = 360;
const WARMUP_FRAMES: usize = 30;
const SAMPLE_FRAMES: usize = 30;

trait CaptureBackend {
    fn name(&self) -> &str;
    fn next_frame(&mut self) -> Result<(Vec<u8>, u32, u32)>;
}

struct OpenCvBackend {
    cap: videoio::VideoCapture,
}

impl OpenCvBackend {
    fn new(device: &str, width: u32, height: u32) -> Result<Self> {
        let mut cap = videoio::VideoCapture::from_file(device, videoio::CAP_V4L)
            .context("failed to open device with OpenCV CAP_V4L")?;
        if !cap.is_opened()? {
            bail!("OpenCV could not open device {device}");
        }
        let _ = cap.set(videoio::CAP_PROP_FRAME_WIDTH, width as f64);
        let _ = cap.set(videoio::CAP_PROP_FRAME_HEIGHT, height as f64);
        let _ = cap.set(videoio::CAP_PROP_FPS, 30.0);
        let _ = cap.set(videoio::CAP_PROP_BUFFERSIZE, 1.0);
        Ok(Self { cap })
    }
}

impl CaptureBackend for OpenCvBackend {
    fn name(&self) -> &str {
        "opencv-cap_v4l"
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

struct FfmpegBackend {
    child: Child,
    stdout: BufReader<ChildStdout>,
    width: u32,
    height: u32,
}

impl FfmpegBackend {
    fn new(device: &str, width: u32, height: u32) -> Result<Self> {
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
                "gray",
                "-video_size",
                &format!("{}x{}", width, height),
                "-framerate",
                "30",
                "-i",
                device,
                "-pix_fmt",
                "gray",
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
        })
    }
}

impl Drop for FfmpegBackend {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl CaptureBackend for FfmpegBackend {
    fn name(&self) -> &str {
        "ffmpeg-sidecar"
    }

    fn next_frame(&mut self) -> Result<(Vec<u8>, u32, u32)> {
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
}

fn brightness(bgr: &[u8]) -> f64 {
    if bgr.is_empty() {
        return 0.0;
    }
    bgr.iter().map(|&v| v as f64).sum::<f64>() / bgr.len() as f64
}

fn build_engine() -> Result<InferenceEngine> {
    let mut config = HowyConfig::default();
    config.ml.provider = "cpu".to_string();
    config.ml.det_threshold = 0.3;
    config.ml.detector_model = format!("{MODEL_DIR}/det_10g.onnx");
    config.ml.recognizer_model = format!("{MODEL_DIR}/w600k_r50.onnx");
    InferenceEngine::new(&config)
}

fn bench_backend<B: CaptureBackend>(mut backend: B, engine: &InferenceEngine) -> Result<()> {
    println!("== backend: {} ==", backend.name());

    let startup = Instant::now();
    let mut first_frame_ms = 0.0;
    let mut capture_ms = Vec::new();
    let mut means = Vec::new();
    let mut last_frame = None;

    for i in 0..(WARMUP_FRAMES + SAMPLE_FRAMES) {
        let t0 = Instant::now();
        let frame = backend.next_frame()?;
        let elapsed = t0.elapsed().as_secs_f64() * 1000.0;
        if i == 0 {
            first_frame_ms = startup.elapsed().as_secs_f64() * 1000.0;
        }
        if i >= WARMUP_FRAMES {
            capture_ms.push(elapsed);
            means.push(brightness(&frame.0));
        }
        last_frame = Some(frame);
    }

    let (bgr, width, height) = last_frame.context("no captured frame")?;
    let avg_capture_ms = capture_ms.iter().sum::<f64>() / capture_ms.len() as f64;
    let avg_brightness = means.iter().sum::<f64>() / means.len() as f64;

    let t0 = Instant::now();
    let faces = engine.detect(&bgr, width, height, false)?;
    let detect_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let best_score = faces.iter().map(|f| f.score).fold(0.0_f32, f32::max);

    let mut analyze_ms = 0.0;
    let mut embedding_ok = false;
    if !faces.is_empty() {
        let t1 = Instant::now();
        let analyzed = engine.analyze(&bgr, width, height, false)?;
        analyze_ms = t1.elapsed().as_secs_f64() * 1000.0;
        embedding_ok = analyzed
            .first()
            .and_then(|f| f.embedding.as_ref())
            .map(|e| e.len() == 512 && e.iter().all(|v| v.is_finite()))
            .unwrap_or(false);
    }

    println!("first_frame_ms={first_frame_ms:.1}");
    println!("avg_capture_ms={avg_capture_ms:.2}");
    println!("avg_brightness={avg_brightness:.1}");
    println!("faces={} best_score={best_score:.4}", faces.len());
    println!("detect_ms={detect_ms:.1}");
    if !faces.is_empty() {
        println!("analyze_ms={analyze_ms:.1} embedding_ok={embedding_ok}");
    }
    println!();

    Ok(())
}

fn main() -> Result<()> {
    println!("howy capture benchmark");
    println!("device={DEVICE} {}x{}\n", WIDTH, HEIGHT);

    let engine = build_engine()?;
    engine.warmup()?;

    match OpenCvBackend::new(DEVICE, WIDTH, HEIGHT) {
        Ok(backend) => {
            if let Err(e) = bench_backend(backend, &engine) {
                println!("opencv-cap_v4l failed: {e:#}");
            }
        }
        Err(e) => println!("opencv-cap_v4l init failed: {e:#}"),
    }

    match FfmpegBackend::new(DEVICE, WIDTH, HEIGHT) {
        Ok(backend) => {
            if let Err(e) = bench_backend(backend, &engine) {
                println!("ffmpeg-sidecar failed: {e:#}");
            }
        }
        Err(e) => println!("ffmpeg-sidecar init failed: {e:#}"),
    }

    Ok(())
}
