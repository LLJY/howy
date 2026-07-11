//! Non-installed production capture benchmark. Requires explicit local inputs.
//!
//! This target is intentionally not suitable for automated tests and must never
//! be run without deliberate hardware/model parameters.

use std::collections::BTreeMap;
use std::env;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use howy_common::config::HowyConfig;
use howy_daemon::camera::{Camera, CaptureBackendKind, Frame, FrameFormat};
use howy_daemon::inference::InferenceEngine;

struct Arguments {
    config: PathBuf,
    device: String,
    detector_model: String,
    recognizer_model: String,
    warmup_frames: usize,
    sample_frames: usize,
}

fn parse_arguments() -> Result<Arguments> {
    let mut values = BTreeMap::new();
    let mut args = env::args_os().skip(1);
    while let Some(key) = args.next() {
        let key = key
            .to_str()
            .and_then(|key| key.strip_prefix("--"))
            .context("arguments must use UTF-8 --name value syntax")?;
        if !matches!(
            key,
            "config"
                | "device"
                | "detector-model"
                | "recognizer-model"
                | "warmup-frames"
                | "samples"
        ) {
            bail!("unknown argument --{key}");
        }
        let value = args.next().context("missing argument value")?;
        if values.insert(key.to_string(), value).is_some() {
            bail!("duplicate argument --{key}");
        }
    }
    let required = |name: &str| {
        values
            .get(name)
            .and_then(|value| value.to_str())
            .map(str::to_owned)
            .with_context(|| format!("missing --{name}"))
    };
    let parse_count = |name: &str| -> Result<usize> {
        required(name)?
            .parse()
            .with_context(|| format!("invalid --{name}"))
    };
    let arguments = Arguments {
        config: PathBuf::from(required("config")?),
        device: required("device")?,
        detector_model: required("detector-model")?,
        recognizer_model: required("recognizer-model")?,
        warmup_frames: parse_count("warmup-frames")?,
        sample_frames: parse_count("samples")?,
    };
    if arguments.sample_frames == 0 {
        bail!("--samples must be greater than zero");
    }
    Ok(arguments)
}

fn brightness(bgr: &[u8]) -> f64 {
    if bgr.is_empty() {
        return 0.0;
    }
    bgr.iter().map(|&value| f64::from(value)).sum::<f64>() / bgr.len() as f64
}

fn backend_name(backend: CaptureBackendKind) -> &'static str {
    match backend {
        CaptureBackendKind::V4l2Mmap => "v4l2-mmap",
        CaptureBackendKind::FfmpegFallback => "ffmpeg-fallback",
    }
}

fn inference_input(frame: &Frame) -> (&[u8], u32, u32, bool) {
    (
        &frame.data,
        frame.width,
        frame.height,
        frame.format == FrameFormat::Gray,
    )
}

fn main() -> Result<()> {
    let arguments = parse_arguments()?;
    let mut config = HowyConfig::load(&arguments.config)?;
    config.video.device_path = arguments.device.clone();
    config.ml.detector_model = arguments.detector_model;
    config.ml.recognizer_model = arguments.recognizer_model;

    let engine = InferenceEngine::new(&config)?;
    engine.warmup()?;
    engine.warmup_recognizer()?;

    let construction_started = Instant::now();
    let mut camera = Camera::open(
        &config.video.device_path,
        config.video.frame_width,
        config.video.frame_height,
        config.video.device_fps,
        config.video.exposure,
    )?;
    camera.start()?;
    let first_frame = camera.capture_frame()?;
    let construction_through_first_frame_ms = construction_started.elapsed().as_secs_f64() * 1000.0;
    let backend = camera
        .selected_backend()
        .context("capture worker did not report its selected backend")?;

    let total_frames = arguments
        .warmup_frames
        .checked_add(arguments.sample_frames)
        .context("requested frame count overflow")?;
    let mut capture_ms = Vec::with_capacity(arguments.sample_frames);
    let mut brightness_samples = Vec::with_capacity(arguments.sample_frames);
    let mut last_frame = first_frame;
    for index in 0..total_frames {
        let started = Instant::now();
        let frame = camera
            .capture_frame()
            .with_context(|| format!("required capture {index}/{total_frames} did not complete"))?;
        if index >= arguments.warmup_frames {
            capture_ms.push(started.elapsed().as_secs_f64() * 1000.0);
            let (bgr, _, _) = frame.to_bgr_data();
            brightness_samples.push(brightness(&bgr));
        }
        last_frame = frame;
    }
    if capture_ms.len() != arguments.sample_frames {
        bail!("required capture sample count did not complete");
    }

    let (data, width, height, is_gray) = inference_input(&last_frame);
    let detect_started = Instant::now();
    let faces = engine.detect(data, width, height, is_gray)?;
    let detect_ms = detect_started.elapsed().as_secs_f64() * 1000.0;

    println!("howy production capture benchmark");
    println!("selected_backend={}", backend_name(backend));
    println!(
        "fallback_selected={}",
        backend == CaptureBackendKind::FfmpegFallback
    );
    println!("construction_through_first_frame_ms={construction_through_first_frame_ms:.2}");
    println!("required_samples_completed={}", capture_ms.len());
    println!(
        "mean_capture_ms={:.2}",
        capture_ms.iter().sum::<f64>() / capture_ms.len() as f64
    );
    println!(
        "mean_brightness={:.2}",
        brightness_samples.iter().sum::<f64>() / brightness_samples.len() as f64
    );
    println!("faces={} detect_ms={detect_ms:.2}", faces.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inference_input_preserves_raw_gray_and_bgr_layouts() {
        let gray = Frame {
            data: vec![10, 20],
            width: 2,
            height: 1,
            format: FrameFormat::Gray,
        };
        let (data, width, height, is_gray) = inference_input(&gray);
        assert_eq!(data, [10, 20]);
        assert_eq!((width, height, is_gray), (2, 1, true));

        let bgr = Frame {
            data: vec![1, 2, 3, 4, 5, 6],
            width: 2,
            height: 1,
            format: FrameFormat::Bgr,
        };
        let (data, width, height, is_gray) = inference_input(&bgr);
        assert_eq!(data, [1, 2, 3, 4, 5, 6]);
        assert_eq!((width, height, is_gray), (2, 1, false));
    }
}
