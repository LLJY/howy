//! Camera startup microbenchmark.
//!
//! Dissects where the ~200ms camera open time goes:
//!   1. V4L2 device open (fd)
//!   2. Format negotiation
//!   3. OpenCV VideoCapture construction
//!   4. First frame read (includes buffer allocation + stream start)
//!   5. Subsequent frame reads (steady-state)
//!
//! Also tests alternative approaches:
//!   - Raw V4L2 open/close cycle time
//!   - Pre-opened fd passed to OpenCV
//!   - ffmpeg startup time
//!   - GREY vs BGR capture overhead
//!
//! Run: cargo test --test camera_startup_bench -- --nocapture --ignored

use std::io::Read;
use std::os::unix::io::AsRawFd;
use std::process::{Command, Stdio};
use std::time::Instant;

use anyhow::{bail, Context, Result};
use opencv::{core, prelude::*, videoio};

const DEVICE: &str = "/dev/video2";
const WIDTH: u32 = 640;
const HEIGHT: u32 = 480;
const TRIALS: usize = 5;

/// Time a closure over N trials, return (min, avg, max) in ms.
fn bench<F: FnMut() -> Result<()>>(trials: usize, mut f: F) -> Result<(f64, f64, f64)> {
    let mut times = Vec::with_capacity(trials);
    for _ in 0..trials {
        let t = Instant::now();
        f()?;
        times.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    let min = times.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = times.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let avg = times.iter().sum::<f64>() / times.len() as f64;
    Ok((min, avg, max))
}

fn print_result(label: &str, min: f64, avg: f64, max: f64) {
    println!("  {label:<45} min={min:7.2}ms  avg={avg:7.2}ms  max={max:7.2}ms");
}

fn bench_raw_v4l2_open_close() -> Result<()> {
    println!("\n=== Raw V4L2 fd open + close ===");
    let (min, avg, max) = bench(TRIALS, || {
        let dev = v4l::Device::with_path(DEVICE)?;
        drop(dev);
        Ok(())
    })?;
    print_result("v4l::Device::with_path + drop", min, avg, max);
    Ok(())
}

fn bench_v4l2_open_and_query() -> Result<()> {
    println!("\n=== V4L2 open + query caps + format negotiate ===");
    let (min, avg, max) = bench(TRIALS, || {
        let dev = v4l::Device::with_path(DEVICE)?;
        let _caps = dev.query_caps()?;

        use v4l::format::Format;
        use v4l::video::Capture;
        use v4l::FourCC;

        let fmt = Format::new(WIDTH, HEIGHT, FourCC::new(b"GREY"));
        let _actual = Capture::set_format(&dev, &fmt)?;
        drop(dev);
        Ok(())
    })?;
    print_result("v4l open + caps + set_format", min, avg, max);
    Ok(())
}

fn bench_opencv_full_cycle() -> Result<()> {
    println!("\n=== OpenCV full cycle: open → first frame → close ===");

    // Break it down step by step
    println!("  --- Step breakdown (single trial) ---");

    let t0 = Instant::now();
    let mut cap =
        videoio::VideoCapture::from_file(DEVICE, videoio::CAP_V4L).context("from_file")?;
    let t_open = t0.elapsed().as_secs_f64() * 1000.0;

    let t1 = Instant::now();
    let _ = cap.set(videoio::CAP_PROP_FRAME_WIDTH, WIDTH as f64);
    let _ = cap.set(videoio::CAP_PROP_FRAME_HEIGHT, HEIGHT as f64);
    let _ = cap.set(videoio::CAP_PROP_FPS, 30.0);
    let _ = cap.set(videoio::CAP_PROP_BUFFERSIZE, 1.0);
    let t_config = t1.elapsed().as_secs_f64() * 1000.0;

    let t2 = Instant::now();
    let mut frame = core::Mat::default();
    cap.read(&mut frame).context("first read")?;
    let t_first_read = t2.elapsed().as_secs_f64() * 1000.0;

    let t3 = Instant::now();
    cap.read(&mut frame).context("second read")?;
    let t_second_read = t3.elapsed().as_secs_f64() * 1000.0;

    let t4 = Instant::now();
    cap.read(&mut frame).context("third read")?;
    let t_third_read = t4.elapsed().as_secs_f64() * 1000.0;

    let t5 = Instant::now();
    drop(cap);
    let t_close = t5.elapsed().as_secs_f64() * 1000.0;

    println!("  VideoCapture::from_file          {t_open:7.2}ms");
    println!("  set props (w/h/fps/buf)          {t_config:7.2}ms");
    println!("  first cap.read()                 {t_first_read:7.2}ms");
    println!("  second cap.read()                {t_second_read:7.2}ms");
    println!("  third cap.read()                 {t_third_read:7.2}ms");
    println!("  drop(cap)                        {t_close:7.2}ms");
    println!(
        "  TOTAL open→first_frame           {:.2}ms",
        t_open + t_config + t_first_read
    );
    println!(
        "  TOTAL open→close                 {:.2}ms",
        t_open + t_config + t_first_read + t_second_read + t_third_read + t_close
    );

    // Now bench the full open→first_frame→close cycle
    println!("\n  --- Full cycle repeated ---");
    let (min, avg, max) = bench(TRIALS, || {
        let mut cap =
            videoio::VideoCapture::from_file(DEVICE, videoio::CAP_V4L).context("from_file")?;
        let _ = cap.set(videoio::CAP_PROP_FRAME_WIDTH, WIDTH as f64);
        let _ = cap.set(videoio::CAP_PROP_FRAME_HEIGHT, HEIGHT as f64);
        let _ = cap.set(videoio::CAP_PROP_BUFFERSIZE, 1.0);
        let mut frame = core::Mat::default();
        cap.read(&mut frame).context("read")?;
        if frame.empty() {
            bail!("empty frame");
        }
        drop(cap);
        Ok(())
    })?;
    print_result("open → read(1) → close", min, avg, max);

    Ok(())
}

fn bench_opencv_buffersize_comparison() -> Result<()> {
    println!("\n=== OpenCV buffer size: 1 vs default ===");

    println!("  --- buffersize=1 ---");
    let (min, avg, max) = bench(TRIALS, || {
        let mut cap = videoio::VideoCapture::from_file(DEVICE, videoio::CAP_V4L)?;
        let _ = cap.set(videoio::CAP_PROP_FRAME_WIDTH, WIDTH as f64);
        let _ = cap.set(videoio::CAP_PROP_FRAME_HEIGHT, HEIGHT as f64);
        let _ = cap.set(videoio::CAP_PROP_BUFFERSIZE, 1.0);
        let mut frame = core::Mat::default();
        cap.read(&mut frame)?;
        drop(cap);
        Ok(())
    })?;
    print_result("buffersize=1", min, avg, max);

    println!("  --- buffersize=default ---");
    let (min, avg, max) = bench(TRIALS, || {
        let mut cap = videoio::VideoCapture::from_file(DEVICE, videoio::CAP_V4L)?;
        let _ = cap.set(videoio::CAP_PROP_FRAME_WIDTH, WIDTH as f64);
        let _ = cap.set(videoio::CAP_PROP_FRAME_HEIGHT, HEIGHT as f64);
        // Don't set buffersize — let driver decide
        let mut frame = core::Mat::default();
        cap.read(&mut frame)?;
        drop(cap);
        Ok(())
    })?;
    print_result("buffersize=default", min, avg, max);

    Ok(())
}

fn bench_ffmpeg_startup() -> Result<()> {
    println!("\n=== ffmpeg startup: spawn → first frame ===");

    let (min, avg, max) = bench(TRIALS, || {
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
                &format!("{WIDTH}x{HEIGHT}"),
                "-framerate",
                "30",
                "-i",
                DEVICE,
                "-pix_fmt",
                "gray",
                "-f",
                "rawvideo",
                "-",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;

        let mut stdout = child.stdout.take().unwrap();
        let frame_size = (WIDTH * HEIGHT) as usize;
        let mut buf = vec![0u8; frame_size];
        stdout.read_exact(&mut buf)?;

        let _ = child.kill();
        let _ = child.wait();
        Ok(())
    })?;
    print_result("ffmpeg spawn → first gray frame", min, avg, max);

    Ok(())
}

fn bench_v4l2_streamon_streamoff() -> Result<()> {
    println!("\n=== Raw V4L2 STREAMON/STREAMOFF cycle ===");
    println!("  (tests if we can keep the device open but toggle streaming)");

    use v4l::buffer::Type;
    use v4l::format::Format;
    use v4l::io::traits::CaptureStream;
    use v4l::prelude::*;
    use v4l::video::Capture;
    use v4l::FourCC;

    let dev = v4l::Device::with_path(DEVICE)?;
    let fmt = Format::new(WIDTH, HEIGHT, FourCC::new(b"GREY"));
    let _actual = Capture::set_format(&dev, &fmt)?;

    // First, just test if mmap streaming works at all
    println!("  --- testing mmap stream ---");
    let stream_result = MmapStream::with_buffers(&dev, Type::VideoCapture, 2);
    match stream_result {
        Ok(mut stream) => {
            // Get first frame
            let t0 = Instant::now();
            let (_buf, _meta) = stream.next()?;
            let first_ms = t0.elapsed().as_secs_f64() * 1000.0;
            println!("  mmap first frame: {first_ms:.2}ms");

            let t1 = Instant::now();
            let (_buf, _meta) = stream.next()?;
            let second_ms = t1.elapsed().as_secs_f64() * 1000.0;
            println!("  mmap second frame: {second_ms:.2}ms");

            drop(stream);
            println!("  mmap streaming works on this device!");

            // Now bench repeated stream create/destroy with same device
            println!("\n  --- mmap stream create/read/destroy cycle ---");
            let (min, avg, max) = bench(TRIALS, || {
                let mut stream = MmapStream::with_buffers(&dev, Type::VideoCapture, 1)?;
                let (_buf, _meta) = stream.next()?;
                drop(stream);
                Ok(())
            })?;
            print_result("mmap stream cycle (device stays open)", min, avg, max);
        }
        Err(e) => {
            println!("  mmap streaming NOT supported: {e}");
            println!("  (this is expected for some IR cameras)");
        }
    }

    Ok(())
}

fn bench_resolution_impact() -> Result<()> {
    println!("\n=== Resolution impact on first frame latency ===");

    for (w, h, label) in [
        (320, 240, "320x240"),
        (640, 360, "640x360"),
        (640, 480, "640x480"),
    ] {
        let (min, avg, max) = bench(3, || {
            let mut cap = videoio::VideoCapture::from_file(DEVICE, videoio::CAP_V4L)?;
            let _ = cap.set(videoio::CAP_PROP_FRAME_WIDTH, w as f64);
            let _ = cap.set(videoio::CAP_PROP_FRAME_HEIGHT, h as f64);
            let _ = cap.set(videoio::CAP_PROP_BUFFERSIZE, 1.0);
            let mut frame = core::Mat::default();
            cap.read(&mut frame)?;
            drop(cap);
            Ok(())
        })?;
        print_result(label, min, avg, max);
    }

    Ok(())
}

fn main() -> Result<()> {
    println!("howy camera startup microbenchmark");
    println!("device={DEVICE} {WIDTH}x{HEIGHT}\n");

    bench_raw_v4l2_open_close()?;
    bench_v4l2_open_and_query()?;
    bench_opencv_full_cycle()?;
    bench_opencv_buffersize_comparison()?;
    bench_ffmpeg_startup()?;
    bench_v4l2_streamon_streamoff()?;
    bench_resolution_impact()?;

    println!("\nDone.");
    Ok(())
}
