use howy_daemon::camera::Camera;

fn main() -> anyhow::Result<()> {
    let mut cam = Camera::open("/dev/video2", 640, 360)?;
    cam.start()?;

    let mut last = None;
    for _ in 0..60 {
        last = Some(cam.capture_frame()?);
    }

    let (bgr, width, height) = last.expect("captured frames");
    let mean: f64 = bgr.iter().map(|&v| v as f64).sum::<f64>() / bgr.len() as f64;
    let min = bgr.iter().copied().min().unwrap_or(0);
    let max = bgr.iter().copied().max().unwrap_or(0);

    println!("captured {width}x{height} mean={mean:.1} min={min} max={max}");
    std::fs::write("/tmp/camera_read_test.bgr", &bgr)?;
    Ok(())
}
