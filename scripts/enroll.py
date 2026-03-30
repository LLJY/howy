#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "opencv-python",
#     "mediapipe",
#     "numpy",
# ]
# ///
"""howy enrollment frontend — pose-guided face capture (Apple FaceID style).

Uses MediaPipe FaceLandmarker for real yaw/pitch head-pose estimation.
Captures frames only when the user's head matches a required pose segment.
Radial indicators around a central oval collapse as segments are captured.

Usage:
    uv run scripts/enroll.py --device /dev/video2 --user lucas --label default
"""

import argparse
import math
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

import cv2
import mediapipe as mp
import numpy as np


WINDOW_TITLE = "howy enrollment"

# Model download URL and local cache.
_MODEL_URL = "https://storage.googleapis.com/mediapipe-models/face_landmarker/face_landmarker/float16/latest/face_landmarker.task"
_MODEL_CACHE = os.path.expanduser("~/.cache/howy/face_landmarker.task")

# Pose segments: 1 center + 4 cardinal directions (up, right, down, left).
NUM_RING_SEGMENTS = 4
CENTER_IDX = -1
CAPTURES_PER_SEGMENT = 4
MIN_CAPTURE_INTERVAL_S = 0.25

# Pose thresholds in degrees — intentionally gentle.
CENTER_YAW = 6.0
CENTER_PITCH = 6.0
RING_MIN_DEG = 8.0  # must exceed center threshold to avoid overlap

# Segment names and angular ranges (center angle, half-width).
# Ordered: up=0, right=1, down=2, left=3.
# Down gets a wider acceptance zone since it's harder to detect.
_SEG_NAMES = ["up", "right", "down", "left"]
_SEG_CENTER_ANGLES = [90.0, 0.0, 270.0, 180.0]  # degrees in atan2 space
_SEG_HALF_WIDTH = [45.0, 45.0, 55.0, 45.0]  # down is wider


# ── main ─────────────────────────────────────────────────────────────────


def main():
    args = parse_args()
    session_dir = create_session_dir()

    try:
        frame_count = run_capture(args, session_dir)
        if frame_count < 0:
            print("\nCancelled by user.", file=sys.stderr)
            cleanup(session_dir)
            return 1

        if frame_count == 0:
            print("No frames captured. Aborting.", file=sys.stderr)
            cleanup(session_dir)
            return 1

        print(f"\nCaptured {frame_count} frames to {session_dir}")

        if args.enroll:
            return run_enrollment(args, session_dir)

        print_enrollment_command(args, session_dir)
        return 0
    except KeyboardInterrupt:
        print("\nAborted by user.", file=sys.stderr)
        cleanup(session_dir)
        return 1
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        cleanup(session_dir)
        return 1


def parse_args():
    p = argparse.ArgumentParser(description="Pose-guided face enrollment for howy.")
    p.add_argument(
        "--device", default="/dev/video2", help="camera device (default: /dev/video2)"
    )
    p.add_argument("--user", default=_default_user(), help="target username")
    p.add_argument("--label", default="default", help="enrollment label")
    p.add_argument("--enroll", action="store_true", help="auto-enroll after capture")
    p.add_argument(
        "--scale",
        type=float,
        default=2.0,
        help="display scale factor for HiDPI (default: 2.0)",
    )
    return p.parse_args()


def _default_user():
    return os.environ.get("SUDO_USER") or os.environ.get("USER") or "unknown"


def create_session_dir():
    return tempfile.mkdtemp(prefix="howy-enroll-", dir="/tmp")


# ── model download ───────────────────────────────────────────────────────


def ensure_model():
    """Download the FaceLandmarker model if not cached."""
    if os.path.isfile(_MODEL_CACHE):
        return _MODEL_CACHE
    os.makedirs(os.path.dirname(_MODEL_CACHE), exist_ok=True)
    print(f"Downloading face landmarker model to {_MODEL_CACHE}...")
    urllib.request.urlretrieve(_MODEL_URL, _MODEL_CACHE)
    print("Done.")
    return _MODEL_CACHE


# ── enrollment state ─────────────────────────────────────────────────────


class EnrollState:
    """Tracks per-segment capture counts."""

    def __init__(self):
        self.counts = {CENTER_IDX: 0}
        for i in range(NUM_RING_SEGMENTS):
            self.counts[i] = 0
        self._last_time = {}
        self.frame_count = 0
        self.total_needed = (1 + NUM_RING_SEGMENTS) * CAPTURES_PER_SEGMENT

    def done(self, seg):
        return self.counts.get(seg, 0) >= CAPTURES_PER_SEGMENT

    def all_done(self):
        return all(c >= CAPTURES_PER_SEGMENT for c in self.counts.values())

    def can_capture(self, seg):
        if seg is None or self.done(seg):
            return False
        return time.monotonic() - self._last_time.get(seg, 0) >= MIN_CAPTURE_INTERVAL_S

    def record(self, seg):
        self.counts[seg] = self.counts.get(seg, 0) + 1
        self._last_time[seg] = time.monotonic()
        self.frame_count += 1

    def total_captured(self):
        return sum(self.counts.values())

    def ring_remaining(self):
        return sum(1 for i in range(NUM_RING_SEGMENTS) if not self.done(i))


# ── head pose estimation ─────────────────────────────────────────────────


class PoseEstimator:
    """Estimates yaw/pitch relative to a calibrated neutral position.

    The first few frames establish the user's baseline nose position,
    then all measurements are offsets from that baseline. This avoids
    hardcoding a "neutral" that varies by face shape and camera angle.
    """

    _CALIBRATION_FRAMES = 10

    def __init__(self):
        self._yaw_samples = []
        self._pitch_samples = []
        self._yaw_baseline = 0.0
        self._pitch_baseline = 0.0
        self._calibrated = False

    @property
    def calibrated(self):
        return self._calibrated

    def estimate(self, landmarks):
        """Returns (yaw_deg, pitch_deg) relative to calibrated neutral."""
        raw_yaw, raw_pitch = self._raw(landmarks)

        if not self._calibrated:
            self._yaw_samples.append(raw_yaw)
            self._pitch_samples.append(raw_pitch)
            if len(self._yaw_samples) >= self._CALIBRATION_FRAMES:
                self._yaw_baseline = sum(self._yaw_samples) / len(self._yaw_samples)
                self._pitch_baseline = sum(self._pitch_samples) / len(
                    self._pitch_samples
                )
                self._calibrated = True
            return 0.0, 0.0  # report neutral during calibration

        return raw_yaw - self._yaw_baseline, raw_pitch - self._pitch_baseline

    @staticmethod
    def _raw(landmarks):
        """Raw yaw/pitch in degrees from landmark geometry (not calibrated)."""
        nose = landmarks[1]
        left_eye = landmarks[33]
        right_eye = landmarks[263]
        chin = landmarks[152]

        eye_cx = (left_eye.x + right_eye.x) / 2.0
        eye_cy = (left_eye.y + right_eye.y) / 2.0
        eye_width = abs(right_eye.x - left_eye.x)

        if eye_width < 0.001:
            return 0.0, 0.0

        # Yaw: nose horizontal offset from eye midpoint.
        yaw_ratio = (nose.x - eye_cx) / eye_width
        yaw_deg = -yaw_ratio * 70.0

        # Pitch: nose vertical position in eyes-to-chin span.
        face_height = chin.y - eye_cy
        if face_height < 0.001:
            return yaw_deg, 0.0

        nose_ratio = (nose.y - eye_cy) / face_height
        pitch_deg = -(nose_ratio - 0.5) * 100.0

        return yaw_deg, pitch_deg


def classify_segment(yaw, pitch):
    """Map yaw/pitch degrees to a segment index.

    Returns CENTER_IDX, a ring index 0..3 (up/right/down/left), or None.
    """
    if abs(yaw) < CENTER_YAW and abs(pitch) < CENTER_PITCH:
        return CENTER_IDX

    deg = max(abs(yaw), abs(pitch))
    if deg < RING_MIN_DEG:
        return None

    # Map yaw/pitch to an angle: right=0°, up=90°, left=180°, down=270°.
    # pitch is already positive=up, so atan2(pitch, yaw) gives up=90°.
    angle = math.degrees(math.atan2(pitch, yaw)) % 360

    # Check each cardinal segment with its own acceptance width.
    for i in range(NUM_RING_SEGMENTS):
        center = _SEG_CENTER_ANGLES[i]
        half = _SEG_HALF_WIDTH[i]
        # Angular distance, wrapping around 360.
        diff = abs((angle - center + 180) % 360 - 180)
        if diff <= half:
            return i

    return None


# ── capture loop ─────────────────────────────────────────────────────────


def run_capture(args, session_dir):
    model_path = ensure_model()

    cap = cv2.VideoCapture(args.device, cv2.CAP_V4L2)
    if not cap.isOpened():
        raise RuntimeError(f"Cannot open camera {args.device!r}")

    cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)

    base_options = mp.tasks.BaseOptions(model_asset_path=model_path)
    fl_options = mp.tasks.vision.FaceLandmarkerOptions(
        base_options=base_options,
        running_mode=mp.tasks.vision.RunningMode.VIDEO,
        num_faces=1,
        min_face_detection_confidence=0.4,
        min_face_presence_confidence=0.4,
        min_tracking_confidence=0.4,
        output_facial_transformation_matrixes=False,
    )
    landmarker = mp.tasks.vision.FaceLandmarker.create_from_options(fl_options)

    state = EnrollState()
    pose = PoseEstimator()
    raw = None
    ts_ms = 0  # monotonic timestamp for VIDEO mode

    cv2.namedWindow(WINDOW_TITLE, cv2.WINDOW_NORMAL | cv2.WINDOW_KEEPRATIO)
    disp_w = int(640 * args.scale)
    disp_h = int(480 * args.scale)
    cv2.resizeWindow(WINDOW_TITLE, disp_w, disp_h)

    try:
        while not state.all_done():
            ok, raw = cap.read()
            if not ok or raw is None:
                if cv2.waitKey(1) & 0xFF in (ord("q"), 27):
                    return -1
                continue

            fh, fw = raw.shape[:2]
            ts_ms += 33  # ~30fps timestamps for VIDEO mode

            # ── detect pose ─────────────────────────────────────────
            # MediaPipe expects RGB.
            if raw.ndim == 2:
                rgb = cv2.cvtColor(raw, cv2.COLOR_GRAY2RGB)
            elif raw.ndim == 3 and raw.shape[2] == 1:
                rgb = cv2.cvtColor(raw[:, :, 0], cv2.COLOR_GRAY2RGB)
            else:
                rgb = cv2.cvtColor(raw, cv2.COLOR_BGR2RGB)

            mp_image = mp.Image(image_format=mp.ImageFormat.SRGB, data=rgb)
            result = landmarker.detect_for_video(mp_image, ts_ms)

            cur_seg = None
            yaw, pitch = 0.0, 0.0
            if result.face_landmarks and len(result.face_landmarks) > 0:
                lm = result.face_landmarks[0]
                yaw, pitch = pose.estimate(lm)
                if pose.calibrated:
                    cur_seg = classify_segment(yaw, pitch)

            # ── capture ─────────────────────────────────────────────
            if state.can_capture(cur_seg):
                state.record(cur_seg)
                path = os.path.join(session_dir, f"frame_{state.frame_count:04d}.png")
                cv2.imwrite(path, _save_frame(raw))

            # ── display ─────────────────────────────────────────────
            display = _to_bgr(raw)
            display = cv2.flip(display, 1)  # mirror for natural UX
            _draw_overlay(
                display, state, cur_seg, yaw, pitch, calibrated=pose.calibrated
            )
            cv2.imshow(WINDOW_TITLE, display)

            if cv2.waitKey(1) & 0xFF in (ord("q"), 27):
                # Cancelled — return -1 so caller knows not to enroll.
                return -1

        # Brief "Done!" flash.
        if state.all_done() and raw is not None:
            display = _to_bgr(raw)
            display = cv2.flip(display, 1)
            _draw_overlay(display, state, None, 0.0, 0.0, finished=True)
            cv2.imshow(WINDOW_TITLE, display)
            cv2.waitKey(700)

        return state.frame_count
    finally:
        landmarker.close()
        cap.release()
        cv2.destroyAllWindows()


# ── overlay drawing ──────────────────────────────────────────────────────


def _draw_overlay(frame, state, cur_seg, yaw, pitch, calibrated=True, finished=False):
    h, w = frame.shape[:2]
    cx, cy = w // 2, h // 2

    oval_rx = max(80, w // 4)
    oval_ry = max(100, int(h * 0.38))
    line_max = min(w, h) // 8

    # ── radial lines / dots (up, right, down, left) ────────────
    # Display angles: up=-90°, right=0°, down=90°, left=180°.
    _display_angles = [-90.0, 0.0, 90.0, 180.0]
    for i in range(NUM_RING_SEGMENTS):
        angle = math.radians(_display_angles[i])
        sx = int(cx + oval_rx * math.cos(angle))
        sy = int(cy + oval_ry * math.sin(angle))

        progress = min(state.counts.get(i, 0) / CAPTURES_PER_SEGMENT, 1.0)
        remain = int(line_max * (1.0 - progress))

        if remain > 1:
            ex = int(sx + remain * math.cos(angle))
            ey = int(sy + remain * math.sin(angle))
            color = (0, 255, 255) if cur_seg == i else (160, 160, 160)
            cv2.line(frame, (sx, sy), (ex, ey), color, 2, cv2.LINE_AA)
        else:
            cv2.circle(frame, (sx, sy), 5, (0, 200, 0), -1, cv2.LINE_AA)

    # ── center oval ──────────────────────────────────────────────
    if finished:
        oval_color = (0, 220, 0)
    elif state.done(CENTER_IDX):
        oval_color = (0, 200, 0)
    elif cur_seg == CENTER_IDX:
        oval_color = (0, 255, 255)
    else:
        oval_color = (160, 160, 160)
    cv2.ellipse(
        frame, (cx, cy), (oval_rx, oval_ry), 0, 0, 360, oval_color, 2, cv2.LINE_AA
    )

    # ── guidance text ────────────────────────────────────────────
    if finished:
        guidance = "Done!"
    elif not calibrated:
        guidance = "Hold still — calibrating..."
    elif not state.done(CENTER_IDX):
        guidance = "Look straight at the camera"
    else:
        # Find the first incomplete direction to guide the user.
        remaining = [
            _SEG_NAMES[i] for i in range(NUM_RING_SEGMENTS) if not state.done(i)
        ]
        if remaining:
            guidance = f"Look {remaining[0]} ({len(remaining)} left)"
        else:
            guidance = "Done!"

    _text(frame, guidance, (16, 32), 0.65, 2)

    # Debug: show live yaw/pitch.
    _text(frame, f"yaw {yaw:+.0f}  pitch {pitch:+.0f}", (16, h - 36), 0.45, 1)
    _text(frame, f"{state.total_captured()}/{state.total_needed}", (16, h - 12), 0.5, 1)
    _text(frame, "q / Esc to cancel", (w - 170, h - 12), 0.4, 1)


def _text(frame, txt, pos, scale, thick):
    x, y = pos
    cv2.putText(
        frame,
        txt,
        (x + 1, y + 1),
        cv2.FONT_HERSHEY_SIMPLEX,
        scale,
        (0, 0, 0),
        thick + 2,
        cv2.LINE_AA,
    )
    cv2.putText(
        frame,
        txt,
        (x, y),
        cv2.FONT_HERSHEY_SIMPLEX,
        scale,
        (255, 255, 255),
        thick,
        cv2.LINE_AA,
    )


# ── frame helpers ────────────────────────────────────────────────────────


def _to_bgr(frame):
    if frame.ndim == 2:
        return cv2.cvtColor(frame, cv2.COLOR_GRAY2BGR)
    if frame.ndim == 3 and frame.shape[2] == 1:
        return cv2.cvtColor(frame[:, :, 0], cv2.COLOR_GRAY2BGR)
    if frame.ndim == 3 and frame.shape[2] == 4:
        return cv2.cvtColor(frame, cv2.COLOR_BGRA2BGR)
    return frame.copy()


def _save_frame(frame):
    if frame.ndim == 3 and frame.shape[2] == 1:
        return frame[:, :, 0]
    if frame.ndim == 3 and frame.shape[2] == 4:
        return cv2.cvtColor(frame, cv2.COLOR_BGRA2BGR)
    return frame


# ── enrollment commands ──────────────────────────────────────────────────


def _enroll_cmd(args, session_dir):
    return [
        "sudo",
        "howy",
        "enroll-batch",
        "--user",
        args.user,
        "--session-dir",
        session_dir,
        "--label",
        args.label,
        "--delete-on-success",
    ]


def run_enrollment(args, session_dir):
    cmd = _enroll_cmd(args, session_dir)
    print("Running:\n  " + _fmt(cmd))
    return subprocess.run(cmd).returncode


def print_enrollment_command(args, session_dir):
    print("Run this to enroll:\n  " + _fmt(_enroll_cmd(args, session_dir)))


def _fmt(cmd):
    return " ".join(shlex.quote(c) for c in cmd)


def cleanup(session_dir):
    if session_dir and os.path.isdir(session_dir):
        shutil.rmtree(session_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
