#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "opencv-python",
#     "mediapipe",
#     "numpy",
# ]
# ///
"""howy enrollment frontend — pose-guided face capture.

Uses MediaPipe FaceLandmarker for real yaw/pitch head-pose estimation.
Captures frames only when the user's head matches a required pose segment.
An elliptical progress ring guides a slow, circular head movement.

Usage:
    uv run scripts/enroll.py --device /dev/video2 --user lucas --label default
"""

import argparse
from dataclasses import dataclass, field
from functools import lru_cache
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

# Pose segments: 1 center + 8 directions around the head-motion ring.
NUM_RING_SEGMENTS = 8
CENTER_IDX = -1
CAPTURES_PER_SEGMENT = 4
MIN_CAPTURE_INTERVAL_S = 0.25

# Pose thresholds in degrees — intentionally gentle.
CENTER_YAW = 6.0
CENTER_PITCH = 6.0
RING_MIN_DEG = 8.0  # must exceed center threshold to avoid overlap

# IR cameras may illuminate in pulses, causing expected landmark gaps between
# otherwise valid frames. Keep the UI stable through short gaps, but reset an
# unfinished calibration when the face has genuinely been absent.
FACE_PRESENCE_GRACE_S = 0.75
CALIBRATION_RESET_AFTER_S = 1.5

# Ordered up through up-left. The mirrored preview places positive logical yaw
# on screen-right; classification itself stays unmirrored.
_DISPLAY_CENTER_ANGLES = [-90.0, -45.0, 0.0, 45.0, 90.0, 135.0, 180.0, -135.0]

PHASE_SEARCHING = "searching"
PHASE_CALIBRATING = "calibrating"
PHASE_CENTER = "center_capture"
PHASE_CIRCULAR = "circular_scan"
PHASE_COMPLETE = "completion"

_BLUE = (255, 132, 10)
_GREEN = (88, 209, 48)
_WHITE = (245, 245, 245)
_SECONDARY = (205, 205, 205)
_NEUTRAL = (145, 145, 145)
_TRACK = (78, 78, 78)


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
        "--debug",
        action="store_true",
        help="show live pose angles and capture counts",
    )
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


@dataclass
class PresentationState:
    """Smooth display-only progress; capture counts remain authoritative."""

    ring_progress: list[float] = field(
        default_factory=lambda: [0.0] * NUM_RING_SEGMENTS
    )
    center_progress: float = 0.0
    last_update: float | None = None
    pulse_started: float | None = None

    def update(self, state, now=None):
        now = time.monotonic() if now is None else now
        if self.last_update is None:
            self.last_update = now
            return

        dt = max(0.0, min(now - self.last_update, 0.25))
        self.last_update = now
        blend = 1.0 - math.exp(-9.0 * dt)

        center_target = min(
            state.counts[CENTER_IDX] / CAPTURES_PER_SEGMENT, 1.0
        )
        self.center_progress += (center_target - self.center_progress) * blend

        for i in range(NUM_RING_SEGMENTS):
            target = min(state.counts[i] / CAPTURES_PER_SEGMENT, 1.0)
            self.ring_progress[i] += (target - self.ring_progress[i]) * blend

    def note_capture(self, now=None):
        self.pulse_started = time.monotonic() if now is None else now

    def pulse_strength(self, now=None):
        if self.pulse_started is None:
            return 0.0
        now = time.monotonic() if now is None else now
        return max(0.0, min(1.0, 1.0 - (now - self.pulse_started) / 0.35))


@dataclass
class FacePresenceState:
    """Debounces expected landmark gaps from pulsed IR illumination."""

    last_seen: float | None = None

    def update(self, detected, now=None):
        now = time.monotonic() if now is None else now
        if detected:
            self.last_seen = now
            return True
        return (
            self.last_seen is not None
            and now - self.last_seen <= FACE_PRESENCE_GRACE_S
        )

    def calibration_expired(self, now=None):
        if self.last_seen is None:
            return False
        now = time.monotonic() if now is None else now
        return now - self.last_seen > CALIBRATION_RESET_AFTER_S


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

    @property
    def calibration_progress(self):
        if self._calibrated:
            return 1.0
        return min(len(self._yaw_samples) / self._CALIBRATION_FRAMES, 1.0)

    def face_lost(self):
        """Require calibration samples to come from one face-present run."""
        if not self._calibrated:
            self._yaw_samples.clear()
            self._pitch_samples.clear()

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

    Returns CENTER_IDX, a ring index 0..7, or None in the center/ring dead zone.
    Angular sectors are 45° wide and half-open. An exact boundary belongs to
    the next clockwise sector, so no pose can receive credit in two sectors.
    """
    # An elliptical neutral zone keeps the center/ring transition equally
    # reachable at cardinal and diagonal angles.
    center_distance = math.hypot(yaw / CENTER_YAW, pitch / CENTER_PITCH)
    if center_distance < 1.0:
        return CENTER_IDX

    deg = math.hypot(yaw, pitch)
    if deg < RING_MIN_DEG:
        return None

    # Logical camera coordinates: right=0°, up=90°, left=180°, down=270°.
    # Preview mirroring is intentionally not part of classification.
    angle = math.degrees(math.atan2(pitch, yaw)) % 360
    clockwise_from_up = (90.0 - angle) % 360.0
    # The tiny epsilon makes the documented clockwise tie-break stable when a
    # mathematically exact boundary has picked up atan2 rounding noise.
    return int(((clockwise_from_up + 22.5 + 1e-9) % 360.0) // 45.0)


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
    presentation = PresentationState()
    presence = FacePresenceState()
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
            now = time.monotonic()
            landmarks_detected = bool(result.face_landmarks)
            if presence.calibration_expired(now):
                pose.face_lost()
            face_present = presence.update(landmarks_detected, now)
            if landmarks_detected:
                lm = result.face_landmarks[0]
                yaw, pitch = pose.estimate(lm)
                if pose.calibrated:
                    cur_seg = classify_segment(yaw, pitch)

            # ── capture ─────────────────────────────────────────────
            capture_seg = None
            if pose.calibrated:
                if not state.done(CENTER_IDX) and cur_seg == CENTER_IDX:
                    capture_seg = CENTER_IDX
                elif state.done(CENTER_IDX) and cur_seg != CENTER_IDX:
                    capture_seg = cur_seg

            if state.can_capture(capture_seg):
                next_frame = state.frame_count + 1
                path = os.path.join(session_dir, f"frame_{next_frame:04d}.png")
                if not cv2.imwrite(path, _save_frame(raw)):
                    raise RuntimeError(f"Failed to save enrollment frame to {path}")
                state.record(capture_seg)
                presentation.note_capture()

            # ── display ─────────────────────────────────────────────
            display = _to_bgr(raw)
            display = cv2.flip(display, 1)  # mirror for natural UX
            phase = _visual_phase(face_present, pose.calibrated, state)
            _draw_overlay(
                display,
                state,
                presentation,
                phase,
                cur_seg,
                yaw,
                pitch,
                calibration_progress=pose.calibration_progress,
                debug=args.debug,
                now=now,
            )
            cv2.imshow(WINDOW_TITLE, display)

            if cv2.waitKey(1) & 0xFF in (ord("q"), 27):
                # Cancelled — return -1 so caller knows not to enroll.
                return -1

        # Brief completion scene.
        if state.all_done() and raw is not None:
            display = _to_bgr(raw)
            display = cv2.flip(display, 1)
            _draw_overlay(
                display,
                state,
                presentation,
                PHASE_COMPLETE,
                None,
                0.0,
                0.0,
                calibration_progress=1.0,
                debug=args.debug,
            )
            cv2.imshow(WINDOW_TITLE, display)
            cv2.waitKey(900)

        return state.frame_count
    finally:
        landmarker.close()
        cap.release()
        cv2.destroyAllWindows()


# ── overlay drawing ──────────────────────────────────────────────────────


def _visual_phase(face_present, calibrated, state):
    if state.all_done():
        return PHASE_COMPLETE
    if not face_present:
        return PHASE_SEARCHING
    if not calibrated:
        return PHASE_CALIBRATING
    if not state.done(CENTER_IDX):
        return PHASE_CENTER
    return PHASE_CIRCULAR


def _draw_overlay(
    frame,
    state,
    presentation,
    phase,
    cur_seg,
    yaw,
    pitch,
    calibration_progress=0.0,
    debug=False,
    now=None,
):
    now = time.monotonic() if now is None else now
    presentation.update(state, now)

    h, w = frame.shape[:2]
    center, oval_axes, ring_axes, ui_scale = _overlay_layout(w, h)
    cx, cy = center
    oval_rx, oval_ry = oval_axes
    ring_rx, ring_ry = ring_axes

    _dim_outside_oval(frame, center, oval_axes)

    ring_thickness = max(3, int(round(5 * ui_scale)))
    oval_thickness = max(1, int(round(2 * ui_scale)))
    segment_half_span = 17.0

    for i, display_angle in enumerate(_DISPLAY_CENTER_ANGLES):
        if phase == PHASE_COMPLETE:
            _draw_ellipse_arc(
                frame,
                center,
                ring_axes,
                display_angle - segment_half_span,
                display_angle + segment_half_span,
                _GREEN,
                ring_thickness,
            )
            continue

        _draw_ellipse_arc(
            frame,
            center,
            ring_axes,
            display_angle - segment_half_span,
            display_angle + segment_half_span,
            _TRACK,
            ring_thickness,
        )
        progress = presentation.ring_progress[i]
        if progress > 0.002:
            progress_half_span = segment_half_span * progress
            _draw_ellipse_arc(
                frame,
                center,
                ring_axes,
                display_angle - progress_half_span,
                display_angle + progress_half_span,
                _BLUE,
                ring_thickness,
            )

    # A single quiet dot connects the observed logical pose to the mirrored ring.
    if (
        phase == PHASE_CIRCULAR
        and cur_seg is not None
        and cur_seg != CENTER_IDX
        and not state.done(cur_seg)
    ):
        angle = math.radians(_DISPLAY_CENTER_ANGLES[cur_seg])
        indicator = (
            int(round(cx + (ring_rx + ring_thickness + 5) * math.cos(angle))),
            int(round(cy + (ring_ry + ring_thickness + 5) * math.sin(angle))),
        )
        cv2.circle(
            frame,
            indicator,
            max(2, int(round(3 * ui_scale))),
            _BLUE,
            -1,
            cv2.LINE_AA,
        )

    oval_color = _GREEN if phase == PHASE_COMPLETE else _NEUTRAL
    cv2.ellipse(
        frame,
        center,
        oval_axes,
        0,
        0,
        360,
        oval_color,
        oval_thickness,
        cv2.LINE_AA,
    )

    pulse = presentation.pulse_strength(now)
    if pulse > 0.0 and phase != PHASE_COMPLETE:
        pulse_layer = frame.copy()
        expansion = max(1, int(round((1.0 - pulse) * 5 * ui_scale)))
        cv2.ellipse(
            pulse_layer,
            center,
            (ring_rx + expansion, ring_ry + expansion),
            0,
            0,
            360,
            _WHITE,
            max(1, int(round(2 * ui_scale))),
            cv2.LINE_AA,
        )
        alpha = 0.12 * pulse
        cv2.addWeighted(pulse_layer, alpha, frame, 1.0 - alpha, 0.0, frame)

    primary, secondary = _phase_instructions(phase)
    primary_y = max(24, int(round(h * 0.075)))
    secondary_y = max(primary_y + 19, int(round(h * 0.135)))
    primary_scale = max(0.52, min(0.82, 0.72 * ui_scale))
    secondary_scale = max(0.36, min(0.55, 0.48 * ui_scale))
    _centered_text(frame, primary, primary_y, primary_scale, 2, _WHITE)
    _centered_text(frame, secondary, secondary_y, secondary_scale, 1, _SECONDARY)

    if phase == PHASE_CALIBRATING:
        _draw_progress_bar(
            frame, calibration_progress, secondary_y + max(10, int(12 * ui_scale)), ui_scale
        )
    elif phase == PHASE_CENTER:
        _draw_progress_bar(
            frame,
            presentation.center_progress,
            secondary_y + max(10, int(12 * ui_scale)),
            ui_scale,
        )

    if phase == PHASE_COMPLETE:
        check_scale = max(0.65, ui_scale)
        check_color = _GREEN
        cv2.line(
            frame,
            (int(cx - 19 * check_scale), int(cy + 1 * check_scale)),
            (int(cx - 5 * check_scale), int(cy + 15 * check_scale)),
            check_color,
            max(3, int(5 * check_scale)),
            cv2.LINE_AA,
        )
        cv2.line(
            frame,
            (int(cx - 5 * check_scale), int(cy + 15 * check_scale)),
            (int(cx + 24 * check_scale), int(cy - 19 * check_scale)),
            check_color,
            max(3, int(5 * check_scale)),
            cv2.LINE_AA,
        )

    cancel_scale = max(0.34, min(0.46, 0.4 * ui_scale))
    _centered_text(frame, "Esc or Q to cancel", h - 10, cancel_scale, 1, _SECONDARY)

    if debug:
        debug_scale = max(0.32, min(0.44, 0.38 * ui_scale))
        _text(
            frame,
            f"yaw {yaw:+.1f}  pitch {pitch:+.1f}  "
            f"captures {state.total_captured()}/{state.total_needed}",
            (10, h - max(27, int(28 * ui_scale))),
            debug_scale,
            1,
            _WHITE,
        )


def _overlay_layout(w, h):
    ui_scale = max(0.65, min(1.5, min(w / 640.0, h / 480.0)))
    top_reserved = min(int(h * 0.35), max(52, int(h * 0.18)))
    bottom_reserved = min(int(h * 0.2), max(26, int(h * 0.08)))
    available_h = max(30, h - top_reserved - bottom_reserved)
    cy = (top_reserved + h - bottom_reserved) // 2

    gap = max(4, int(round(7 * ui_scale)))
    ring_ry = max(12, int(available_h * 0.43))
    ring_ry = min(
        ring_ry,
        max(12, cy - top_reserved),
        max(12, h - bottom_reserved - cy),
    )
    oval_ry = max(8, ring_ry - gap)
    oval_rx = max(7, min(int(oval_ry * 0.76), int(w * 0.28)))
    ring_rx = oval_rx + gap
    return (w // 2, cy), (oval_rx, oval_ry), (ring_rx, ring_ry), ui_scale


@lru_cache(maxsize=8)
def _oval_mask(height, width, cx, cy, rx, ry):
    mask = np.zeros((height, width), dtype=np.uint8)
    cv2.ellipse(mask, (cx, cy), (rx, ry), 0, 0, 360, 255, -1, cv2.LINE_AA)
    mask.setflags(write=False)
    return mask


def _dim_outside_oval(frame, center, axes):
    h, w = frame.shape[:2]
    mask = _oval_mask(h, w, center[0], center[1], axes[0], axes[1])
    dimmed = cv2.convertScaleAbs(frame, alpha=0.62)
    cv2.copyTo(frame, mask, dimmed)
    frame[:] = dimmed


def _draw_ellipse_arc(frame, center, axes, start, end, color, thickness):
    """Draw an anti-aliased arc with explicitly rounded endpoints."""
    cv2.ellipse(frame, center, axes, 0, start, end, color, thickness, cv2.LINE_AA)
    radius = max(1, thickness // 2)
    for angle_deg in (start, end):
        angle = math.radians(angle_deg)
        point = (
            int(round(center[0] + axes[0] * math.cos(angle))),
            int(round(center[1] + axes[1] * math.sin(angle))),
        )
        cv2.circle(frame, point, radius, color, -1, cv2.LINE_AA)


def _draw_progress_bar(frame, progress, y, ui_scale):
    h, w = frame.shape[:2]
    y = min(max(4, y), h - 4)
    width = max(54, min(int(w * 0.27), int(150 * ui_scale)))
    thickness = max(3, int(round(4 * ui_scale)))
    x1 = (w - width) // 2
    x2 = x1 + width
    cv2.line(frame, (x1, y), (x2, y), _TRACK, thickness, cv2.LINE_AA)
    cv2.circle(frame, (x1, y), thickness // 2, _TRACK, -1, cv2.LINE_AA)
    cv2.circle(frame, (x2, y), thickness // 2, _TRACK, -1, cv2.LINE_AA)

    progress = max(0.0, min(progress, 1.0))
    if progress > 0.0:
        fill_x = int(round(x1 + width * progress))
        cv2.line(frame, (x1, y), (fill_x, y), _BLUE, thickness, cv2.LINE_AA)
        cv2.circle(frame, (x1, y), thickness // 2, _BLUE, -1, cv2.LINE_AA)
        cv2.circle(frame, (fill_x, y), thickness // 2, _BLUE, -1, cv2.LINE_AA)


def _phase_instructions(phase):
    if phase == PHASE_SEARCHING:
        return "Position your face in the frame", "Keep your face fully visible"
    if phase == PHASE_CALIBRATING:
        return "Hold still for a moment", "Keep looking straight at the camera"
    if phase == PHASE_CENTER:
        return "Look straight at the camera", "Hold your position"
    if phase == PHASE_CIRCULAR:
        return "Move your head slowly in a circle", "Follow the circle to finish"
    return "You're all set", "Enrollment complete"


def _centered_text(frame, txt, y, scale, thick, color):
    max_width = max(20, frame.shape[1] - 24)
    (text_width, _), _ = cv2.getTextSize(
        txt, cv2.FONT_HERSHEY_SIMPLEX, scale, thick
    )
    if text_width > max_width:
        scale *= max_width / text_width
        (text_width, _), _ = cv2.getTextSize(
            txt, cv2.FONT_HERSHEY_SIMPLEX, scale, thick
        )
    x = max(4, (frame.shape[1] - text_width) // 2)
    _text(frame, txt, (x, y), scale, thick, color)


def _text(frame, txt, pos, scale, thick, color=_WHITE):
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
        color,
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
