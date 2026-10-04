"""Observed M-SHARK trace grammar and protocol-session state; no network I/O."""
import math
import re
import secrets
import time


M_SHARK_TRACE_RE = re.compile(
    r"5172(?P<device>[A-Za-z0-9]{64})?(?P<marker>[A-Za-z0-9]{6})"
    r"(?P<timestamp>[0-9]{13}\.[0-9]{6})(?P<suffix>[A-Za-z0-9]{6})")
_MARKER_RE = re.compile(r"[A-Za-z0-9]{6}")
_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def ensure_m_shark_session_marker(profile):
    """Create one public trace marker per current profile, never from capture."""
    key = "m_shark_session_marker"
    if key not in profile:
        profile[key] = "".join(secrets.choice(_ALPHABET) for _ in range(6))
    value = profile[key]
    _require(isinstance(value, str) and _MARKER_RE.fullmatch(value) is not None,
             "current M-SHARK session marker is invalid")
    return value


def make_m_shark_trace_id(template_value, csecuuid, *, now_ms=None, session_marker=None):
    """Refresh a trace with current device/time and an explicit session marker.

    Captures use both an early 36-character form without a device and a
    100-character form containing a 64-character device ID. Preserve the
    template's form; the six-character marker belongs to this session.
    Templates contribute only the grammar.
    Callers persist the marker once; absent markers are generated for one-off
    calls. SDK PRNG parity and server acceptance are not implied.
    """
    _require(isinstance(template_value, str) and template_value, "M-SHARK template is missing")
    parsed = M_SHARK_TRACE_RE.fullmatch(template_value)
    _require(parsed is not None, "M-SHARK template layout differs")
    device = ""
    if parsed['device'] is not None:
        _require(isinstance(csecuuid, str) and csecuuid, "csecuuid is missing for M-SHARK")
        _require(re.fullmatch(r"[A-Za-z0-9]{64}", csecuuid) is not None, "csecuuid layout differs")
        device = csecuuid
    marker = ensure_m_shark_session_marker(
        {} if session_marker is None else {"m_shark_session_marker": session_marker})
    if now_ms is None:
        now_ms = time.time() * 1000.0
    _require(type(now_ms) in (int, float) and math.isfinite(float(now_ms)), "M-SHARK timestamp is invalid")
    timestamp = f"{float(now_ms):.6f}"
    _require(re.fullmatch(r"[0-9]{13}\.[0-9]{6}", timestamp) is not None,
             "M-SHARK timestamp layout differs")
    suffix = "".join(secrets.choice(_ALPHABET) for _ in range(6))
    return "5172" + device + marker + timestamp + suffix
