"""Load cookie settings at startup; read the idle timeout per request."""
import os
import re

_DIGITS = re.compile(r"[0-9]{1,3}")

# DB fallback.
IDLE_FALLBACK_MINUTES = 30
# Match DB constraint.
IDLE_MIN = 5
IDLE_MAX = 120
# Patient deadline, hours.
# Match DB constraint.
DEADLINE_MIN = 0
DEADLINE_MAX = 48
# Refresh cookie once a minute.
SESSION_TOUCH_SECONDS = 60
# Reject future timestamps.
CLOCK_SKEW_SECONDS = 60


def _absolute_hours() -> int:
    raw = os.environ.get("SESSION_ABSOLUTE_HOURS")
    if raw is None:
        return 12
    if not _DIGITS.fullmatch(raw) or not 3 <= int(raw) <= 24:
        raise RuntimeError("SESSION_ABSOLUTE_HOURS must be a whole number of hours from 3 to 24")
    return int(raw)


def _same_site() -> str:
    raw = os.environ.get("SESSION_SAME_SITE")
    if raw is None:
        return "lax"
    if raw not in ("lax", "strict"):
        raise RuntimeError("SESSION_SAME_SITE must be lax or strict")
    return raw


def _https_only() -> bool:
    raw = os.environ.get("SESSION_HTTPS_ONLY")
    if raw is None:
        # Keep cookies secure outside Compose.
        return True
    if raw not in ("true", "false"):
        raise RuntimeError("SESSION_HTTPS_ONLY must be true or false")
    return raw == "true"


ABSOLUTE_HOURS = _absolute_hours()
ABSOLUTE_SECONDS = ABSOLUTE_HOURS * 3600
SAME_SITE = _same_site()
HTTPS_ONLY = _https_only()
