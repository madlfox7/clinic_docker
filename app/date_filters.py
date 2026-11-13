"""Shared GET filter parsing: strict ISO dates, day/week views, LIKE escaping.

Used by the calendars, the slot list, /my, the audit log and the reschedule page.
Bad input never raises: the caller gets a default value and an error code to show.
"""
from datetime import date, datetime, time, timedelta
from urllib.parse import urlencode

from db import contains_nul, has_control_char, parse_strict_int

CALENDAR_MIN_YEAR = 1900
CALENDAR_MAX_YEAR = 2100
MAX_FILTER_RANGE_DAYS = 366
MAX_SEARCH_LENGTH = 100


def parse_iso_day(raw):
    """Return (day, error). error is None, "invalid_day" or "day_out_of_range"."""
    if raw is None or raw == "":
        return None, None
    if not isinstance(raw, str) or contains_nul(raw):
        return None, "invalid_day"
    try:
        parsed = date.fromisoformat(raw)
        if parsed.isoformat() != raw:
            raise ValueError
    except ValueError:
        return None, "invalid_day"
    if not CALENDAR_MIN_YEAR <= parsed.year <= CALENDAR_MAX_YEAR:
        return None, "day_out_of_range"
    return parsed, None


def calendar_state(request, default_view="day"):
    """Selected day (default today) and view (day|week) from the query string."""
    errors = []
    selected_day = date.today()
    raw_day = request.query_params.get("day")
    if raw_day is not None:
        parsed, error = parse_iso_day(raw_day)
        if error:
            errors.append(error)
        elif parsed is not None:
            selected_day = parsed
        else:
            errors.append("invalid_day")
    raw_view = request.query_params.get("view", default_view)
    if raw_view not in ("day", "week"):
        errors.append("invalid_view")
        view = default_view
    else:
        view = raw_view
    return selected_day, view, errors


def day_start(day):
    return datetime.combine(day, time.min)


def date_range(request, max_days=MAX_FILTER_RANGE_DAYS):
    """Optional from/to dates. Returns (from_day, to_day, errors).

    A bad or out-of-order pair is dropped with an error; to - from is at most max_days.
    """
    errors = []
    from_day, from_error = parse_iso_day(request.query_params.get("from"))
    to_day, to_error = parse_iso_day(request.query_params.get("to"))
    if from_error or to_error:
        return None, None, ["invalid_range"]
    if from_day and to_day:
        if to_day < from_day or (to_day - from_day).days > max_days:
            errors.append("invalid_range")
            from_day = to_day = None
    elif from_day and not to_day:
        if from_day + timedelta(days=max_days) > date(CALENDAR_MAX_YEAR, 12, 31):
            to_day = date(CALENDAR_MAX_YEAR, 12, 31)
        else:
            to_day = from_day + timedelta(days=max_days)
    elif to_day and not from_day:
        if to_day - timedelta(days=max_days) < date(CALENDAR_MIN_YEAR, 1, 1):
            from_day = date(CALENDAR_MIN_YEAR, 1, 1)
        else:
            from_day = to_day - timedelta(days=max_days)
    return from_day, to_day, errors


def range_bounds(from_day, to_day):
    """[from 00:00, to + 1 day 00:00) as naive datetimes, or (None, None)."""
    if from_day is None or to_day is None:
        return None, None
    return day_start(from_day), day_start(to_day + timedelta(days=1))


def parse_page(raw, max_page=500):
    """page >= 1 and <= max_page, otherwise 1."""
    if raw is None:
        return 1
    value = parse_strict_int(raw, min_value=1, max_value=max_page)
    return value if value is not None else 1


def clean_search(raw, max_length=MAX_SEARCH_LENGTH):
    """Free-text search: stripped, <= max_length, no NUL/control characters.

    Returns (value, error). An empty value means no filter.
    """
    if raw is None:
        return "", None
    if not isinstance(raw, str) or contains_nul(raw) or has_control_char(raw):
        return "", "invalid_filter"
    value = " ".join(raw.split())
    if len(value) > max_length:
        return "", "invalid_filter"
    return value, None


def escape_like(value):
    """Escape \\ % _ for ILIKE ... ESCAPE '\\'."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def url_with(path, params):
    """path?query with empty values dropped; values are urlencoded."""
    clean = {key: str(value) for key, value in params.items() if value not in (None, "")}
    return f"{path}?{urlencode(clean)}" if clean else path
