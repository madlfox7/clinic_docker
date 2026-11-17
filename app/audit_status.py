"""Banner "Log integrity" on /admin/audit (plan 18.2).

The api only reads /audit_status/status.json, written by audit_anchor
(mounted read-only here; the api has no anchor key, no anchors and no
auditor password). read_banner is a pure function: a strict schema v1, then
green only when the file is fresh, ok, fully checked and has no history of a
replaced chain. Anything else is "broken" or "not checked"; nothing raises.

The banner is an indicator, not the source of truth: an attacker with code
execution in the api draws whatever he likes in his own answer. The source
of truth is make audit-verify and copies of the anchors outside this server.
"""
from __future__ import annotations

import json
import math
import os
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

STATUS_PATH = os.environ.get("CLINIC_AUDIT_STATUS_PATH", "/audit_status/status.json")
MAX_BYTES = 4096
# Same ranges as audit/anchor.py; a bad value here falls back to the default.
INTERVAL_DEFAULT, INTERVAL_RANGE = 60, (10, 3600)
FULL_EVERY_DEFAULT, FULL_EVERY_RANGE = 600, (60, 86400)
# Times "in the future" more than this are not trusted (same host clock).
FUTURE_SLACK = 60

# English texts: the interface has no i18n (base.html is lang="en").
INTEGRITY_PROBLEMS = {
    "gap": "a journal row is missing (gap in seq)",
    "hash_version": "unknown hash version of a journal row",
    "prev_hash": "a journal row does not link to the row before it",
    "row_hash": "a journal row was changed",
    "anchor_mismatch": "the journal does not match an anchor",
    "truncated": "the journal is shorter than an anchor",
    "head": "the chain head does not match the journal",
    "head_missing": "the chain head is missing",
    "trigger_mode": "a journal protection trigger is not active",
    "registry_missing": "the chain registry is missing",
    "registry_format": "the chain registry is damaged",
    "registry_mac": "the chain registry signature does not match",
    "anchor_format": "an anchor file is damaged",
    "anchor_mac": "an anchor signature does not match",
    "anchor_file_missing": "the anchor file of the open chain is missing",
    "anchor_copy_mismatch": "an outside anchor copy does not match",
    "chain_replaced": "the journal chain was replaced",
    "genesis_rows": "a new chain was opened over a non-empty journal",
}
UNKNOWN_PROBLEM = "unknown integrity problem"
UNCHECKED_REASONS = {
    "database": "the database could not be read",
    "anchor_dir": "the anchor directory is not writable",
    "retired": "the chain is closed (between a retire and a reset)",
    "stale": "the status is out of date (is audit_anchor running?)",
    "missing": "no status yet",
    "invalid": "the status file is not valid",
    "future": "the status time is in the future",
}
SWITCH_KINDS = ("new", "reused", "retired_reused")
FIELDS = {"v", "state", "checked_at", "full_checked_at", "full_ok", "anchored_at", "last_anchor_seq",
          "problem", "retired_forced", "retired_offline", "replaced_history"}
STATES = ("ok", "broken", "unchecked")
LOCAL_ZONE = "Asia/Yerevan"


@dataclass(frozen=True)
class Banner:
    state: str                     # ok | broken | unchecked
    reason: str | None = None      # problem type (broken) or UNCHECKED_REASONS key
    text: str | None = None        # fixed text for the reason
    seq: int | None = None         # seq of the problem
    kind: str | None = None        # switch kind of chain_replaced
    checked_at: str | None = None
    full_checked_at: str | None = None
    anchored_at: str | None = None
    last_anchor_seq: int | None = None
    retired_forced: int = 0
    retired_offline: int = 0
    replaced_history: int = 0

    @property
    def label(self) -> str:
        return {"ok": "OK", "broken": "BROKEN"}.get(self.state, "not checked")


class _Invalid(Exception):
    pass


def env_seconds(name: str, default: int, bounds: tuple[int, int]) -> int:
    raw = os.environ.get(name, str(default))
    if raw.isdigit() and bounds[0] <= int(raw) <= bounds[1]:
        return int(raw)
    return default


def _zone():
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(LOCAL_ZONE)
    except Exception:   # no tz database in the image: Yerevan is UTC+4 all year
        return timezone(timedelta(hours=4), LOCAL_ZONE)


def _when(value) -> str | None:
    if value is None:
        return None
    return datetime.fromtimestamp(value, _zone()).strftime("%Y-%m-%d %H:%M:%S")


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _time(value, nullable: bool):
    if value is None and nullable:
        return None
    if not (_is_int(value) or isinstance(value, float)) or not math.isfinite(value) or value < 0:
        raise _Invalid
    return float(value)


def _count(value, nullable: bool = False):
    if value is None and nullable:
        return None
    if not _is_int(value) or value < 0:
        raise _Invalid
    return value


def _read(path: str) -> bytes | None:
    """O_NOFOLLOW, a regular file of at most MAX_BYTES; None if missing."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return None
    except OSError:
        raise _Invalid from None   # a symlink (ELOOP), no access, ...
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
            raise _Invalid
        data = os.read(fd, MAX_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_BYTES:
        raise _Invalid
    return data


def _parse(data: bytes) -> dict:
    def no_constants(name):
        raise _Invalid   # NaN, Infinity

    try:
        doc = json.loads(data.decode("utf-8"), parse_constant=no_constants)
    except (UnicodeDecodeError, ValueError):
        raise _Invalid from None
    if not isinstance(doc, dict) or set(doc) != FIELDS:
        raise _Invalid
    if not _is_int(doc["v"]) or doc["v"] != 1 or doc["state"] not in STATES:
        raise _Invalid
    out = {"v": 1, "state": doc["state"]}
    out["checked_at"] = _time(doc["checked_at"], False)
    out["full_checked_at"] = _time(doc["full_checked_at"], True)
    out["anchored_at"] = _time(doc["anchored_at"], True)
    if doc["full_ok"] is not None and not isinstance(doc["full_ok"], bool):
        raise _Invalid
    out["full_ok"] = doc["full_ok"]
    out["last_anchor_seq"] = _count(doc["last_anchor_seq"], True)
    for name in ("retired_forced", "retired_offline", "replaced_history"):
        out[name] = _count(doc[name])
    problem = doc["problem"]
    if problem is not None:
        if not isinstance(problem, dict) or set(problem) != {"type", "seq", "kind"}:
            raise _Invalid
        if not isinstance(problem["type"], str) or not 1 <= len(problem["type"]) <= 64:
            raise _Invalid
        if problem["kind"] is not None and problem["kind"] not in SWITCH_KINDS:
            raise _Invalid
        problem = {"type": problem["type"], "seq": _count(problem["seq"], True), "kind": problem["kind"]}
    out["problem"] = problem
    return out


def _broken(doc: dict, common: dict) -> Banner:
    problem = doc["problem"]
    if problem is None or problem["type"] in UNCHECKED_REASONS:
        # broken without a (known) break type: a replaced chain in the history
        if doc["replaced_history"] > 0:
            return Banner("broken", "chain_replaced", INTEGRITY_PROBLEMS["chain_replaced"], **common)
        return Banner("broken", "unknown", UNKNOWN_PROBLEM, **common)
    reason = problem["type"]
    if reason not in INTEGRITY_PROBLEMS:
        return Banner("broken", "unknown", UNKNOWN_PROBLEM, problem["seq"], **common)
    kind = problem["kind"] if reason == "chain_replaced" else None
    return Banner("broken", reason, INTEGRITY_PROBLEMS[reason], problem["seq"], kind, **common)


def read_banner(path: str, now: float, interval: int, full_every: int) -> Banner:
    try:
        return _banner(path, now, interval, full_every)
    except Exception:   # never a 500 because of the banner
        return Banner("unchecked", "invalid", UNCHECKED_REASONS["invalid"])


def _banner(path: str, now: float, interval: int, full_every: int) -> Banner:
    try:
        data = _read(path)
        if data is None:
            return Banner("unchecked", "missing", UNCHECKED_REASONS["missing"])
        doc = _parse(data)
    except _Invalid:
        return Banner("unchecked", "invalid", UNCHECKED_REASONS["invalid"])
    common = {
        "checked_at": _when(doc["checked_at"]),
        "full_checked_at": _when(doc["full_checked_at"]),
        "anchored_at": _when(doc["anchored_at"]),
        "last_anchor_seq": doc["last_anchor_seq"],
        "retired_forced": doc["retired_forced"],
        "retired_offline": doc["retired_offline"],
        "replaced_history": doc["replaced_history"],
    }
    problem = doc["problem"]
    if doc["state"] == "broken" or doc["replaced_history"] > 0 or doc["full_ok"] is False:
        return _broken(doc, common)
    if problem is not None and problem["type"] not in UNCHECKED_REASONS:
        return _broken(doc, common)          # "ok" or "unchecked" with a break type: not trusted
    times = [t for t in (doc["checked_at"], doc["full_checked_at"], doc["anchored_at"]) if t is not None]
    if any(t > now + FUTURE_SLACK for t in times):
        return Banner("unchecked", "future", UNCHECKED_REASONS["future"], **common)
    if doc["state"] == "unchecked" or problem is not None:
        reason = problem["type"] if problem is not None else "invalid"
        return Banner("unchecked", reason, UNCHECKED_REASONS[reason], **common)
    if now - doc["checked_at"] > 3 * interval + 60:
        return Banner("unchecked", "stale", UNCHECKED_REASONS["stale"], **common)
    if doc["full_checked_at"] is None or doc["full_ok"] is not True \
            or now - doc["full_checked_at"] > 2 * full_every + 60:
        return Banner("unchecked", "stale", UNCHECKED_REASONS["stale"], **common)
    return Banner("ok", **common)
