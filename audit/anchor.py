"""audit_anchor service (plan 17 §8): every CLINIC_AUDIT_ANCHOR_INTERVAL
seconds check the chain and anchor it if intact.
"""
from __future__ import annotations

import argparse
import errno
import json
import os
import re
import stat
import sys
import time
import traceback
from pathlib import Path

import chainlib as cl
import verify_audit

ANCHOR_DIR = Path(os.environ.get("CLINIC_AUDIT_ANCHOR_PATH", "/anchors"))
KEY_FILE = os.environ.get("CLINIC_AUDIT_ANCHOR_KEY_FILE", "/run/secrets/audit_anchor_key")
STATUS_FILE = Path(os.environ.get("CLINIC_AUDIT_STATUS_FILE", "/tmp/audit_anchor_status.json"))
# API status file.
PUBLIC_STATUS_DIR = Path(os.environ.get("CLINIC_AUDIT_PUBLIC_STATUS_DIR", "/status"))
PUBLIC_STATUS_NAME = "status.json"
# Unknown types are broken.
PROBLEM_TYPES = (
    "gap", "hash_version", "prev_hash", "row_hash", "anchor_mismatch", "truncated", "head",
    "head_missing", "trigger_mode", "registry_missing", "registry_format", "registry_mac",
    "anchor_format", "anchor_mac", "anchor_file_missing", "anchor_copy_mismatch",
    "chain_replaced", "genesis_rows",
)
# No-check errors.
UNCHECKED_ERRORS = ("database", "anchor_dir")
# Unchecked reasons.
UNCHECKED_REASONS = ("database", "anchor_dir", "retired")


def say(text: str) -> None:
    print(text, flush=True)


def interval() -> int:
    raw = os.environ.get("CLINIC_AUDIT_ANCHOR_INTERVAL", "60")
    if not raw.isdigit() or not 10 <= int(raw) <= 3600:
        raise SystemExit("CLINIC_AUDIT_ANCHOR_INTERVAL must be an integer from 10 to 3600")
    return int(raw)


def full_check_every() -> int:
    raw = os.environ.get("CLINIC_AUDIT_FULL_CHECK_EVERY", "600")
    if not raw.isdigit() or not 60 <= int(raw) <= 86400:
        raise SystemExit("CLINIC_AUDIT_FULL_CHECK_EVERY must be an integer from 60 to 86400")
    return int(raw)


class Result:
    def __init__(self, ok: bool, state: str, error: str | None = None, anchored=None, line: str = "",
                 seq=None, kind=None):
        self.ok, self.state, self.error, self.anchored, self.line = ok, state, error, anchored, line
        self.seq, self.kind = seq, kind   # Break location.
        self.full = None                  # Full check result.
        self.counts = None                # Registry counts.


class FullCheck:
    def __init__(self, ok: bool, kind=None, seq=None, switch_kind=None):
        self.ok, self.kind, self.seq, self.switch_kind = ok, kind, seq, switch_kind


_BROKEN_LINE = re.compile(r"^BROKEN(?: seq=(0|[1-9][0-9]*))?(?: id=[0-9]+)? type=([a-z_]+)")
_SWITCH_KIND = re.compile(r"\bkind=(new|reused|retired_reused)\b")


def full_check(directory: Path, key: bytes, source, every: int) -> FullCheck:
    """Run full verification and retain only the break type, sequence and switch kind."""
    lines: list[str] = []
    if verify_audit.verify(source, directory, key, False, None, every, out=lines.append) == 0:
        return FullCheck(True)
    for line in reversed(lines):
        m = _BROKEN_LINE.match(line)
        if m:
            kind = _SWITCH_KIND.search(line) if m.group(2) == "chain_replaced" else None
            return FullCheck(False, m.group(2), int(m.group(1)) if m.group(1) else None,
                             kind.group(1) if kind else None)
    return FullCheck(False, "unknown")


def registry_counts(directory: Path, key: bytes):
    """(switch lines, forced retires, offline retires) of the registry, or None."""
    registry = directory / cl.REGISTRY
    if not registry.exists():
        return 0, 0, 0
    try:
        entries, _ = cl.parse_registry(registry, key)
    except cl.Broken:
        return None
    return (sum(e.kind == "switch" for e in entries),
            sum(e.kind == "retire" and e.mode == "forced" for e in entries),
            sum(e.kind == "retire" and e.mode == "offline" for e in entries))


def _anchor(directory: Path, key: bytes, source, chain_id: str) -> Result:
    path = directory / f"{chain_id}.log"
    anchors, prev = cl.read_anchors(path, key, chain_id)
    _, last_seq, last_hash = cl.check_from_anchor(source, chain_id, anchors[-1] if anchors else None)
    now = cl.utc()
    cl.append_line(path, key, prev, f"{cl.VERSION} {chain_id} {last_seq} {last_hash.hex()} {now}")
    return Result(True, "anchoring", anchored=(last_seq, now), line=f"anchored chain={chain_id} seq={last_seq}")


def cycle(directory: Path, key: bytes, source, full: bool = False, every: int = 60) -> Result:
    """Verify and anchor under the directory lock; optionally run a full check there too."""
    if not os.access(directory, os.W_OK | os.X_OK):
        return Result(False, "error", "anchor_dir", line=f"anchor directory {directory} is not writable")
    with cl.locked(directory):
        result = _step(directory, key, source)
        if full:
            result.full = full_check(directory, key, source, every)
        result.counts = registry_counts(directory, key)
        return result


def _step(directory: Path, key: bytes, source) -> Result:
    try:
        cl.check_triggers(source)
        head = source.head()
        if head is None:
            raise cl.Broken("head_missing")
        h = head["chain_id"]
        registry = directory / cl.REGISTRY
        has_registry = registry.exists()
        entries, reg_mac = cl.parse_registry(registry, key) if has_registry else ([], cl.ZERO_MAC)
        state = cl.registry_state(entries)
        has_anchor_files = bool(cl.anchor_files(directory))
        holds = (not has_registry and not has_anchor_files
                 and cl.journal_holds_chain(source, head, beyond_genesis=True))
        decision = cl.decide(state, h, head["genesis_rows"], has_registry, has_anchor_files,
                             holds_chain=holds)
        if decision.action == "error":
            kind = decision.kind
            text = {"registry_missing": "ERROR audit chain registry missing"
                    + (f" (no chains.log and no anchors, but chain={h} has last_seq={head['last_seq']}:"
                       " anchor directory removed or renamed? restore it, or"
                       " make reset RETIRE_FORCE=yes CONFIRM=yes)" if holds else ""),
                    "genesis_rows": f"new chain {h} opened over a non-empty journal"}[kind]
            return Result(False, "error", kind, line=text)
        if decision.action in ("first_open", "open"):
            cl.touch(directory / f"{h}.log")
            cl.append_line(registry, key, reg_mac,
                           f"{cl.VERSION} open {h} {cl.utc(head['genesis_at'])} {head['genesis_rows']} {cl.utc()}")
            say(f"opened chain={h}")
        elif decision.action == "switch":
            cl.append_line(registry, key, reg_mac,
                           f"{cl.VERSION} switch {decision.old or '-'} {h} {decision.kind} {cl.utc()}")
            say(f"ERROR audit chain replaced old={decision.old or '-'} new={h} kind={decision.kind}")
            if not (directory / f"{h}.log").exists():
                cl.touch(directory / f"{h}.log")
            state = cl.registry_state(cl.parse_registry(registry, key)[0])
        elif decision.action == "retired_check":
            retired = state.last_retired
            try:
                anchors, _ = cl.read_anchors(directory / f"{h}.log", key, h)
                _, last_seq, last_hash = cl.check_full(source, h, anchors)
                same = last_seq == retired.last_seq and last_hash.hex() == retired.row_hash
            except cl.Broken:
                same = False
            if same:
                return Result(True, "retired", line=f"chain={h} is retired, no anchor")
            cl.append_line(registry, key, reg_mac,
                           f"{cl.VERSION} switch {h} {h} retired_reused {cl.utc()}")
            say(f"ERROR audit chain replaced old={h} new={h} kind=retired_reused")
            state = cl.registry_state(cl.parse_registry(registry, key)[0])
        elif not (directory / f"{h}.log").exists():
            return Result(False, "error", "anchor_file_missing", line=f"anchor file of chain={h} is missing")
        result = _anchor(directory, key, source, h)
        if h in state.switched_to:
            kind = state.switched_to[h][-1].switch_kind
            result.ok, result.error, result.kind = False, "chain_replaced", kind
            result.line += f" (chain_replaced kind={kind}: needs a human)"
        return result
    except cl.Broken as broken:
        return Result(False, "error", broken.kind, line=f"ERROR audit chain broken: {broken.line()}",
                      seq=broken.seq)


def write_status(result: Result, every: int) -> None:
    previous = read_status() or {}
    data = {"ok": result.ok, "state": result.state, "error": result.error, "interval": every,
            "checked_at": time.time(),
            "anchored_at": time.time() if result.anchored else previous.get("anchored_at")}
    tmp = STATUS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data))
    os.replace(tmp, STATUS_FILE)


def read_status():
    try:
        return json.loads(STATUS_FILE.read_text())
    except (OSError, ValueError):
        return None


def health() -> int:
    status = read_status()
    if not status or not status.get("ok"):
        return 1
    now, every = time.time(), status["interval"]
    if now - status["checked_at"] > 2 * every:
        return 1
    if status["state"] == "retired":
        return 0
    anchored = status.get("anchored_at")
    return 0 if anchored and now - anchored <= 2 * every else 1


def describe_error(exc: BaseException) -> str:
    """Describe failure without database messages or file contents; include OS error details."""
    text = type(exc).__name__
    if isinstance(exc, OSError):
        if exc.errno is not None:
            text += f" errno={errno.errorcode.get(exc.errno, '?')}({exc.errno})"
        # Report our call site.
        here = os.path.dirname(os.path.abspath(__file__))
        frames = [f for f in traceback.extract_tb(exc.__traceback__)
                  if os.path.dirname(os.path.abspath(f.filename)) == here and f.name != "_named"]
        if frames:
            call = re.search(r"([A-Za-z_][\w.]*)\(", frames[-1].line or "")
            text += f" op={call.group(1) if call else frames[-1].name}"
        if exc.filename is not None:
            text += f" path={os.fsdecode(exc.filename)}"
        if exc.filename2 is not None:
            text += f" path2={os.fsdecode(exc.filename2)}"
    return text


def run_cycle(key: bytes, conn_holder: dict, full: bool = False, every: int = 60) -> Result:
    try:
        if conn_holder.get("conn") is None or conn_holder["conn"].closed:
            conn_holder["conn"] = cl.connect()
        conn = conn_holder["conn"]
        try:
            return cycle(ANCHOR_DIR, key, cl.DbSource(conn), full, every)
        finally:
            conn.rollback()  # Fresh snapshot next cycle.
    except Exception as exc:  # Missing anchor is unhealthy.
        if conn_holder.get("conn") is not None:
            try:
                conn_holder["conn"].close()
            except Exception:
                pass
            conn_holder["conn"] = None
        return Result(False, "error", "database", line=f"ERROR audit cycle failed: {describe_error(exc)}")


class PublicStatus:
    """Track public loop status; full checks repeat periodically and counters never decrease."""

    def __init__(self, full_every: int):
        self.full_every = full_every
        self.full_checked_at = None
        self.full_ok = None
        self.full_problem = None
        self.anchored_at = None
        self.last_anchor_seq = None
        self.replaced = self.forced = self.offline = 0

    def full_due(self, now: float) -> bool:
        return self.full_checked_at is None or now - self.full_checked_at >= self.full_every

    def step(self, now: float, do_cycle) -> tuple[Result, dict]:
        """do_cycle(full) -> Result; returns the result and the public status."""
        result = do_cycle(self.full_due(now))
        if result.full is not None:
            self.full_checked_at, self.full_ok = now, result.full.ok
            self.full_problem = None if result.full.ok else _problem(
                result.full.kind, result.full.seq, result.full.switch_kind)
        if result.anchored:
            self.anchored_at, self.last_anchor_seq = now, result.anchored[0]
        if result.counts is not None:
            self.replaced = max(self.replaced, result.counts[0])
            self.forced = max(self.forced, result.counts[1])
            self.offline = max(self.offline, result.counts[2])
        return result, self.public(result, now)

    def public(self, result: Result, now: float) -> dict:
        """Classify status as broken, unchecked or ok; problem identifies the relevant cause."""
        problem = None
        if not result.ok and result.error not in UNCHECKED_ERRORS:
            state = "broken"
            problem = _problem(result.error, result.seq, result.kind)
        elif self.full_ok is False:
            state, problem = "broken", self.full_problem
        elif result.error in UNCHECKED_ERRORS or result.state == "retired":
            state = "unchecked"
            problem = {"type": result.error if result.error in UNCHECKED_ERRORS else "retired",
                       "seq": None, "kind": None}
        else:
            state = "ok"
        if state == "ok" and self.replaced > 0:
            state, problem = "broken", _problem("chain_replaced", None, None)
        return {
            "v": 1, "state": state, "checked_at": float(now),
            "full_checked_at": None if self.full_checked_at is None else float(self.full_checked_at),
            "full_ok": self.full_ok,
            "anchored_at": None if self.anchored_at is None else float(self.anchored_at),
            "last_anchor_seq": self.last_anchor_seq,
            "problem": problem,
            "retired_forced": self.forced, "retired_offline": self.offline,
            "replaced_history": self.replaced,
        }


def _problem(kind, seq, switch_kind) -> dict:
    return {"type": kind if kind in PROBLEM_TYPES else "unknown",
            "seq": seq if isinstance(seq, int) and not isinstance(seq, bool) and seq >= 0 else None,
            "kind": switch_kind if kind == "chain_replaced" and switch_kind in cl.SWITCH_KINDS else None}


def write_public_status(directory: Path, data: dict) -> None:
    """Atomically replace status via a no-follow temp file and fsync, avoiding partial reads."""
    body = json.dumps(data, separators=(",", ":"), allow_nan=False).encode("ascii")
    tmp = directory / f".{PUBLIC_STATUS_NAME}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
    try:
        os.fchmod(fd, 0o644)
        view = memoryview(body)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, directory / PUBLIC_STATUS_NAME)
    cl._fsync_dir(directory)


AUDIT_UID = 10002
ACL_XATTRS = ("system.posix_acl_access", "system.posix_acl_default")


def check_dir(directory: Path, uid: int | None = None) -> str | None:
    """Check for a real uid-10002 mode-700 directory without a POSIX ACL; return a reason if unsafe."""
    uid = AUDIT_UID if uid is None else uid
    try:
        info = os.lstat(directory)
    except OSError as exc:
        return f"anchor directory {directory}: {describe_error(exc)}"
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        return f"anchor directory {directory} is not a directory"
    mode = stat.S_IMODE(info.st_mode)
    if info.st_uid != uid or mode != 0o700:
        return (f"anchor directory {directory} is owner uid {info.st_uid} mode {mode:o}, "
                f"not owner uid {uid} mode 700")
    try:
        acl = [name for name in os.listxattr(directory, follow_symlinks=False) if name in ACL_XATTRS]
    except OSError:
        acl = []     # No ACL support.
    if acl:
        return f"anchor directory {directory} has a POSIX ACL ({', '.join(acl)})"
    return None


def check_dir_main() -> int:
    problem = check_dir(ANCHOR_DIR)
    if problem:
        say(f"ERROR {problem}")
        return 1
    say(f"OK anchor directory {ANCHOR_DIR}: owner uid {AUDIT_UID}, mode 700, no ACL")
    return 0


def prepare(key: bytes) -> int:
    """Prepare fresh anchors before writes; fail closed on unsafe setup."""
    problem = check_dir(ANCHOR_DIR)
    if problem:
        say(f"audit_prepare: ERROR {problem}")
        return 1
    try:
        if (ANCHOR_DIR / cl.REGISTRY).exists() or cl.anchor_files(ANCHOR_DIR):
            say("audit_prepare: chain registry present, nothing to prepare")
            return 0
    except OSError:
        pass
    result = run_cycle(key, {})
    say(f"audit_prepare: {result.line}")
    return 1 if result.error in ("anchor_dir", "database") else 0


def _db_source():
    conn = cl.connect()
    return cl.DbSource(conn), conn.close


NIL_CHAIN = "00000000-0000-0000-0000-000000000000"


def _retire_without_registry(registry: Path, key: bytes, force: bool, open_source) -> int:
    """Handle a missing registry: protect a non-empty journal unless retirement is forced."""
    try:
        source, close = open_source()
    except Exception as exc:
        say(f"ERROR retire: database unavailable ({type(exc).__name__})")
        return 3
    try:
        head = source.head()
        if head is not None:
            chain, last_seq, last_hash = head["chain_id"], head["last_seq"], bytes(head["last_hash"]).hex()
        else:
            chain, last_seq, last_hash = NIL_CHAIN, 0, "0" * 64
        if not cl.journal_holds_chain(source, head):
            say("retire: no chain registry and an empty journal, nothing to close")
            return 0
        say(f"BROKEN type=registry_missing chain={chain} last_seq={last_seq} (the database holds a chain)")
        if not force:
            say("retire refused: no chain registry (anchor directory missing, renamed or replaced?) while the "
                "database holds a chain; RETIRE_FORCE=yes CONFIRM=yes closes it as forced no_registry")
            return 2
        cl.append_line(registry, key, cl.ZERO_MAC,
                       f"{cl.VERSION} retire {chain} {last_seq} {last_hash} forced no_registry@- {cl.utc()}")
        say(f"retired chain={chain} forced no_registry@- (new registry)")
        return 0
    finally:
        close()


def retire(key: bytes, force: bool, offline: bool, directory: Path | None = None, open_source=_db_source) -> int:
    """Retire the open chain after verification, with --force, or offline without a database."""
    directory = directory or ANCHOR_DIR
    with cl.locked(directory):
        registry = directory / cl.REGISTRY
        if not registry.exists():
            if offline:     # Nothing to protect.
                say("retire: no chain registry, nothing to close")
                return 0
            return _retire_without_registry(registry, key, force, open_source)
        try:
            entries, reg_mac = cl.parse_registry(registry, key)
        except cl.Broken as broken:
            say(broken.line())
            return 2
        state = cl.registry_state(entries)
        current = state.current
        if current is None:
            say("retire: no open chain (already retired), nothing to do")
            return 0
        switches = state.switched_to.get(current, [])
        if switches and not force and not offline:
            # Never clear unacknowledged replacement evidence.
            last = switches[-1]
            say(f"BROKEN type=chain_replaced kind={last.switch_kind} old={last.old or '-'} new={current}")
            say("retire refused: the chain was replaced (chain_replaced); "
                "RETIRE_FORCE=yes CONFIRM=yes closes it as forced")
            return 2
        if offline:
            cl.append_line(registry, key, reg_mac, f"{cl.VERSION} retire {current} - - offline - {cl.utc()}")
            say(f"retired chain={current} offline")
            return 0
        try:
            source, close = open_source()
        except Exception as exc:
            say(f"ERROR retire: database unavailable ({type(exc).__name__})")
            return 3
        try:
            head = source.head()
            if switches:   # Requires --force.
                if head is not None and head["chain_id"] == current:
                    last_seq, last_hash = head["last_seq"], bytes(head["last_hash"]).hex()
                else:
                    last_seq, last_hash = 0, "0" * 64
                cl.append_line(registry, key, reg_mac,
                               f"{cl.VERSION} retire {current} {last_seq} {last_hash} forced "
                               f"chain_replaced@- {cl.utc()}")
                say(f"retired chain={current} forced chain_replaced@-")
                return 0
            try:
                anchors, _ = cl.read_anchors(directory / f"{current}.log", key, current)
                _, last_seq, last_hash = cl.check_full(source, current, anchors)
                cl.append_line(registry, key, reg_mac,
                               f"{cl.VERSION} retire {current} {last_seq} {last_hash.hex()} normal - {cl.utc()}")
                say(f"retired chain={current} seq={last_seq}")
                return 0
            except (cl.Broken, FileNotFoundError) as broken:
                if isinstance(broken, FileNotFoundError):
                    broken = cl.Broken("anchor_mismatch", detail="anchor file missing")
                say(broken.line())
                if not force:
                    say("retire refused: the chain is broken (RETIRE_FORCE=yes closes it as forced)")
                    return 2
                if head is not None:
                    last_seq, last_hash = head["last_seq"], bytes(head["last_hash"]).hex()
                else:
                    last_seq, last_hash = 0, "0" * 64
                where = broken.seq if broken.seq is not None else "-"
                cl.append_line(registry, key, reg_mac,
                               f"{cl.VERSION} retire {current} {last_seq} {last_hash} forced "
                               f"{broken.kind}@{where} {cl.utc()}")
                say(f"retired chain={current} forced {broken.kind}@{where}")
                return 0
        finally:
            close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--retire", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--health", action="store_true")
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--check-dir", action="store_true")
    args = parser.parse_args(argv)
    if args.health:
        return health()
    if args.check_dir:
        return check_dir_main()
    if (args.force or args.offline) and not args.retire:
        parser.error("--force and --offline go with --retire")
    key = cl.load_key(KEY_FILE)
    if args.retire:
        return retire(key, args.force, args.offline)
    if args.prepare:
        return prepare(key)
    every = interval()
    holder: dict = {}
    if args.once:
        result = run_cycle(key, holder, every=every)
        say(("OK " if result.ok else "") + result.line)
        return 0 if result.ok else 1
    public = PublicStatus(full_check_every())
    say(f"audit_anchor: every {every} s, full check every {public.full_every} s, anchors in {ANCHOR_DIR}")
    while True:
        result, data = public.step(time.time(), lambda full: run_cycle(key, holder, full, every))
        say(result.line)
        if result.full is not None:
            problem = public.full_problem or {}
            say("full check: OK" if result.full.ok else f"full check: BROKEN type={problem.get('type')}")
        write_status(result, every)
        try:
            write_public_status(PUBLIC_STATUS_DIR, data)
        except OSError as exc:   # Keep anchor errors.
            say(f"WARN public status not written ({type(exc).__name__})")
        time.sleep(every)


if __name__ == "__main__":
    sys.exit(main())
