"""audit_anchor service (plan 17 §8): every CLINIC_AUDIT_ANCHOR_INTERVAL
seconds check the journal from the last anchor on and, only if it is intact,
append a HMAC-signed anchor line for the chain head.

    python anchor.py                      loop (the service)
    python anchor.py --once               one cycle now (E6, tests)
    python anchor.py --retire [--force]   close the open chain before a wipe
    python anchor.py --retire --offline   close it without a database
    python anchor.py --health             healthcheck of the running loop

--retire refuses with 2 when the chain is broken, was replaced
(chain_replaced) or the registry is missing while the database holds a chain;
--force closes it anyway as forced (<break>@<seq>, chain_replaced@- or
no_registry@-), 3 when the database is unavailable.

The key (/run/secrets/audit_anchor_key) is mounted only into this service.
Output carries seq, break type and chain id only: never the key, a MAC input
or the content of an event.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import chainlib as cl

ANCHOR_DIR = Path(os.environ.get("CLINIC_AUDIT_ANCHOR_PATH", "/anchors"))
KEY_FILE = os.environ.get("CLINIC_AUDIT_ANCHOR_KEY_FILE", "/run/secrets/audit_anchor_key")
STATUS_FILE = Path(os.environ.get("CLINIC_AUDIT_STATUS_FILE", "/tmp/audit_anchor_status.json"))


def say(text: str) -> None:
    print(text, flush=True)


def interval() -> int:
    raw = os.environ.get("CLINIC_AUDIT_ANCHOR_INTERVAL", "60")
    if not raw.isdigit() or not 10 <= int(raw) <= 3600:
        raise SystemExit("CLINIC_AUDIT_ANCHOR_INTERVAL must be an integer from 10 to 3600")
    return int(raw)


class Result:
    def __init__(self, ok: bool, state: str, error: str | None = None, anchored=None, line: str = ""):
        self.ok, self.state, self.error, self.anchored, self.line = ok, state, error, anchored, line


def _anchor(directory: Path, key: bytes, source, chain_id: str) -> Result:
    path = directory / f"{chain_id}.log"
    anchors, prev = cl.read_anchors(path, key, chain_id)
    _, last_seq, last_hash = cl.check_from_anchor(source, chain_id, anchors[-1] if anchors else None)
    now = cl.utc()
    cl.append_line(path, key, prev, f"{cl.VERSION} {chain_id} {last_seq} {last_hash.hex()} {now}")
    return Result(True, "anchoring", anchored=(last_seq, now), line=f"anchored chain={chain_id} seq={last_seq}")


def cycle(directory: Path, key: bytes, source) -> Result:
    """One read -> verify -> append -> fsync step under the directory lock."""
    if not os.access(directory, os.W_OK | os.X_OK):
        return Result(False, "error", "anchor_dir", line=f"anchor directory {directory} is not writable")
    with cl.locked(directory):
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
            decision = cl.decide(state, h, head["genesis_rows"], has_registry,
                                 bool(cl.anchor_files(directory)))
            if decision.action == "error":
                kind = decision.kind
                text = {"registry_missing": "audit chain registry missing",
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
                result.ok, result.error = False, "chain_replaced"
                result.line += f" (chain_replaced kind={kind}: needs a human)"
            return result
        except cl.Broken as broken:
            return Result(False, "error", broken.kind, line=f"ERROR audit chain broken: {broken.line()}")


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


def run_cycle(key: bytes, conn_holder: dict) -> Result:
    try:
        if conn_holder.get("conn") is None or conn_holder["conn"].closed:
            conn_holder["conn"] = cl.connect()
        conn = conn_holder["conn"]
        try:
            return cycle(ANCHOR_DIR, key, cl.DbSource(conn))
        finally:
            conn.rollback()  # a fresh snapshot for the next cycle
    except Exception as exc:  # database down, permissions: no anchor, red health
        if conn_holder.get("conn") is not None:
            try:
                conn_holder["conn"].close()
            except Exception:
                pass
            conn_holder["conn"] = None
        return Result(False, "error", "database", line=f"ERROR audit cycle failed: {type(exc).__name__}")


def _db_source():
    conn = cl.connect()
    return cl.DbSource(conn), conn.close


NIL_CHAIN = "00000000-0000-0000-0000-000000000000"


def _retire_without_registry(registry: Path, key: bytes, force: bool, open_source) -> int:
    """З-10: no chains.log, but the database may still hold a chain (the anchor
    directory was removed or renamed). "A chain" = a head with last_seq > 0, or
    journal rows without a head. An empty chain (fresh volume, genesis only)
    has nothing to protect. Otherwise refuse (2) unless forced; forced writes
    the first line of a new registry: retire <chain> ... forced no_registry@-."""
    try:
        source, close = open_source()
    except Exception as exc:
        say(f"ERROR retire: database unavailable ({type(exc).__name__})")
        return 3
    try:
        head = source.head()
        if head is not None:
            chain, last_seq, last_hash = head["chain_id"], head["last_seq"], bytes(head["last_hash"]).hex()
            present = last_seq > 0
        else:
            chain, last_seq, last_hash = NIL_CHAIN, 0, "0" * 64
            present = next(iter(source.rows_from(1)), None) is not None
        if not present:
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
    """Close the open chain C in the registry (§8.6): normal after a full check,
    forced (only with --force, the break is printed first) or offline."""
    directory = directory or ANCHOR_DIR
    with cl.locked(directory):
        registry = directory / cl.REGISTRY
        if not registry.exists():
            if offline:     # no database volume either: nothing to protect (unchanged)
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
            # chain_replaced not acknowledged by anyone: a plain reset would wipe
            # the evidence and turn the daemon green again (Securo, 90f093f §2)
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
            if switches:   # only with --force here
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
    args = parser.parse_args(argv)
    if args.health:
        return health()
    if (args.force or args.offline) and not args.retire:
        parser.error("--force and --offline go with --retire")
    key = cl.load_key(KEY_FILE)
    if args.retire:
        return retire(key, args.force, args.offline)
    every = interval()
    holder: dict = {}
    if args.once:
        result = run_cycle(key, holder)
        say(("OK " if result.ok else "") + result.line)
        return 0 if result.ok else 1
    say(f"audit_anchor: every {every} s, anchors in {ANCHOR_DIR}")
    while True:
        result = run_cycle(key, holder)
        say(result.line)
        write_status(result, every)
        time.sleep(every)


if __name__ == "__main__":
    sys.exit(main())
