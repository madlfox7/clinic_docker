"""Independent check of the audit journal (plan 17 §9.1, A5).

    python verify_audit.py [--strict] [--anchors <dir>]

Recomputes the canon and every hash itself (canon.py) and trusts no function
in the database. Checks seq from 1, prev_hash links, row_hash, hash_version,
the head, the anchor file of the chain (MAC chain, every anchor against its
row, no truncated tail), the chain registry (§8.6 rules again, not trusting
anchor.py) and the mode 'A' of the six journal triggers.

Exit codes: 0 OK (WARN lines for forced/offline retires are allowed),
1 BROKEN, 2 the check could not run (no key, database unavailable, bad
arguments), 3 with --strict when a retire was forced or offline.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

import chainlib as cl

ANCHOR_DIR = Path(os.environ.get("CLINIC_AUDIT_ANCHOR_PATH", "/anchors"))
KEY_FILE = os.environ.get("CLINIC_AUDIT_ANCHOR_KEY_FILE", "/run/secrets/audit_anchor_key")


def check_registry(directory: Path, key: bytes, head: dict, source):
    """Returns (anchors of the head chain, warnings, forced, offline)."""
    registry = directory / cl.REGISTRY
    if not registry.exists():
        if cl.anchor_files(directory):
            raise cl.Broken("registry_missing")
        raise cl.Broken("registry_missing", detail="no registry and no anchors yet")
    entries, _ = cl.parse_registry(registry, key)
    warnings, forced, offline = [], 0, 0
    opened, seen_before = {}, set()
    # A switch stays BROKEN for good; the registry is still read to the end so
    # that a later forced retire of the replaced chain is shown as a WARN too.
    switched: cl.Broken | None = None

    def broken(kind: str, detail: str) -> cl.Broken:
        if switched is not None:
            switched.warnings = warnings
            return switched
        return cl.Broken(kind, detail=detail)

    for e in entries:
        if e.kind == "open":
            opened[e.chain_id] = opened.get(e.chain_id, 0) + 1
            if opened[e.chain_id] > 1 or e.chain_id in seen_before:
                raise broken("chain_replaced", f"kind=reused old=- new={e.chain_id}")
            if seen_before and e.genesis_rows > 0:
                raise broken("chain_replaced", f"kind=new old=- new={e.chain_id} genesis_rows={e.genesis_rows}")
            seen_before.add(e.chain_id)
        elif e.kind == "switch":
            if switched is None:
                switched = cl.Broken("chain_replaced", detail=f"kind={e.switch_kind} old={e.old or '-'} new={e.new}")
            seen_before.add(e.new)
        elif e.kind == "retire":
            seen_before.add(e.chain_id)
            if e.mode == "forced":
                forced += 1
                warnings.append(f"WARN retire forced chain={e.chain_id} break={e.brk}")
            elif e.mode == "offline":
                offline += 1
                warnings.append(f"WARN retire offline chain={e.chain_id}")
    if switched is not None:
        raise broken("chain_replaced", "")
    state = cl.registry_state(entries)
    for chain_id in opened:
        if not (directory / f"{chain_id}.log").exists():
            raise cl.Broken("anchor_mismatch", detail=f"anchor file missing chain={chain_id}")
    h = head["chain_id"]
    anchors, _ = cl.read_anchors(directory / f"{h}.log", key, h) if (directory / f"{h}.log").exists() else ([], None)
    if state.current == h:
        return anchors, warnings, forced, offline
    retired = state.last_retired
    if state.current is None and retired is not None and retired.chain_id == h and retired.mode != "offline":
        _, last_seq, last_hash = cl.check_full(source, h, anchors)
        if last_seq == retired.last_seq and last_hash.hex() == retired.row_hash:
            warnings.append(f"WARN chain={h} is retired (between --retire and down -v)")
            return anchors, warnings, forced, offline
        raise cl.Broken("chain_replaced", detail=f"kind=retired_reused old={h} new={h}")
    kind = "reused" if h in state.known else "new"
    raise cl.Broken("chain_replaced", detail=f"kind={kind} old={state.current or '-'} new={h}")


def check_copy(directory: Path, copy: Path) -> None:
    """--anchors: an outside copy (WORM) must be a prefix of the local files."""
    for theirs in sorted(copy.iterdir()):
        if theirs.name != cl.REGISTRY and theirs not in cl.anchor_files(copy):
            continue
        ours = directory / theirs.name
        mine = ours.read_bytes() if ours.exists() else b""
        if not mine.startswith(theirs.read_bytes()):
            raise cl.Broken("anchor_copy_mismatch", detail=f"file={theirs.name}")


def verify(source, directory: Path, key: bytes, strict: bool, copy: Path | None, every: int, out=print) -> int:
    try:
        cl.check_triggers(source)
        head = source.head()
        if head is None:
            raise cl.Broken("head_missing")
        anchors, warnings, forced, offline = check_registry(directory, key, head, source)
        count, last_seq, _ = cl.check_full(source, head["chain_id"], anchors)
        if copy is not None:
            check_copy(directory, copy)
    except cl.Broken as broken:
        for line in getattr(broken, "warnings", None) or []:
            out(line)
        out(broken.line())
        return 1
    age = "-"
    if anchors:
        age_s = time.time() - cl.parse_utc(anchors[-1].at).timestamp()
        age = str(int(age_s))
        if age_s > 2 * every:
            warnings.append(f"WARN last anchor is {int(age_s)} s old (more than 2 intervals): is audit_anchor running?")
    for line in warnings:
        out(line)
    out(f"OK chain={head['chain_id']} rows={count} anchors={len(anchors)} last_anchor_age={age} "
        f"retired_forced={forced} retired_offline={offline}")
    return 3 if strict and (forced or offline) else 0


def main(argv=None, out=print) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--strict", action="store_true", help="exit 3 if any retire was forced or offline")
    parser.add_argument("--anchors", type=Path, help="outside copy of the anchor directory to compare")
    args = parser.parse_args(argv)
    raw = os.environ.get("CLINIC_AUDIT_ANCHOR_INTERVAL", "60")
    every = int(raw) if raw.isdigit() else 60
    # Not BROKEN: nothing was checked. Only the exception type is printed,
    # never a path content, a password or the key.
    try:
        key = cl.load_key(KEY_FILE)
    except (OSError, ValueError) as exc:
        out(f"ERROR cannot check: audit_anchor_key unavailable ({type(exc).__name__})")
        return 2
    try:
        conn = cl.connect()
    except Exception as exc:  # psycopg2 lives only in the image
        out(f"ERROR cannot check: database unavailable ({type(exc).__name__})")
        return 2
    try:
        return verify(cl.DbSource(conn), ANCHOR_DIR, key, args.strict, args.anchors, every, out)
    except Exception as exc:
        if type(exc).__module__.split(".")[0] != "psycopg2":
            raise
        out(f"ERROR cannot check: database error ({type(exc).__name__})")
        return 2
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
