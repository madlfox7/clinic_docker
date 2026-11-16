"""Shared code of anchor.py and verify_audit.py (plan 17 §8-§9).

- verification of the journal rows (canon and hashes from canon.py only);
- anchor files <chain_id>.log and the chain registry chains.log: one strict
  line format each, a HMAC-SHA256 chain over the lines (prev_mac of the first
  line = 32 zero bytes);
- the registry rules of §8.6;
- the exclusive lock on <anchor dir>/.lock (Securo Б-B1).

Nothing here logs or returns the key, a MAC input or the content of an event:
errors carry a type, a seq and a chain id at most.
"""
from __future__ import annotations

import datetime as _dt
import fcntl
import hashlib
import hmac
import os
import re
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

import canon

VERSION = "v1"
ZERO_MAC = bytes(32)
REGISTRY = "chains.log"
LOCK = ".lock"
TRIGGERS = (
    ("audit_events", "zz_audit_chain"),
    ("audit_events", "audit_events_no_update_delete"),
    ("audit_events", "audit_events_no_truncate"),
    ("audit_chain_head", "audit_chain_head_guard"),
    ("audit_chain_head", "audit_chain_head_no_delete"),
    ("audit_chain_head", "audit_chain_head_no_truncate"),
)
RETIRE_MODES = ("normal", "forced", "offline")
SWITCH_KINDS = ("new", "reused", "retired_reused")
BREAK_TYPES = ("gap", "prev_hash", "row_hash", "head", "hash_version", "anchor_mismatch",
               "truncated", "chain_replaced", "head_missing")

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_INT = re.compile(r"^(0|[1-9][0-9]*)$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_ANCHOR_FILE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.log$")


# --- the MAC: the one place that names it (HMAC-SHA256) ------------------------

def line_mac(key: bytes, prev_mac: bytes, body: str) -> bytes:
    return hmac.new(key, prev_mac + body.encode("ascii"), hashlib.sha256).digest()


def utc(value: _dt.datetime | None = None) -> str:
    value = value or _dt.datetime.now(_dt.timezone.utc)
    return value.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_utc(text: str) -> _dt.datetime:
    return _dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=_dt.timezone.utc)


def load_key(path: str | os.PathLike) -> bytes:
    text = Path(path).read_text().strip()
    if not _HEX64.match(text):
        raise ValueError("audit_anchor_key must be 64 hex characters")
    return bytes.fromhex(text)


class Broken(Exception):
    """A break in the journal, an anchor file or the registry (BROKEN type=...)."""

    def __init__(self, kind: str, seq=None, row_id=None, detail: str = ""):
        super().__init__(kind)
        self.kind, self.seq, self.row_id, self.detail = kind, seq, row_id, detail

    def line(self) -> str:
        parts = ["BROKEN"]
        if self.seq is not None:
            parts.append(f"seq={self.seq}")
        if self.row_id is not None:
            parts.append(f"id={self.row_id}")
        parts.append(f"type={self.kind}")
        if self.detail:
            parts.append(self.detail)
        return " ".join(parts)


# --- line files (anchors and registry) -----------------------------------------

@dataclass
class Anchor:
    chain_id: str
    seq: int
    row_hash: str
    at: str


@dataclass
class Entry:
    kind: str            # open | retire | switch
    line_no: int
    chain_id: str | None = None
    genesis_at: str | None = None
    genesis_rows: int | None = None
    last_seq: int | None = None
    row_hash: str | None = None
    mode: str | None = None
    brk: str | None = None
    old: str | None = None
    new: str | None = None
    switch_kind: str | None = None
    at: str = ""


def _read_lines(path: Path) -> list[str]:
    data = path.read_bytes()
    if data and not data.endswith(b"\n"):
        # a torn last line (crash mid-write) is a format error, not data
        torn = data.count(b"\n") + 1
        raise Broken("registry_format" if path.name == REGISTRY else "anchor_format",
                     detail=f"file={path.name} line={torn}")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise Broken("registry_format" if path.name == REGISTRY else "anchor_format",
                     detail=f"file={path.name}") from None
    return text.splitlines()


def _check_mac(key, prev, body, mac_hex, kind, path, number):
    if not _HEX64.match(mac_hex):
        raise Broken(f"{kind}_format", detail=f"file={path.name} line={number}")
    mac = bytes.fromhex(mac_hex)
    if not hmac.compare_digest(line_mac(key, prev, body), mac):
        raise Broken(f"{kind}_mac", detail=f"file={path.name} line={number}")
    return mac


def read_anchors(path: Path, key: bytes, chain_id: str) -> tuple[list[Anchor], bytes]:
    """All anchors of one chain file and the MAC of its last line."""
    prev, anchors = ZERO_MAC, []
    for number, line in enumerate(_read_lines(path), 1):
        fields = line.split(" ")
        bad = Broken("anchor_format", detail=f"file={path.name} line={number}")
        if len(fields) != 6 or fields[0] != VERSION or fields[1] != chain_id:
            raise bad
        _, cid, seq, rhash, at, mac_hex = fields
        if not (_INT.match(seq) and _HEX64.match(rhash) and _UTC.match(at)):
            raise bad
        prev = _check_mac(key, prev, " ".join(fields[:5]), mac_hex, "anchor", path, number)
        anchors.append(Anchor(cid, int(seq), rhash, at))
    return anchors, prev


def _uuid_or_dash(value: str, dash_ok: bool) -> bool:
    return (dash_ok and value == "-") or bool(_UUID.match(value))


def parse_registry(path: Path, key: bytes) -> tuple[list[Entry], bytes]:
    """Strict parser (§8.6): fixed field count per type, enums, MAC chain."""
    prev, entries = ZERO_MAC, []
    for number, line in enumerate(_read_lines(path), 1):
        f = line.split(" ")
        bad = Broken("registry_format", detail=f"line={number}")
        if len(f) < 2 or f[0] != VERSION:
            raise bad
        kind = f[1]
        if kind == "open":
            if len(f) != 7 or not _UUID.match(f[2]) or not _UTC.match(f[3]) \
                    or not _INT.match(f[4]) or not _UTC.match(f[5]):
                raise bad
            entry = Entry("open", number, chain_id=f[2], genesis_at=f[3],
                          genesis_rows=int(f[4]), at=f[5])
        elif kind == "retire":
            if len(f) != 9 or not _UUID.match(f[2]) or f[5] not in RETIRE_MODES or not _UTC.match(f[7]):
                raise bad
            offline = f[5] == "offline"
            if offline:
                if (f[3], f[4], f[6]) != ("-", "-", "-"):
                    raise bad
            else:
                if not _INT.match(f[3]) or not _HEX64.match(f[4]):
                    raise bad
                if f[5] == "normal" and f[6] != "-":
                    raise bad
                if f[5] == "forced":
                    m = re.match(r"^([a-z_]+)@(0|[1-9][0-9]*|-)$", f[6])
                    if not m or m.group(1) not in BREAK_TYPES:
                        raise bad
            entry = Entry("retire", number, chain_id=f[2],
                          last_seq=None if offline else int(f[3]),
                          row_hash=None if offline else f[4], mode=f[5], brk=f[6], at=f[7])
        elif kind == "switch":
            if len(f) != 7 or not _uuid_or_dash(f[2], True) or not _UUID.match(f[3]) \
                    or f[4] not in SWITCH_KINDS or not _UTC.match(f[5]):
                raise bad
            entry = Entry("switch", number, old=None if f[2] == "-" else f[2], new=f[3],
                          switch_kind=f[4], at=f[5])
        else:
            raise bad
        prev = _check_mac(key, prev, " ".join(f[:-1]), f[-1], "registry", path, number)
        entries.append(entry)
    return entries, prev


def append_line(path: Path, key: bytes, prev_mac: bytes, body: str) -> bytes:
    """Append one MAC-chained line and fsync it. Files are 0644 inside the
    700 anchor directory, so the host user can read them (Securo fix 3)."""
    mac = line_mac(key, prev_mac, body)
    created = not path.exists()
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    try:
        os.fchmod(fd, 0o644)
        os.write(fd, f"{body} {mac.hex()}\n".encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
    if created:
        _fsync_dir(path.parent)
    return mac


def touch(path: Path) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    try:
        os.fchmod(fd, 0o644)
        os.fsync(fd)
    finally:
        os.close(fd)
    _fsync_dir(path.parent)


def _fsync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextmanager
def locked(directory: Path):
    """Exclusive flock on <dir>/.lock for a whole read -> verify -> append ->
    fsync step, in every mode (loop, --once, --retire; Б-B1). prev_mac is
    always read from the file under this lock, never kept in memory."""
    fd = os.open(directory / LOCK, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def anchor_files(directory: Path) -> list[Path]:
    return sorted(p for p in directory.iterdir() if _ANCHOR_FILE.match(p.name))


# --- registry state -------------------------------------------------------------

@dataclass
class RegistryState:
    entries: list[Entry] = field(default_factory=list)
    current: str | None = None          # C: open chain (last open/switch without a later retire)
    last_retired: Entry | None = None   # the retire entry when there is no C
    known: set = field(default_factory=set)
    switched_to: dict = field(default_factory=dict)   # new id -> list of switch entries
    opened: dict = field(default_factory=dict)        # id -> number of open lines


def registry_state(entries: list[Entry]) -> RegistryState:
    state = RegistryState(entries=entries)
    for e in entries:
        if e.kind == "open":
            state.known.add(e.chain_id)
            state.opened[e.chain_id] = state.opened.get(e.chain_id, 0) + 1
            state.current, state.last_retired = e.chain_id, None
        elif e.kind == "switch":
            if e.old:
                state.known.add(e.old)
            state.known.add(e.new)
            state.switched_to.setdefault(e.new, []).append(e)
            state.current, state.last_retired = e.new, None
        elif e.kind == "retire":
            state.known.add(e.chain_id)
            if state.current == e.chain_id:
                state.current = None
            state.last_retired = e
    return state


@dataclass
class Decision:
    action: str                 # first_open | open | normal | switch | retired_check | error
    kind: str | None = None     # switch kind / error type
    old: str | None = None


def decide(state: RegistryState, head_chain: str, genesis_rows: int, has_registry: bool,
           has_anchor_files: bool) -> Decision:
    """§8.6 rules 1-7 for the head chain H against the registry."""
    if not has_registry:
        if has_anchor_files:
            return Decision("error", "registry_missing")
        return Decision("first_open")
    c = state.current
    if c is not None and head_chain == c:
        return Decision("normal")
    if head_chain not in state.known:
        if c is not None:
            return Decision("switch", "new", old=c)
        if state.entries and genesis_rows > 0:
            return Decision("error", "genesis_rows")
        return Decision("open")
    if c is None and state.last_retired is not None and state.last_retired.chain_id == head_chain:
        if state.last_retired.mode == "offline":
            return Decision("switch", "retired_reused", old=head_chain)
        return Decision("retired_check")
    return Decision("switch", "reused", old=c)


# --- journal verification ---------------------------------------------------------

def check_rows(rows, chain_id: str, prev_hash: bytes, expect_seq: int, anchors: dict | None = None):
    """Stream rows in seq order from expect_seq on, linked to prev_hash.

    anchors: {seq: row_hash hex} checked on the way. Returns (count, last_seq,
    last_hash). Raises Broken at the first break."""
    count, last_seq, last_hash = 0, expect_seq - 1, prev_hash
    for row in rows:
        seq = row["seq"]
        if seq != expect_seq:
            raise Broken("gap", seq=expect_seq, row_id=None, detail=f"next={seq}")
        if row["hash_version"] != canon.HASH_VERSION:
            raise Broken("hash_version", seq=seq, row_id=row["id"])
        if bytes(row["prev_hash"]) != last_hash:
            raise Broken("prev_hash", seq=seq, row_id=row["id"])
        computed = canon.row_hash(last_hash, row)
        if bytes(row["row_hash"]) != computed:
            raise Broken("row_hash", seq=seq, row_id=row["id"])
        if anchors is not None and seq in anchors and anchors[seq] != computed.hex():
            raise Broken("anchor_mismatch", seq=seq, row_id=row["id"])
        count, last_seq, last_hash, expect_seq = count + 1, seq, computed, seq + 1
    return count, last_seq, last_hash


def check_full(source, chain_id: str, anchors: list[Anchor]):
    """Whole chain from seq 1, every anchor of the file, head, tail truncation."""
    by_seq = {a.seq: a.row_hash for a in anchors}
    count, last_seq, last_hash = check_rows(source.rows_from(1), chain_id,
                                            canon.genesis_prev_hash(chain_id), 1, by_seq)
    if anchors and last_seq < max(by_seq):
        raise Broken("truncated", seq=last_seq + 1, detail=f"anchored={max(by_seq)}")
    head = source.head()
    if head is None:
        raise Broken("head_missing")
    if head["chain_id"] != chain_id or head["last_seq"] != last_seq or bytes(head["last_hash"]) != last_hash:
        raise Broken("head", seq=head["last_seq"])
    return count, last_seq, last_hash


def check_from_anchor(source, chain_id: str, anchor: Anchor | None):
    """Incremental check of the anchor cycle (§8.5): the anchored row still has
    its hash, then every row after it links on; head = last row."""
    if anchor is None:
        return check_full(source, chain_id, [])
    if anchor.seq == 0:
        # anchored while the chain was still empty (fresh volume)
        if anchor.row_hash != canon.genesis_prev_hash(chain_id).hex():
            raise Broken("anchor_mismatch", seq=0)
        return check_full(source, chain_id, [])
    row = source.row(anchor.seq)
    if row is None:
        raise Broken("truncated", seq=anchor.seq)
    if bytes(row["row_hash"]).hex() != anchor.row_hash \
            or canon.row_hash(bytes(row["prev_hash"]), row).hex() != anchor.row_hash:
        raise Broken("anchor_mismatch", seq=anchor.seq, row_id=row["id"])
    count, last_seq, last_hash = check_rows(source.rows_from(anchor.seq + 1), chain_id,
                                            bytes.fromhex(anchor.row_hash), anchor.seq + 1)
    head = source.head()
    if head is None:
        raise Broken("head_missing")
    if head["chain_id"] != chain_id or head["last_seq"] != last_seq or bytes(head["last_hash"]) != last_hash:
        raise Broken("head", seq=head["last_seq"])
    return count, last_seq, last_hash


def check_triggers(source) -> None:
    modes = source.trigger_modes()
    for table, name in TRIGGERS:
        mode = modes.get((table, name), "missing")
        if mode != "A":
            raise Broken("trigger_mode", detail=f"name={name} mode={mode}")


# --- database source (clinic_auditor) -----------------------------------------------

ROW_COLUMNS = ("seq", "id", "created_at", "actor_user_id", "actor_role", "action", "target_type",
               "target_id", "reason", "source", "old_value", "new_value", "prev_hash", "row_hash",
               "hash_version")


class DbSource:
    def __init__(self, conn):
        self.conn = conn

    def _row(self, values):
        row = dict(zip(ROW_COLUMNS, values))
        row["prev_hash"] = bytes(row["prev_hash"])
        row["row_hash"] = bytes(row["row_hash"])
        return row

    def head(self):
        with self.conn.cursor() as cur:
            cur.execute("SELECT chain_id::text, last_seq, last_hash, genesis_at, genesis_rows "
                        "FROM public.audit_chain_head WHERE id = 1")
            found = cur.fetchone()
        if not found:
            return None
        return {"chain_id": found[0], "last_seq": found[1], "last_hash": bytes(found[2]),
                "genesis_at": found[3], "genesis_rows": found[4]}

    def row(self, seq: int):
        with self.conn.cursor() as cur:
            cur.execute(f"SELECT {', '.join(ROW_COLUMNS)} FROM public.audit_events WHERE seq = %s", (seq,))
            found = cur.fetchone()
        return self._row(found) if found else None

    def rows_from(self, seq: int):
        # server-side cursor: 100k rows are streamed, not loaded (§9.1)
        with self.conn.cursor(name=f"audit_rows_{uuid.uuid4().hex}") as cur:
            cur.itersize = 2000
            cur.execute(f"SELECT {', '.join(ROW_COLUMNS)} FROM public.audit_events "
                        "WHERE seq >= %s ORDER BY seq", (seq,))
            for values in cur:
                yield self._row(values)

    def trigger_modes(self) -> dict:
        with self.conn.cursor() as cur:
            cur.execute("SELECT c.relname, t.tgname, t.tgenabled::text FROM pg_catalog.pg_trigger t "
                        "JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid "
                        "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
                        "WHERE n.nspname = 'public' AND c.relname IN ('audit_events', 'audit_chain_head') "
                        "AND NOT t.tgisinternal")
            return {(table, name): mode for table, name, mode in cur.fetchall()}


def connect():
    import psycopg2  # only inside the service image

    password = Path(os.environ.get("CLINIC_AUDIT_DB_PASSWORD_FILE", "/run/secrets/audit_db_password")).read_text().strip()
    conn = psycopg2.connect(host=os.environ.get("PGHOST", "db"), user=os.environ.get("PGUSER", "clinic_auditor"),
                            dbname=os.environ.get("PGDATABASE", "clinic"), password=password,
                            connect_timeout=10, application_name="audit_anchor")
    conn.set_session(readonly=True, isolation_level="REPEATABLE READ")
    return conn
