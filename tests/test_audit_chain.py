"""Audit journal hash chain (plan 17 §6-§9): schema, trigger, genesis,
append-only rules and the independent Python canon (audit/canon.py)."""
import datetime as dt
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from tests.csrf_client import CsrfClient
from tests.demo_secret import demo_password

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "audit"))
import canon  # noqa: E402  (audit/canon.py, the code verify_audit trusts)

BASE = os.environ.get("CLINIC_TEST_BASE", "https://localhost:8450")
PROJECT = os.environ.get("COMPOSE_PROJECT_NAME", "")
PASSWORD = demo_password()
ADMIN = "admin@clinic.local"
PAT = "pat@clinic.local"


def _psql_try(sql: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "exec", "-T", "db", "psql", "-X", "-U", "clinic", "-d", "clinic",
         "-v", "ON_ERROR_STOP=1", "-At", "-F", "|", "-c", sql],
        cwd=ROOT, capture_output=True, text=True, timeout=120,
    )


def _psql(sql: str) -> list[str]:
    done = _psql_try(sql)
    assert done.returncode == 0, done.stderr or done.stdout
    return [line for line in done.stdout.splitlines() if line.strip()]


def _one(sql: str) -> str:
    return _psql(sql)[0]


def _user_id(email: str) -> int:
    return int(_one(f"SELECT id FROM users WHERE email = '{email}'"))


_ROW_JSON = (
    "json_build_object('seq', seq, 'id', id, "
    "'created_at', to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US'), "
    "'actor_user_id', actor_user_id, 'actor_role', actor_role, 'action', action, "
    "'target_type', target_type, 'target_id', target_id, 'reason', reason, 'source', source, "
    "'old_value', old_value, 'new_value', new_value, 'hash_version', hash_version, "
    "'prev_hash', encode(prev_hash, 'hex'), 'row_hash', encode(row_hash, 'hex'))"
)


def _decode(text: str) -> dict:
    row = json.loads(text)
    row["created_at"] = dt.datetime.fromisoformat(row["created_at"]).replace(tzinfo=dt.timezone.utc)
    row["prev_hash"] = bytes.fromhex(row["prev_hash"])
    row["row_hash"] = bytes.fromhex(row["row_hash"])
    return row


def _rows(where: str = "TRUE") -> list[dict]:
    return [_decode(line) for line in _psql(f"SELECT {_ROW_JSON} FROM audit_events WHERE {where} ORDER BY seq")]


def _head() -> dict:
    chain, last_seq, last_hash, genesis_at, genesis_rows = _one(
        "SELECT chain_id, last_seq, encode(last_hash, 'hex'), genesis_at, genesis_rows "
        "FROM audit_chain_head").split("|")
    return {"chain_id": chain, "last_seq": int(last_seq), "last_hash": bytes.fromhex(last_hash),
            "genesis_at": genesis_at, "genesis_rows": int(genesis_rows)}


def _check_links(rows: list[dict]) -> None:
    """Each row hashes to its row_hash in Python and links to the row before it."""
    for before, row in zip(rows, rows[1:]):
        assert row["seq"] == before["seq"] + 1, (before["seq"], row["seq"])
        assert row["prev_hash"] == before["row_hash"], row["seq"]
    for row in rows:
        assert row["hash_version"] == 1
        assert canon.row_hash(row["prev_hash"], row) == row["row_hash"], row["seq"]


def _mark() -> int:
    return _head()["last_seq"]


def _insert_admin_event() -> None:
    admin = _user_id(ADMIN)
    _psql(f"INSERT INTO audit_events (actor_user_id, actor_role, action, target_type, target_id) "
          f"VALUES ({admin}, 'admin', 'test.chain', 'test', {admin})")


def test_chain_schema_columns_head_and_constraints():
    cols = dict(line.split("|") for line in _psql(
        "SELECT column_name, is_nullable FROM information_schema.columns "
        "WHERE table_schema = 'public' AND table_name = 'audit_events' "
        "AND column_name IN ('seq', 'prev_hash', 'row_hash', 'hash_version')"))
    assert cols == {"seq": "NO", "prev_hash": "NO", "row_hash": "NO", "hash_version": "NO"}
    assert _one("SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conname = 'audit_events_seq_key'") == "UNIQUE (seq)"
    check = _one("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'audit_events_chain_check'")
    for part in ("octet_length(prev_hash) = 32", "octet_length(row_hash) = 32", "hash_version = 1", "seq >= 1"):
        assert part in check, check
    assert _psql("SELECT id FROM audit_chain_head") == ["1"]
    head = _head()
    last = _rows(f"seq = {head['last_seq']}")
    assert last and last[0]["row_hash"] == head["last_hash"]
    assert _one("SELECT count(*) = max(seq) FROM audit_events") == "t"


def test_canon_covers_every_journal_column():
    """A6: a new journal column without a new canon version turns this red."""
    columns = set(_psql("SELECT column_name FROM information_schema.columns "
                        "WHERE table_schema = 'public' AND table_name = 'audit_events'"))
    # seq is a chain column and also the first canon field.
    assert columns - set(canon.CHAIN_COLUMNS) | {"seq"} == set(canon.FIELDS)
    assert set(canon.CHAIN_COLUMNS) <= columns


def test_canon_encodes_every_field_with_its_length():
    row = {name: None for name in canon.FIELDS}
    row.update(seq=12, id=3, created_at=dt.datetime(1970, 1, 1, 0, 0, 1, 5, tzinfo=dt.timezone.utc),
               actor_role="admin", action="ա")
    data = canon.canon_v1(row)
    assert data == (b"clinic-audit-v1" + b"2:12" + b"1:3" + b"7:1000005" + b"-" + b"5:admin"
                    + b"2:" + "ա".encode() + b"-" * 6)
    sql = _one("SELECT encode(audit_canon_v1(12, 3, to_timestamp(1.000005), NULL, 'admin', 'ա', "
               "NULL, NULL, NULL, NULL, NULL, NULL), 'hex')")
    assert bytes.fromhex(sql) == data


def test_first_row_links_to_the_chain_id():
    head = _head()
    first = _rows("seq = 1")
    assert first and first[0]["prev_hash"] == canon.genesis_prev_hash(head["chain_id"])
    assert canon.genesis_prev_hash(head["chain_id"]) == bytes.fromhex(
        _one(f"SELECT encode(audit_genesis_hash_v1('{head['chain_id']}'), 'hex')"))


def test_app_and_superuser_inserts_join_the_chain():
    mark = _mark()
    # Through the api: a sign-in writes auth.login.success (record_auth_event).
    with CsrfClient(base_url=BASE, follow_redirects=True, timeout=10.0) as c:
        page = c.post("/login", data={"email": PAT, "password": PASSWORD})
        assert page.status_code == 200 and page.url.path == "/me"
    # As the application role app_admin, through record_audit_event.
    admin = _user_id(ADMIN)
    _psql(f"BEGIN; SET LOCAL ROLE app_admin; SELECT set_config('app.user_id', '{admin}', true); "
          f"SELECT record_audit_event('service.create', 'service', 1); COMMIT;")
    # As the superuser, straight through psql.
    _insert_admin_event()
    rows = _rows(f"seq >= {mark}")
    new = [r for r in rows if r["seq"] > mark]
    actions = [r["action"] for r in new]
    assert "auth.login.success" in actions and "service.create" in actions and actions[-1] == "test.chain"
    _check_links(rows)
    head = _head()
    assert head["last_seq"] == new[-1]["seq"] and head["last_hash"] == new[-1]["row_hash"]


def test_client_chain_values_and_created_at_are_overwritten():
    mark = _mark()
    admin = _user_id(ADMIN)
    zeros = "'\\x" + "00" * 32 + "'"
    _psql("INSERT INTO audit_events (actor_user_id, actor_role, action, target_type, target_id, "
          "seq, prev_hash, row_hash, hash_version, created_at) VALUES "
          f"({admin}, 'admin', 'test.chain', 'test', {admin}, 999999, {zeros}, {zeros}, 7, '2000-01-01')")
    rows = _rows(f"seq >= {mark}")
    row = rows[-1]
    assert row["seq"] == mark + 1 and row["hash_version"] == 1
    assert row["prev_hash"] != b"\0" * 32 and row["row_hash"] != b"\0" * 32
    assert abs(dt.datetime.now(dt.timezone.utc) - row["created_at"]) < dt.timedelta(minutes=5)
    _check_links(rows)


def test_canon_does_not_depend_on_session_settings():
    mark = _mark()
    admin = _user_id(ADMIN)
    _psql("SET TimeZone = 'Pacific/Kiritimati'; SET DateStyle = 'SQL, DMY'; "
          f"INSERT INTO audit_events (actor_user_id, actor_role, action, target_type, target_id) "
          f"VALUES ({admin}, 'admin', 'test.chain', 'test', {admin})")
    _check_links(_rows(f"seq >= {mark}"))


def test_parallel_inserts_get_consecutive_seq_and_an_intact_chain():
    mark = _mark()
    admin = _user_id(ADMIN)
    errors = []

    def insert(n: int) -> None:
        done = _psql_try(f"INSERT INTO audit_events (actor_user_id, actor_role, action, target_type, target_id) "
                         f"VALUES ({admin}, 'admin', 'test.chain', 'test', {n})")
        if done.returncode != 0:
            errors.append(done.stderr)

    threads = [threading.Thread(target=insert, args=(n,)) for n in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors[:2]
    rows = _rows(f"seq >= {mark}")
    assert [r["seq"] for r in rows] == list(range(mark, mark + 21))
    _check_links(rows)


def test_rollback_leaves_no_gap():
    mark = _mark()
    admin = _user_id(ADMIN)
    _psql(f"BEGIN; INSERT INTO audit_events (actor_user_id, actor_role, action, target_type, target_id) "
          f"VALUES ({admin}, 'admin', 'test.chain', 'test', {admin}); ROLLBACK;")
    assert _mark() == mark
    _insert_admin_event()
    rows = _rows(f"seq >= {mark}")
    assert [r["seq"] for r in rows] == [mark, mark + 1]
    _check_links(rows)


def _chain_state() -> dict:
    return {
        "head": _one("SELECT chain_id || '|' || genesis_at || '|' || genesis_rows FROM audit_chain_head"),
        "head_oid": _one("SELECT 'public.audit_chain_head'::regclass::oid"),
        "triggers": _psql("SELECT tgname || ':' || oid || ':' || tgenabled::text FROM pg_trigger "
                          "WHERE tgrelid IN ('public.audit_events'::regclass, 'public.audit_chain_head'::regclass) "
                          "AND NOT tgisinternal ORDER BY tgname"),
        "checks": _psql("SELECT conname || ':' || oid FROM pg_constraint "
                        "WHERE conrelid = 'public.audit_events'::regclass ORDER BY conname"),
        "first": _one("SELECT encode(row_hash, 'hex') FROM audit_events WHERE seq = 1"),
    }


def _migrate() -> subprocess.CompletedProcess:
    return subprocess.run(["docker", "compose", "run", "--rm", "--no-deps", "-T", "migrate"],
                          cwd=ROOT, capture_output=True, text=True, timeout=300)


def test_repeat_migrate_keeps_the_chain_triggers_and_checks():
    before = _chain_state()
    names = [c.split(":")[0] for c in before["checks"]]
    for name in ("audit_events_actor_role_check", "audit_events_actor_check", "audit_events_source_check"):
        assert name in names
    assert any(t.startswith("zz_audit_chain:") and t.endswith(":A") for t in before["triggers"])
    done = _migrate()
    assert done.returncode == 0, done.stderr[-2000:]
    assert _chain_state() == before
    _check_links(_rows(f"seq >= {max(1, _mark() - 50)}"))


@pytest.mark.skipif(PROJECT != "e6", reason="only on the disposable stand -p e6 (deletes the chain head)")
def test_missing_head_stops_migrate_instead_of_a_new_chain():
    """A7: with seq rows but no head, migrate refuses to rebuild (fail closed)."""
    _psql("ALTER TABLE audit_chain_head DISABLE TRIGGER ALL; DELETE FROM audit_chain_head; "
          "ALTER TABLE audit_chain_head ENABLE ALWAYS TRIGGER ALL")
    done = _migrate()
    assert done.returncode != 0 and "refusing to rebuild" in done.stdout + done.stderr


@pytest.mark.skipif(PROJECT != "e6", reason="only on a fresh disposable volume -p e6")
def test_fresh_volume_has_an_empty_genesis_and_triggers_in_mode_a():
    assert _head()["genesis_rows"] == 0
    modes = _psql("SELECT tgname || ':' || tgenabled::text FROM pg_trigger WHERE tgrelid IN "
                  "('public.audit_events'::regclass, 'public.audit_chain_head'::regclass) AND NOT tgisinternal")
    assert modes and all(m.endswith(":A") for m in modes)
