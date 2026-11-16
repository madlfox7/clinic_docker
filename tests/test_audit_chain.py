"""Audit journal hash chain (plan 17 §6-§9): schema, trigger, genesis,
append-only rules and the independent Python canon (audit/canon.py)."""
import datetime as dt
import json
import os
import re
import time
import uuid
import subprocess
import sys
import threading
from contextlib import contextmanager
from pathlib import Path

import httpx
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
MAILPIT = os.environ.get("CLINIC_MAILPIT", "http://127.0.0.1:8025")


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


def test_seq_has_no_gaps_from_one():
    """Red on the long-lived Fixer volume between commits 7 and 9, when the tests
    still deleted journal rows (plan 17 П9); green on a fresh volume."""
    assert _one("SELECT count(*) = max(seq) AND min(seq) = 1 FROM audit_events") == "t"


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
    mark = _mark()
    before = _chain_state()
    names = [c.split(":")[0] for c in before["checks"]]
    for name in ("audit_events_actor_role_check", "audit_events_actor_check", "audit_events_source_check"):
        assert name in names
    assert any(t.startswith("zz_audit_chain:") and t.endswith(":A") for t in before["triggers"])
    done = _migrate()
    assert done.returncode == 0, done.stderr[-2000:]
    assert _chain_state() == before
    assert _foreign_keys() == "0"
    _insert_admin_event()
    _check_links(_rows(f"seq >= {mark}"))


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


# --- §7.2-7.3: no actor foreign key, discarded invites keep their history ---

def _foreign_keys() -> str:
    return _one("SELECT count(*) FROM pg_constraint "
                "WHERE conrelid = 'public.audit_events'::regclass AND contype = 'f'")


@contextmanager
def _admin_client():
    with CsrfClient(base_url=BASE, follow_redirects=True, timeout=30.0) as c:
        page = c.post("/login", data={"email": ADMIN, "password": PASSWORD})
        assert page.status_code == 200 and page.url.path == "/me"
        yield c


def _events(where: str) -> list[str]:
    return _psql("SELECT concat_ws('|', actor_user_id, actor_role, action, target_type, target_id) "
                 f"FROM audit_events WHERE {where} ORDER BY seq")


def test_audit_events_have_no_foreign_key():
    assert _foreign_keys() == "0"


def _setup_token(address: str) -> str:
    found = httpx.get(f"{MAILPIT}/api/v1/search", timeout=5,
                      params={"query": f'to:"{address}" subject:"Reset your clinic password"'})
    found.raise_for_status()
    messages = found.json().get("messages") or []
    assert messages, "setup email was not delivered"
    message_id = messages[0].get("ID") or messages[0].get("Id")
    body = httpx.get(f"{MAILPIT}/api/v1/message/{message_id}", timeout=5).json().get("Text") or ""
    match = re.search(r"reset-password\?token=([0-9a-f]{64})", body)
    assert match, "setup link missing"
    return match.group(1)


def _discard(token: str) -> str:
    """What _discard_invite (routes_admin.py) runs after a failed delivery.

    Called directly: through the app the call is never reached today, see the
    note in the plan 17B report (smtp_ready() refuses the invite up front, and
    deliver_password_reset() revokes the token before _discard_invite runs)."""
    return _one(f"SELECT discard_undelivered_invite('{token}')")


def test_discarded_registrar_invite_keeps_the_invite_and_adds_an_event():
    email = f"discard-reg-{uuid.uuid4().hex}@example.com"
    admin = _user_id(ADMIN)
    mark = _mark()
    with _admin_client() as c:
        created = c.post("/admin/users", data={"email": email, "role": "registrar"})
        assert "Staff account created." in created.text
    invited = _user_id(email)
    assert _discard(_setup_token(email)) == "t"
    assert _psql(f"SELECT count(*) FROM users WHERE email = '{email}'") == ["0"]
    assert _events(f"seq > {mark} AND action = 'user.invite'") == [
        f"{admin}|admin|user.invite|registrar|{invited}"
    ]
    assert _events(f"seq > {mark} AND action = 'user.invite_discarded'") == [
        f"{admin}|admin|user.invite_discarded|user|{invited}"
    ]
    _check_links(_rows(f"seq >= {mark}"))


def test_discarded_doctor_invite_is_found_by_doctor_id_and_written_with_user_id():
    email = f"discard-doc-{uuid.uuid4().hex}@example.com"
    admin = _user_id(ADMIN)
    mark = _mark()
    with _admin_client() as c:
        created = c.post("/admin/doctors", data={
            "email": email, "full_name": "Discard Check", "specialty": "Therapy", "experience_years": "3",
        })
        assert "created=1" in str(created.url), created.url
    invited = _user_id(email)
    doctor_id = int(_one(f"SELECT id FROM doctors WHERE user_id = {invited}"))
    assert _discard(_setup_token(email)) == "t"
    assert _psql(f"SELECT count(*) FROM users WHERE id = {invited}") == ["0"]
    assert _psql(f"SELECT count(*) FROM doctors WHERE id = {doctor_id}") == ["0"]
    assert _events(f"seq > {mark} AND action = 'doctor.invite'") == [
        f"{admin}|admin|doctor.invite|doctor|{doctor_id}"
    ]
    # P4: the invite names the doctors.id, the discard event the users.id.
    assert _events(f"seq > {mark} AND action = 'user.invite_discarded'") == [
        f"{admin}|admin|user.invite_discarded|user|{invited}"
    ]


def test_discard_after_a_login_attempt_keeps_the_login_event_without_fk_errors():
    email = f"discard-login-{uuid.uuid4().hex}@example.com"
    mark = _mark()
    with _admin_client() as admin:
        created = admin.post("/admin/users", data={"email": email, "role": "registrar"})
        assert "Staff account created." in created.text
    invited = _user_id(email)
    token = _setup_token(email)
    with CsrfClient(base_url=BASE, follow_redirects=True, timeout=10.0) as c:
        assert c.post("/login", data={"email": email, "password": "Wrong-Password-2026!"}).status_code == 401
    assert _discard(token) == "t"
    assert _psql(f"SELECT count(*) FROM users WHERE id = {invited}") == ["0"]
    assert _events(f"seq > {mark} AND action = 'auth.login.failure' AND actor_user_id = {invited}")
    assert _events(f"seq > {mark} AND action = 'user.invite_discarded' AND target_id = {invited}")
    with _admin_client() as admin:
        page = admin.get("/admin/audit", params={"action": "auth.login.failure"})
        assert page.status_code == 200
        listed = admin.get("/admin/audit", params={"action": "user.invite_discarded"})
        assert listed.status_code == 200 and "user.invite_discarded" in listed.text


def test_discard_without_an_invite_event_fails_closed_and_warns_without_data():
    email = f"discard-none-{uuid.uuid4().hex}@example.com"
    token = uuid.uuid4().hex + uuid.uuid4().hex
    done = _psql_try(
        "BEGIN; "
        f"INSERT INTO users (email, password_hash, role) VALUES ('{email}', 'x', 'registrar'); "
        "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) "
        f"SELECT id, public.digest('{token}', 'sha256'), now() + interval '1 hour' FROM users WHERE email = '{email}'; "
        f"SELECT 'result=' || discard_undelivered_invite('{token}'); "
        f"SELECT 'left=' || count(*) FROM users WHERE email = '{email}'; "
        "ROLLBACK;"
    )
    assert done.returncode == 0, done.stderr
    assert "result=false" in done.stdout and "left=1" in done.stdout
    assert "without an invite event" in done.stderr
    assert email not in done.stderr and token not in done.stderr


# --- §9.2: the tests themselves never edit the journal -----------------------

def test_no_test_edits_the_audit_journal():
    """grep -niE '(DELETE FROM|UPDATE|TRUNCATE)[^;]*audit_events' tests/ is empty,
    except for statements that expect the refusal (marked on the same line)."""
    pattern = re.compile(r"(DELETE FROM|UPDATE|TRUNCATE)[^;]*audit_events", re.I)
    found = []
    for path in sorted((ROOT / "tests").glob("*.py")):
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if pattern.search(line) and "# expects refusal" not in line and "pattern = re.compile" not in line:
                found.append(f"{path.name}:{number}: {line.strip()}")
    assert found == []


def test_a_login_gets_the_next_seq_and_a_valid_row_hash():
    """O-26: auth.login.success after the mark has seq = head.last_seq."""
    mark = _mark()
    with CsrfClient(base_url=BASE, follow_redirects=True, timeout=10.0) as c:
        page = c.post("/login", data={"email": PAT, "password": PASSWORD})
        assert page.status_code == 200 and page.url.path == "/me"
    rows = _rows(f"seq >= {mark}")
    logins = [r for r in rows if r["seq"] > mark and r["action"] == "auth.login.success"]
    assert logins and logins[-1]["seq"] == _head()["last_seq"]
    _check_links(rows)

