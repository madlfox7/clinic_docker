"""Audit journal hash chain (plan 17 §6-§9): schema, trigger, genesis,
append-only rules and the independent Python canon (audit/canon.py)."""
import datetime as dt
import hashlib
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


def _ensure_rows() -> None:
    # a fresh volume starts with an empty journal; these checks need one row
    if _one("SELECT count(*) FROM audit_events") == "0":
        _insert_admin_event()


def test_chain_schema_columns_head_and_constraints():
    _ensure_rows()
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
    _ensure_rows()
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
    _ensure_rows()
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
    _ensure_rows()
    _psql("BEGIN; ALTER TABLE audit_chain_head DISABLE TRIGGER USER; DELETE FROM audit_chain_head; "
          + "".join(f"ALTER TABLE audit_chain_head ENABLE ALWAYS TRIGGER {name}; " for name in
                    ("audit_chain_head_guard", "audit_chain_head_no_delete", "audit_chain_head_no_truncate"))
          + "COMMIT;")
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


# --- §7.1: append-only journal and head ---------------------------------------

JOURNAL_TRIGGERS = {
    "audit_events": (
        "zz_audit_chain",
        "audit_events_no_update_delete",
        "audit_events_no_truncate",
    ),
    "audit_chain_head": ("audit_chain_head_guard", "audit_chain_head_no_delete", "audit_chain_head_no_truncate"),
}
APP_ROLES = ("clinic_api", "app_admin", "app_patient", "app_registrar")


def _trigger_modes() -> dict:
    return dict(line.split("|") for line in _psql(
        "SELECT tgname, tgenabled::text FROM pg_trigger WHERE tgrelid IN "
        "('public.audit_events'::regclass, 'public.audit_chain_head'::regclass) AND NOT tgisinternal"))


def _row_one() -> str:
    return _one(f"SELECT {_ROW_JSON}::text FROM audit_events WHERE seq = 1")


@pytest.mark.parametrize("role", APP_ROLES)
def test_application_roles_cannot_change_or_insert_journal_rows(role):
    user = _user_id(ADMIN)
    for sql in ("UPDATE audit_events SET action = 'x' WHERE seq = 1",  # expects refusal
                "DELETE FROM audit_events WHERE seq = 1",  # expects refusal
                "TRUNCATE audit_events",  # expects refusal
                "INSERT INTO audit_events (actor_user_id, actor_role, action, target_type) "
                "VALUES (1, 'admin', 'x', 'y')",
                "UPDATE audit_chain_head SET last_seq = 0",
                "DELETE FROM audit_chain_head"):
        done = _psql_try(f"BEGIN; SET LOCAL ROLE {role}; "
                         f"SELECT set_config('app.user_id', '{user}', true); {sql}; ROLLBACK;")
        assert done.returncode != 0 and "permission denied" in done.stderr, (role, sql, done.stderr)


def test_superuser_cannot_update_delete_or_truncate_the_journal():
    before = _row_one()
    for sql in ("UPDATE audit_events SET action = 'x' WHERE seq = 1",  # expects refusal
                "DELETE FROM audit_events WHERE seq = 1",  # expects refusal
                "TRUNCATE audit_events"):  # expects refusal
        done = _psql_try(sql)
        assert done.returncode != 0 and "audit_events is append-only" in done.stderr, (sql, done.stderr)
    assert _row_one() == before


def test_head_moves_only_from_the_chain_trigger():
    head = _head()
    for sql in ("UPDATE audit_chain_head SET last_seq = 0",
                f"UPDATE audit_chain_head SET last_seq = {head['last_seq'] + 1}",
                "DELETE FROM audit_chain_head", "TRUNCATE audit_chain_head"):
        done = _psql_try(sql)
        assert done.returncode != 0, sql
        assert "only by the chain trigger" in done.stderr or "audit_chain_head is append-only" in done.stderr, done.stderr
    assert _head() == head
    mark = _mark()
    _insert_admin_event()
    assert _head()["last_seq"] == mark + 1
    _check_links(_rows(f"seq >= {mark}"))


@pytest.mark.parametrize("change", ["last_seq = last_seq + 2", "chain_id = gen_random_uuid()",
                                    "genesis_rows = genesis_rows + 1", "genesis_at = now() - interval '1 day'"])
def test_head_guard_checks_the_step_even_at_depth_two(change):
    """P2: a wrapper trigger (depth 2) that moves the head wrongly is refused (rolled back)."""
    done = _psql_try(
        "BEGIN; CREATE TABLE pg_temp.p2 (x int); "
        "CREATE FUNCTION pg_temp.p2_wrap() RETURNS trigger LANGUAGE plpgsql AS "
        f"$f$ BEGIN UPDATE public.audit_chain_head SET {change}; RETURN NEW; END $f$; "
        "CREATE TRIGGER p2_wrap BEFORE INSERT ON pg_temp.p2 FOR EACH ROW EXECUTE FUNCTION pg_temp.p2_wrap(); "
        "INSERT INTO pg_temp.p2 VALUES (1); ROLLBACK;"
    )
    assert done.returncode != 0 and "only by the chain trigger" in done.stderr, done.stderr


def test_all_six_journal_triggers_fire_always():
    modes = _trigger_modes()
    for names in JOURNAL_TRIGGERS.values():
        for name in names:
            assert modes.get(name) == "A", (name, modes)


def test_replica_role_does_not_switch_the_triggers_off():
    done = _psql_try("BEGIN; SET LOCAL session_replication_role = replica; "
                     "UPDATE audit_events SET action = 'x' WHERE seq = 1; ROLLBACK;")  # expects refusal
    assert done.returncode != 0 and "append-only" in done.stderr, done.stderr


def test_migrate_block_puts_mode_a_back_after_disable_and_enable():
    text = (ROOT / "db" / "init.sql").read_text()
    start = text.index("-- BEGIN audit_trigger_mode")
    block = text[start:text.index("-- END audit_trigger_mode", start)]
    probe = ("SELECT 'mode=' || tgenabled::text FROM pg_trigger "
             "WHERE tgrelid = 'public.audit_events'::regclass AND tgname = 'zz_audit_chain'")
    done = _psql_try(
        "BEGIN; ALTER TABLE audit_events DISABLE TRIGGER zz_audit_chain; "
        "ALTER TABLE audit_events ENABLE TRIGGER zz_audit_chain; "
        "DO $chk$ BEGIN IF (SELECT tgenabled FROM pg_trigger WHERE tgname = 'zz_audit_chain') <> 'O' "
        "THEN RAISE EXCEPTION 'expected mode O'; END IF; END $chk$; "
        f"{block}\n"
        "DO $chk$ BEGIN IF (SELECT tgenabled FROM pg_trigger WHERE tgname = 'zz_audit_chain') <> 'A' "
        "THEN RAISE EXCEPTION 'expected mode A'; END IF; END $chk$; ROLLBACK;"
    )
    assert done.returncode == 0, done.stderr
    assert _one(probe) == "mode=A"


# --- §8: audit_anchor, unit tests on a temporary directory and a fake journal ---

import multiprocessing  # noqa: E402

from tests.audit_fake import KEY, FakeSource  # noqa: E402
import anchor  # noqa: E402  (audit/anchor.py)
import chainlib as cl  # noqa: E402
import verify_audit  # noqa: E402


def _dir(tmp_path):
    d = tmp_path / "anchors"
    d.mkdir(mode=0o700)
    return d


def _registry(d):
    return [e.kind + ":" + (e.mode or e.switch_kind or "") for e in cl.parse_registry(d / cl.REGISTRY, KEY)[0]]


def _anchors(d, chain_id):
    return cl.read_anchors(d / f"{chain_id}.log", KEY, chain_id)[0]


def _snapshot(d):
    return {p.name: p.read_bytes() for p in d.iterdir()}


def test_unit_first_start_opens_and_anchors(tmp_path):
    d, src = _dir(tmp_path), FakeSource(rows=3, genesis_rows=3)
    result = anchor.cycle(d, KEY, src)
    assert result.ok and _registry(d) == ["open:"]
    assert [a.seq for a in _anchors(d, src.chain_id)] == [3]
    assert oct((d / f"{src.chain_id}.log").stat().st_mode & 0o777) == "0o644"
    src.add(2)
    assert anchor.cycle(d, KEY, src).ok
    assert [a.seq for a in _anchors(d, src.chain_id)] == [3, 5]
    assert anchor.cycle(d, KEY, src).ok   # no new rows: still a line, same seq
    assert [a.seq for a in _anchors(d, src.chain_id)] == [3, 5, 5]


def test_unit_registry_missing_with_anchor_files_is_an_error(tmp_path):
    d, src = _dir(tmp_path), FakeSource(rows=2)
    assert anchor.cycle(d, KEY, src).ok
    (d / cl.REGISTRY).unlink()
    before = _snapshot(d)
    result = anchor.cycle(d, KEY, src)
    assert not result.ok and result.error == "registry_missing"
    assert _snapshot(d) == before


def test_unit_new_chain_without_retire_is_a_switch_and_stays_red(tmp_path):
    d, old = _dir(tmp_path), FakeSource(rows=2)
    assert anchor.cycle(d, KEY, old).ok
    new = FakeSource(rows=1)
    result = anchor.cycle(d, KEY, new)
    assert not result.ok and result.error == "chain_replaced"
    assert _registry(d) == ["open:", "switch:new"]
    again = anchor.cycle(d, KEY, new)        # a restart does not heal a switch
    assert not again.ok and _registry(d) == ["open:", "switch:new"]
    assert [a.seq for a in _anchors(d, new.chain_id)] == [1, 1]   # anchors continue


def test_unit_after_retire_a_new_chain_is_opened(tmp_path):
    d, old = _dir(tmp_path), FakeSource(rows=2)
    assert anchor.cycle(d, KEY, old).ok
    assert anchor.retire(KEY, False, False, d, lambda: (old, lambda: None)) == 0
    new = FakeSource(rows=0)
    assert anchor.cycle(d, KEY, new).ok
    assert _registry(d) == ["open:", "retire:normal", "open:"]


def test_unit_known_chain_id_is_reused_never_opened_again(tmp_path):
    d, first = _dir(tmp_path), FakeSource(rows=2)
    assert anchor.cycle(d, KEY, first).ok
    anchor.retire(KEY, False, False, d, lambda: (first, lambda: None))
    second = FakeSource(rows=0)
    assert anchor.cycle(d, KEY, second).ok
    result = anchor.cycle(d, KEY, first)    # the old chain comes back (old dump)
    assert not result.ok and _registry(d) == ["open:", "retire:normal", "open:", "switch:reused"]
    assert [e.kind for e in cl.parse_registry(d / cl.REGISTRY, KEY)[0]].count("open") == 2


def _retired(tmp_path, rows=3):
    d, src = _dir(tmp_path), FakeSource(rows=rows)
    assert anchor.cycle(d, KEY, src).ok
    assert anchor.retire(KEY, False, False, d, lambda: (src, lambda: None)) == 0
    return d, src


def test_unit_retired_chain_with_the_same_head_is_green_without_anchor(tmp_path):
    d, src = _retired(tmp_path)
    before = _snapshot(d)
    result = anchor.cycle(d, KEY, src)
    assert result.ok and result.state == "retired"
    assert _snapshot(d) == before


@pytest.mark.parametrize("change", ["more", "other_hash", "less", "row_below"])
def test_unit_retired_chain_that_changed_is_retired_reused(tmp_path, change):
    d, src = _retired(tmp_path)
    if change == "more":
        src.add(1)
    elif change == "other_hash":
        src.head_override = dict(src.head(), last_hash=bytes(32))
    elif change == "less":
        src.rows.pop()
    else:
        # same last_seq and hash, but a row below no longer matches its anchor
        anchors_file = d / f"{src.chain_id}.log"
        text = anchors_file.read_text().splitlines()
        assert text
        src.rows[0]["row_hash"] = bytes(32)
    result = anchor.cycle(d, KEY, src)
    assert not result.ok
    assert _registry(d)[-1] == "switch:retired_reused"


def test_unit_offline_retired_chain_back_is_retired_reused(tmp_path):
    d, src = _dir(tmp_path), FakeSource(rows=2)
    assert anchor.cycle(d, KEY, src).ok
    assert anchor.retire(KEY, False, True, d) == 0
    assert _registry(d) == ["open:", "retire:offline"]
    assert not anchor.cycle(d, KEY, src).ok
    assert _registry(d)[-1] == "switch:retired_reused"


def _body_mac(prev, body):
    return f"{body} {cl.line_mac(KEY, prev, body).hex()}"


@pytest.mark.parametrize("line, kind", [
    ("v1 open {id} 2026-11-16T10:00:00.000000Z 0 2026-11-16T10:00:00.000000Z extra", "registry_format"),
    ("v1 open {id} 2026-11-16T10:00:00.000000Z 2026-11-16T10:00:00.000000Z", "registry_format"),
    ("v1 close {id} 2026-11-16T10:00:00.000000Z 0 2026-11-16T10:00:00.000000Z", "registry_format"),
    ("v1 retire {id} 1 {h} sloppy - 2026-11-16T10:00:00.000000Z", "registry_format"),
    ("v1 switch {id} {id} borrowed 2026-11-16T10:00:00.000000Z", "registry_format"),
    ("v1 open - 2026-11-16T10:00:00.000000Z 0 2026-11-16T10:00:00.000000Z", "registry_format"),
    ("v1 retire {id} - - normal - 2026-11-16T10:00:00.000000Z", "registry_format"),
    ("bad-mac", "registry_mac"),
])
def test_unit_strict_registry_parser(tmp_path, line, kind):
    d, src = _dir(tmp_path), FakeSource(rows=1)
    assert anchor.cycle(d, KEY, src).ok
    reg = d / cl.REGISTRY
    entries, prev = cl.parse_registry(reg, KEY)
    if line == "bad-mac":
        body = f"v1 retire {src.chain_id} 1 {'a' * 64} normal - 2026-11-16T10:00:00.000000Z"
        text = f"{body} {'0' * 64}"
    else:
        text = _body_mac(prev, line.format(id=src.chain_id, h="a" * 64))
    with reg.open("a") as f:
        f.write(text + "\n")
    before = _snapshot(d)
    result = anchor.cycle(d, KEY, src)
    assert not result.ok and result.error == kind
    assert _snapshot(d) == before
    out = []
    assert verify_audit.verify(src, d, KEY, False, None, 60, out.append) == 1
    assert f"type={kind}" in out[-1]


def test_unit_new_chain_over_a_full_journal_with_a_registry_is_an_error(tmp_path):
    d, old = _retired(tmp_path)
    full = FakeSource(rows=5, genesis_rows=5)
    result = anchor.cycle(d, KEY, full)
    assert not result.ok and result.error == "genesis_rows"
    assert _registry(d) == ["open:", "retire:normal"]


def test_unit_retire_of_a_broken_chain_refuses_unless_forced(tmp_path, capsys):
    d, src = _dir(tmp_path), FakeSource(rows=4)
    assert anchor.cycle(d, KEY, src).ok
    src.rows[1]["action"] = "forged"
    before = _snapshot(d)
    assert anchor.retire(KEY, False, False, d, lambda: (src, lambda: None)) != 0
    assert "BROKEN seq=2" in capsys.readouterr().out and _snapshot(d) == before
    assert anchor.retire(KEY, True, False, d, lambda: (src, lambda: None)) == 0
    out = capsys.readouterr().out
    assert out.index("BROKEN seq=2") < out.index("forced row_hash@2")
    last = cl.parse_registry(d / cl.REGISTRY, KEY)[0][-1]
    assert (last.kind, last.mode, last.brk) == ("retire", "forced", "row_hash@2")
    assert anchor.retire(KEY, True, False, d, lambda: (src, lambda: None)) == 0   # no-op
    assert _registry(d) == ["open:", "retire:forced"]
    # a forced retire does not turn the next chain red
    assert anchor.cycle(d, KEY, FakeSource(rows=0)).ok


def test_unit_retire_offline_and_again_is_a_no_op(tmp_path):
    d, src = _dir(tmp_path), FakeSource(rows=1)
    assert anchor.cycle(d, KEY, src).ok
    assert anchor.retire(KEY, False, True, d) == 0
    line = (d / cl.REGISTRY).read_text().splitlines()[-1].split(" ")
    assert line[1:7] == ["retire", src.chain_id, "-", "-", "offline", "-"]
    assert anchor.retire(KEY, False, True, d) == 0
    assert _registry(d) == ["open:", "retire:offline"]


def test_unit_trigger_not_in_mode_a_stops_the_cycle(tmp_path):
    d, src = _dir(tmp_path), FakeSource(rows=2)
    assert anchor.cycle(d, KEY, src).ok
    src.modes[("audit_events", "zz_audit_chain")] = "O"
    before = _snapshot(d)
    result = anchor.cycle(d, KEY, src)
    assert not result.ok and result.error == "trigger_mode"
    assert _snapshot(d) == before


def test_unit_broken_chain_is_never_anchored(tmp_path):
    d, src = _dir(tmp_path), FakeSource(rows=3)
    assert anchor.cycle(d, KEY, src).ok
    src.add(2)
    src.rows[4]["target_id"] = 99
    before = _snapshot(d)
    result = anchor.cycle(d, KEY, src)
    assert not result.ok and result.error == "row_hash"
    assert _snapshot(d) == before


def test_unit_no_retired_directory_in_the_code():
    for name in ("anchor.py", "chainlib.py", "verify_audit.py"):
        assert "retired/" not in (ROOT / "audit" / name).read_text()


def _parallel_once(directory, chain_id, rows):
    src = FakeSource(chain_id=chain_id, rows=rows)
    return anchor.cycle(Path(directory), KEY, src).ok


def test_unit_twenty_parallel_once_keep_both_mac_chains(tmp_path):
    """Б-B1: twenty --once next to each other (and a cycle already running) never
    fork the MAC chain of the anchor file or of the registry."""
    d, src = _dir(tmp_path), FakeSource(rows=5)
    ctx = multiprocessing.get_context("fork")
    with ctx.Pool(20) as pool:
        results = pool.starmap(_parallel_once, [(str(d), src.chain_id, 5)] * 21)
    assert all(results)
    assert _registry(d) == ["open:"]
    assert len(_anchors(d, src.chain_id)) == 21


def test_unit_verify_audit_reports(tmp_path):
    d, src = _dir(tmp_path), FakeSource(rows=3)
    assert anchor.cycle(d, KEY, src).ok
    out = []
    assert verify_audit.verify(src, d, KEY, False, None, 60, out.append) == 0
    assert out[-1].startswith(f"OK chain={src.chain_id} rows=3 anchors=1 ")
    src.modes[("audit_chain_head", "audit_chain_head_guard")] = "O"
    out = []
    assert verify_audit.verify(src, d, KEY, False, None, 60, out.append) == 1
    assert out[-1] == "BROKEN type=trigger_mode name=audit_chain_head_guard mode=O"


@pytest.mark.parametrize("kind", ["new", "reused", "retired_reused"])
def test_unit_verify_audit_sees_every_switch(tmp_path, kind):
    d, src = _dir(tmp_path), FakeSource(rows=2)
    assert anchor.cycle(d, KEY, src).ok
    entries, prev = cl.parse_registry(d / cl.REGISTRY, KEY)
    cl.append_line(d / cl.REGISTRY, KEY, prev, f"v1 switch {src.chain_id} {src.chain_id} {kind} {cl.utc()}")
    out = []
    assert verify_audit.verify(src, d, KEY, False, None, 60, out.append) == 1
    assert f"type=chain_replaced kind={kind}" in out[-1]


def test_unit_verify_audit_warns_on_forced_and_offline_retires(tmp_path):
    d = _dir(tmp_path)
    first = FakeSource(rows=2)
    assert anchor.cycle(d, KEY, first).ok
    first.rows[0]["action"] = "forged"
    assert anchor.retire(KEY, True, False, d, lambda: (first, lambda: None)) == 0
    second = FakeSource(rows=0)
    assert anchor.cycle(d, KEY, second).ok
    assert anchor.retire(KEY, False, True, d) == 0
    third = FakeSource(rows=1)
    assert anchor.cycle(d, KEY, third).ok
    out = []
    assert verify_audit.verify(third, d, KEY, False, None, 60, out.append) == 0
    assert f"WARN retire forced chain={first.chain_id} break=row_hash@1" in out
    assert f"WARN retire offline chain={second.chain_id}" in out
    assert out[-1].endswith("retired_forced=1 retired_offline=1")
    out = []
    assert verify_audit.verify(third, d, KEY, True, None, 60, out.append) == 3


def test_unit_verify_audit_compares_an_outside_copy(tmp_path):
    d, src = _dir(tmp_path), FakeSource(rows=2)
    assert anchor.cycle(d, KEY, src).ok
    copy = tmp_path / "copy"
    copy.mkdir()
    for p in d.iterdir():
        if p.name != cl.LOCK:
            (copy / p.name).write_bytes(p.read_bytes())
    assert anchor.cycle(d, KEY, src.add(1)).ok      # the copy lags: still a prefix
    assert verify_audit.verify(src, d, KEY, False, copy, 60, [].append) == 0
    (copy / f"{src.chain_id}.log").write_text("v1 tampered\n")
    out = []
    assert verify_audit.verify(src, d, KEY, False, copy, 60, out.append) == 1
    assert "type=anchor_copy_mismatch" in out[-1]


# --- §8: the audit_anchor service on the stand -----------------------------------

import shutil  # noqa: E402
import stat  # noqa: E402

ANCHOR_DIR = ROOT / os.environ.get("CLINIC_AUDIT_ANCHOR_DIR", "audit_anchors")
SERVICES_WITHOUT_KEY = ("db", "migrate", "api", "seed", "proxy", "mailpit")


def _compose_config() -> dict:
    done = subprocess.run(["docker", "compose", "config", "--format", "json"], cwd=ROOT,
                          capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def _host_key() -> bytes:
    # read only here, never printed
    return cl.load_key(ROOT / "secrets" / "audit_anchor_key")


def _head_chain() -> str:
    return _head()["chain_id"]


def test_compose_mounts_the_key_only_on_audit_anchor_and_hardens_it():
    services = _compose_config()["services"]
    for name, service in services.items():
        mounted = {item["source"] for item in service.get("secrets") or []}
        if name == "audit_anchor":
            assert mounted == {"audit_db_password", "audit_anchor_key"}
        else:
            assert "audit_anchor_key" not in mounted, name
            assert ("audit_db_password" in mounted) == (name == "migrate"), name
    anchor_service = services["audit_anchor"]
    assert set(anchor_service["networks"]) == {"backend"}
    assert anchor_service.get("read_only") is True
    assert anchor_service.get("cap_drop") == ["ALL"]
    assert "no-new-privileges:true" in anchor_service.get("security_opt", [])
    assert not anchor_service.get("ports")


@pytest.mark.parametrize("sql", [
    "INSERT INTO audit_events (actor_user_id, actor_role, action, target_type) VALUES (1, 'admin', 'x', 'y')",
    "UPDATE audit_events SET action = 'x' WHERE seq = 1",  # expects refusal
    "DELETE FROM audit_events WHERE seq = 1",  # expects refusal
    "UPDATE audit_chain_head SET last_seq = 0",
    "SELECT count(*) FROM users",
    "SELECT count(*) FROM visit_notes",
    "SELECT count(*) FROM prescriptions",
    "SELECT public.record_audit_event('service.create', 'service', 1)",
])
def test_auditor_role_reads_the_journal_only(sql):
    ok = _psql_try("BEGIN; SET LOCAL ROLE clinic_auditor; "
                   "SELECT count(*) FROM audit_events; SELECT count(*) FROM audit_chain_head; ROLLBACK;")
    assert ok.returncode == 0, ok.stderr
    denied = _psql_try(f"BEGIN; SET LOCAL ROLE clinic_auditor; {sql}; ROLLBACK;")
    assert denied.returncode != 0 and "permission denied" in denied.stderr, (sql, denied.stderr)


def test_auditor_role_attributes():
    assert _one("SELECT rolcanlogin::text || rolsuper::text || rolbypassrls::text || rolinherit::text "
                "|| rolcreatedb::text || rolcreaterole::text FROM pg_roles WHERE rolname = 'clinic_auditor'") \
        == "truefalsefalsefalsefalsefalse"


def test_no_other_container_gets_the_anchor_key():
    for service in ("api", "db", "proxy"):
        listed = subprocess.run(["docker", "compose", "exec", "-T", service, "ls", "/run/secrets"],
                                cwd=ROOT, capture_output=True, text=True, timeout=60)
        assert listed.returncode == 0, (service, listed.stderr)
        assert "audit_anchor_key" not in listed.stdout, service
    # Securo fix 2: migrate's entrypoint is "sh -ec", so ls goes in as the entrypoint
    migrate = subprocess.run(["docker", "compose", "run", "--rm", "--no-deps", "-T", "--entrypoint", "ls",
                              "migrate", "/run/secrets"], cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert migrate.returncode == 0, migrate.stderr
    names = migrate.stdout.split()
    assert "postgres_password" in names and "audit_db_password" in names
    assert "audit_anchor_key" not in names
    mine = subprocess.run(["docker", "compose", "exec", "-T", "audit_anchor", "ls", "/run/secrets"],
                          cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert sorted(mine.stdout.split()) == ["audit_anchor_key", "audit_db_password"]


def test_key_file_is_never_world_readable():
    mode = (ROOT / "secrets" / "audit_anchor_key").stat().st_mode
    assert not mode & (stat.S_IROTH | stat.S_IWOTH | stat.S_IRGRP | stat.S_IWGRP) or shutil.which("getfacl")
    assert not mode & (stat.S_IROTH | stat.S_IWOTH)


def _wait_for_anchor(chain_id: str, at_least_seq: int, timeout: float) -> cl.Anchor:
    deadline = time.time() + timeout
    while True:
        path = ANCHOR_DIR / f"{chain_id}.log"
        if path.exists():
            anchors, _ = cl.read_anchors(path, _host_key(), chain_id)
            if anchors and anchors[-1].seq >= at_least_seq:
                return anchors[-1]
        if time.time() > deadline:
            raise AssertionError(f"no anchor for seq >= {at_least_seq} within {timeout} s")
        time.sleep(2)


def test_service_anchors_the_head_within_two_intervals_and_the_macs_hold():
    every = int(os.environ.get("CLINIC_AUDIT_ANCHOR_INTERVAL", "60"))
    chain = _head_chain()
    last = _wait_for_anchor(chain, 1, 2 * every + 15)
    assert time.time() - cl.parse_utc(last.at).timestamp() <= 2 * every + 15
    entries, _ = cl.parse_registry(ANCHOR_DIR / cl.REGISTRY, _host_key())
    assert any(e.kind == "open" and e.chain_id == chain for e in entries)
    assert not any(e.kind == "switch" for e in entries)


def test_once_anchors_the_new_max_seq():
    _insert_admin_event()
    seq = _head()["last_seq"]
    done = subprocess.run(["docker", "compose", "exec", "-T", "audit_anchor", "python", "anchor.py", "--once"],
                          cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stdout + done.stderr
    assert _wait_for_anchor(_head_chain(), seq, 5).seq == seq
    assert "mac" not in done.stdout.lower() and "key" not in done.stdout.lower()


def test_audit_anchor_is_healthy():
    state = subprocess.run(["docker", "compose", "ps", "--format", "{{.Health}}", "audit_anchor"],
                           cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert state.stdout.strip() == "healthy", state.stdout


def test_make_audit_verify_is_ok_on_an_intact_journal():
    compose = "docker compose" + (f" -p {PROJECT}" if PROJECT else "")
    done = subprocess.run(["make", "-s", "audit-verify", f"COMPOSE={compose}"], cwd=ROOT,
                          capture_output=True, text=True, timeout=300)
    assert done.returncode == 0, done.stdout + done.stderr
    assert done.stdout.strip().splitlines()[-1].startswith(f"OK chain={_head_chain()} ")


def test_registry_starts_with_an_open_line_and_anchors_are_git_ignored():
    entries, _ = cl.parse_registry(ANCHOR_DIR / cl.REGISTRY, _host_key())
    assert entries and entries[0].kind == "open"
    assert any(e.kind == "open" and e.chain_id == _head_chain() for e in entries)
    ignored = subprocess.run(["git", "check-ignore", "audit_anchors/chains.log", "audit_anchors_e6/x", ".env.e6"],
                             cwd=ROOT, capture_output=True, text=True)
    assert ignored.stdout.split() == ["audit_anchors/chains.log", "audit_anchors_e6/x", ".env.e6"]
    docker_ignore = (ROOT / ".dockerignore").read_text().split()
    assert "audit_anchors*/" in docker_ignore and ".env.e6" in docker_ignore


@pytest.mark.skipif(PROJECT != "e6", reason="only on the disposable stand -p e6 (loop and --once together)")
def test_live_twenty_parallel_once_next_to_the_loop():
    procs = [subprocess.Popen(["docker", "compose", "exec", "-T", "audit_anchor", "python", "anchor.py", "--once"],
                              cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
             for _ in range(20)]
    for proc in procs:
        assert proc.wait(timeout=300) == 0
    cl.read_anchors(ANCHOR_DIR / f"{_head_chain()}.log", _host_key(), _head_chain())
    cl.parse_registry(ANCHOR_DIR / cl.REGISTRY, _host_key())


# --- init_secrets.sh for the audit secrets (Б-B2, П12, test 6), on a copy ----------

def _copy_scripts(tmp_path) -> Path:
    work = tmp_path / "repo"
    (work / "scripts").mkdir(parents=True)
    for name in ("init_secrets.sh", "tls_lib.sh"):
        shutil.copy(ROOT / "scripts" / name, work / "scripts" / name)
    return work


def _path_without(tmp_path, *missing) -> str:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for folder in ("/usr/local/bin", "/usr/bin", "/bin"):
        if not os.path.isdir(folder):
            continue
        for entry in os.listdir(folder):
            if entry in missing or (bin_dir / entry).exists():
                continue
            (bin_dir / entry).symlink_to(os.path.join(folder, entry))
    return str(bin_dir)


@pytest.mark.skipif(os.geteuid() == 0, reason="the fallback without ACL is for a non-root user")
def test_init_secrets_without_setfacl_keeps_the_key_600_and_warns(tmp_path):
    work = _copy_scripts(tmp_path)
    env = dict(os.environ, PATH=_path_without(tmp_path, "setfacl"))
    env.pop("CLINIC_AUDIT_ANCHOR_DIR", None)
    first = subprocess.run(["sh", "scripts/init_secrets.sh"], cwd=work, env=env, capture_output=True, text=True)
    assert first.returncode == 0, first.stderr
    key = work / "secrets" / "audit_anchor_key"
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert "audit_anchor_key stays 600" in first.stderr
    assert "audit_anchors: cannot grant write access" in first.stderr
    assert stat.S_IMODE((work / "audit_anchors").stat().st_mode) == 0o700
    sums = {n: hashlib.sha256((work / "secrets" / n).read_bytes()).hexdigest()
            for n in ("audit_anchor_key", "audit_db_password")}
    second = subprocess.run(["sh", "scripts/init_secrets.sh"], cwd=work, env=env, capture_output=True, text=True)
    assert second.returncode == 0
    assert {n: hashlib.sha256((work / "secrets" / n).read_bytes()).hexdigest() for n in sums} == sums
    assert "keep    secrets/audit_anchor_key" in second.stdout


def test_no_world_writable_anchor_directory_anywhere():
    for path in [ROOT / "Makefile", ROOT / "README.md", *(ROOT / "scripts").iterdir()]:
        if path.is_file():
            assert not re.search(r"chmod.*777", path.read_text(errors="ignore")), path


# --- Makefile wipe_stack with a stub COMPOSE (7a) ------------------------------------

STUB = r"""#!/bin/sh
echo "$*" >> "$STUB_LOG"
case "$*" in
  "config --format json") echo '{"name": "stubproj"}' ;;
  "ps --status running -q audit_anchor") [ "$STUB_MODE" = running ] && echo abc123 ;;
  "volumes -q") [ "$STUB_MODE" = volume ] && echo stubproj_db_data ;;
  *--retire*) exit "${STUB_RETIRE_RC:-0}" ;;
esac
exit 0
"""


def _make_with_stub(tmp_path, mode: str, *args, rc: int = 0):
    stub = tmp_path / "compose.sh"
    stub.write_text(STUB)
    stub.chmod(0o755)
    log = tmp_path / "calls.log"
    log.write_text("")
    env = dict(os.environ, STUB_LOG=str(log), STUB_MODE=mode, STUB_RETIRE_RC=str(rc))
    done = subprocess.run(["make", *args, f"COMPOSE={stub}"], cwd=ROOT, env=env,
                          capture_output=True, text=True, timeout=60)
    return done, log.read_text().splitlines()


def test_makefile_wipe_stack_order_and_retire_force_text():
    text = (ROOT / "Makefile").read_text()
    body = text[text.index("define wipe_stack"):text.index("endef", text.index("define wipe_stack"))]
    assert body.index("stop proxy api") < body.index("--retire") < body.index("down -v $(1)")
    assert "RETIRE_FORCE ?=" in text and "RETIRE_FORCE=yes  with CONFIRM=yes" in text
    assert "audit-verify" in text.split(".PHONY:", 1)[1].splitlines()[0]
    assert "up -d --no-build --wait audit_anchor" not in text


def test_retire_force_without_confirm_changes_nothing(tmp_path):
    done, calls = _make_with_stub(tmp_path, "running", "reset", "RETIRE_FORCE=yes")
    assert done.returncode != 0 and "needs CONFIRM=yes" in done.stderr
    assert calls == []


@pytest.mark.parametrize("mode, expected", [
    ("running", ["exec -T audit_anchor python anchor.py --retire"]),
    ("volume", ["run --rm --no-build audit_anchor python anchor.py --retire"]),
    ("none", ["run --rm --no-deps --no-build audit_anchor python anchor.py --retire --offline"]),
])
def test_wipe_stack_retires_the_chain_before_down(tmp_path, mode, expected):
    done, calls = _make_with_stub(tmp_path, mode, "fclean", "CONFIRM=yes")
    assert done.returncode == 0, done.stdout + done.stderr
    retire = [c.strip() for c in calls if "--retire" in c]
    assert retire == expected
    assert calls.index("stop proxy api") < calls.index(next(c for c in calls if "--retire" in c)) \
        < calls.index(next(c for c in calls if c.startswith("down -v")))


def test_failed_retire_stops_before_down(tmp_path):
    for mode in ("running", "volume", "none"):
        done, calls = _make_with_stub(tmp_path, mode, "fclean", "CONFIRM=yes", rc=2)
        assert done.returncode != 0, mode
        assert not any(c.startswith("down") for c in calls), (mode, calls)


def test_forced_retire_passes_force_and_falls_back_offline(tmp_path):
    done, calls = _make_with_stub(tmp_path, "running", "fclean", "CONFIRM=yes", "RETIRE_FORCE=yes")
    assert done.returncode == 0
    assert [c.strip() for c in calls if "--retire" in c] == ["exec -T audit_anchor python anchor.py --retire --force"]
    done, calls = _make_with_stub(tmp_path, "volume", "fclean", "CONFIRM=yes", "RETIRE_FORCE=yes", rc=3)
    assert done.returncode != 0      # the stub also fails the offline retire
    assert "RETIRE_FORCE=yes -> offline forced" in done.stdout
    assert [c.strip() for c in calls if "--retire" in c] == [
        "run --rm --no-build audit_anchor python anchor.py --retire --force",
        "run --rm --no-deps --no-build audit_anchor python anchor.py --retire --offline"]
    assert not any(c.startswith("down") for c in calls)
