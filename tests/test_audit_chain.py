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

    Called directly: the app does call it (routes_admin.py, after a failed
    deliver_password_reset), but there it finds nothing to discard: when SMTP
    fails after smtp_ready(), deliver_password_reset() has already revoked the
    token, and the function only takes a token with used_at IS NULL. A known
    defect from before plan 17 part B, left as it is."""
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


def test_unit_retire_after_chain_replaced_needs_force(tmp_path, capsys):
    """Securo 90f093f §2: a replaced chain is an incident; a plain retire (make
    reset/fclean CONFIRM=yes) refuses with 2 and changes nothing; --force writes
    forced chain_replaced@-, the switch line stays (verify: WARN + BROKEN)."""
    d, old = _dir(tmp_path), FakeSource(rows=2)
    assert anchor.cycle(d, KEY, old).ok
    new = FakeSource(rows=1)
    assert not anchor.cycle(d, KEY, new).ok
    before = _snapshot(d)
    assert anchor.retire(KEY, False, False, d, lambda: (new, lambda: None)) == 2
    out = capsys.readouterr().out
    assert f"BROKEN type=chain_replaced kind=new old={old.chain_id} new={new.chain_id}" in out
    assert "RETIRE_FORCE=yes CONFIRM=yes" in out
    assert _snapshot(d) == before
    assert anchor.retire(KEY, True, False, d, lambda: (new, lambda: None)) == 0
    assert "forced chain_replaced@-" in capsys.readouterr().out
    assert _registry(d) == ["open:", "switch:new", "retire:forced"]
    last = cl.parse_registry(d / cl.REGISTRY, KEY)[0][-1]
    assert (last.chain_id, last.brk, last.last_seq) == (new.chain_id, "chain_replaced@-", new.head()["last_seq"])
    # verify: the forced retire is a WARN, the switch stays BROKEN (1, also with --strict)
    for strict in (False, True):
        lines = []
        assert verify_audit.verify(new, d, KEY, strict, None, 60, lines.append) == 1
        assert lines[0] == f"WARN retire forced chain={new.chain_id} break=chain_replaced@-"
        assert lines[-1].startswith("BROKEN type=chain_replaced kind=new")
    # the next chain opens normally; verify stays red because of the switch
    nxt = FakeSource(rows=0)
    assert anchor.cycle(d, KEY, nxt).ok
    assert verify_audit.verify(nxt, d, KEY, False, None, 60, [].append) == 1


def test_unit_retire_after_chain_replaced_offline_and_retired_reused(tmp_path):
    # --offline (no database volume left) is not blocked: nothing left to protect, logged as offline
    d, old = _dir(tmp_path), FakeSource(rows=2)
    assert anchor.cycle(d, KEY, old).ok
    assert not anchor.cycle(d, KEY, FakeSource(rows=1)).ok
    assert anchor.retire(KEY, False, True, d) == 0
    assert _registry(d)[-1] == "retire:offline"
    # retired_reused is a switch as well
    d2, src = tmp_path / "b", FakeSource(rows=2)
    d2.mkdir()
    d2.chmod(0o700)
    assert anchor.cycle(d2, KEY, src).ok
    assert anchor.retire(KEY, False, True, d2) == 0
    assert not anchor.cycle(d2, KEY, src).ok
    assert anchor.retire(KEY, False, False, d2, lambda: (src, lambda: None)) == 2


def _only_lock(d):
    return [x.name for x in d.iterdir()] in ([], [".lock"])


def test_unit_decide_without_registry_and_anchors():
    """З-11: no registry and no anchor files: a chain in the database is
    registry_missing, an empty or genesis-only journal is a first open."""
    state = cl.registry_state([])
    h = str(uuid.uuid4())
    assert cl.decide(state, h, 0, False, False, holds_chain=True) == cl.Decision("error", "registry_missing")
    assert cl.decide(state, h, 0, False, False, holds_chain=False) == cl.Decision("first_open")
    assert cl.decide(state, h, 0, False, True, holds_chain=False) == cl.Decision("error", "registry_missing")


def test_unit_journal_holds_chain_is_one_rule():
    """The З-10 rule (retire) and the daemon's (beyond the genesis rows)."""
    empty, genesis, more = FakeSource(rows=0), FakeSource(rows=3), FakeSource(rows=3, genesis_rows=0)
    assert not cl.journal_holds_chain(empty, empty.head())
    assert not cl.journal_holds_chain(empty, empty.head(), beyond_genesis=True)
    assert cl.journal_holds_chain(genesis, genesis.head())                    # retire: rows are rows
    assert not cl.journal_holds_chain(genesis, genesis.head(), beyond_genesis=True)
    assert cl.journal_holds_chain(more, more.head(), beyond_genesis=True)
    assert cl.journal_holds_chain(more, None) and not cl.journal_holds_chain(empty, None)   # rows, no head


def test_unit_lost_registry_is_registry_missing_until_the_directory_is_back(tmp_path, capsys):
    """З-11: the anchor directory renamed, the loop (re)started over a database
    that holds a chain: no first_open, nothing written, red, verify BROKEN;
    the old directory put back: green again."""
    d, src = _dir(tmp_path), FakeSource(rows=2)
    assert anchor.cycle(d, KEY, src).ok
    src.add(3)
    archive = tmp_path / "archived"
    d.rename(archive)
    d.mkdir(mode=0o700)                        # init_secrets / anchor_dir.sh makes an empty one
    for _ in range(2):
        result = anchor.cycle(d, KEY, src)
        assert not result.ok and result.error == "registry_missing"
        assert result.line.startswith("ERROR audit chain registry missing")
        assert f"chain={src.chain_id} has last_seq=5" in result.line and "RETIRE_FORCE=yes" in result.line
        assert _only_lock(d)                   # no chains.log, no anchor file
    out = []
    assert verify_audit.verify(src, d, KEY, False, None, 60, out.append) == 1
    assert out[-1] == (f"BROKEN type=registry_missing no registry and no anchors, but the database holds "
                       f"chain={src.chain_id} last_seq=5")
    (d / cl.LOCK).unlink(missing_ok=True)
    d.rmdir()
    archive.rename(d)
    result = anchor.cycle(d, KEY, src)
    assert result.ok and result.anchored[0] == 5
    assert _registry(d) == ["open:"]


def test_unit_lost_registry_then_forced_retire_and_a_new_volume(tmp_path):
    """The other way out: reset with RETIRE_FORCE=yes (forced no_registry@-),
    a new volume, a normal open."""
    d, src = _dir(tmp_path), FakeSource(rows=4, genesis_rows=0)
    assert anchor.cycle(d, KEY, src).error == "registry_missing"
    assert anchor.retire(KEY, False, False, d, lambda: (src, lambda: None)) == 2
    assert anchor.retire(KEY, True, False, d, lambda: (src, lambda: None)) == 0
    nxt = FakeSource(rows=0)
    assert anchor.cycle(d, KEY, nxt).ok
    assert _registry(d) == ["retire:forced", "open:"]


def test_unit_prepare_opens_a_fresh_stand_and_leaves_alarms_to_the_loop(tmp_path, monkeypatch):
    d = _dir(tmp_path)
    monkeypatch.setattr(anchor, "ANCHOR_DIR", d)
    src = FakeSource(rows=0)
    monkeypatch.setattr(anchor, "run_cycle", lambda key, holder: anchor.cycle(d, KEY, src))
    assert anchor.prepare(KEY) == 0 and _registry(d) == ["open:"]     # before seed/api: open first
    src.add(2)                                  # events after the open: a normal anchor later
    calls = []
    monkeypatch.setattr(anchor, "run_cycle", lambda key, holder: calls.append(1))
    assert anchor.prepare(KEY) == 0 and calls == []                   # registry present: nothing to do
    lost = tmp_path / "lost"
    lost.mkdir(mode=0o700)
    monkeypatch.setattr(anchor, "ANCHOR_DIR", lost)
    held = FakeSource(rows=3, genesis_rows=0)
    monkeypatch.setattr(anchor, "run_cycle", lambda key, holder: anchor.cycle(lost, KEY, held))
    assert anchor.prepare(KEY) == 0 and _only_lock(lost)               # registry_missing: the loop's job
    monkeypatch.setattr(anchor, "run_cycle",
                        lambda key, holder: anchor.Result(False, "error", "database", line="ERROR db"))
    assert anchor.prepare(KEY) == 1                                    # cannot open a fresh stand: stop
    locked = tmp_path / "ro"
    locked.mkdir(mode=0o500)
    monkeypatch.setattr(anchor, "ANCHOR_DIR", locked)
    monkeypatch.setattr(anchor, "run_cycle", lambda key, holder: anchor.cycle(locked, KEY, FakeSource()))
    if os.geteuid() != 0:
        assert anchor.prepare(KEY) == 1


def test_unit_retire_without_registry_but_a_chain_in_the_database_needs_force(tmp_path, capsys):
    """З-10: the anchor directory removed or renamed: a plain retire refused (2),
    nothing written; --force starts a new registry with forced no_registry@-,
    verify shows it as a WARN once the next chain is open."""
    d, src = _dir(tmp_path), FakeSource(rows=3)
    assert anchor.retire(KEY, False, False, d, lambda: (src, lambda: None)) == 2
    out = capsys.readouterr().out
    assert f"BROKEN type=registry_missing chain={src.chain_id} last_seq=3" in out
    assert "RETIRE_FORCE=yes CONFIRM=yes" in out and "no_registry" in out
    assert [x.name for x in d.iterdir()] in ([], [".lock"])
    assert anchor.retire(KEY, True, False, d, lambda: (src, lambda: None)) == 0
    entries, _ = cl.parse_registry(d / cl.REGISTRY, KEY)
    assert [(e.kind, e.chain_id, e.mode, e.brk, e.last_seq) for e in entries] == [
        ("retire", src.chain_id, "forced", "no_registry@-", 3)]
    assert anchor.retire(KEY, True, False, d, lambda: (src, lambda: None)) == 0   # no-op now
    assert len(cl.parse_registry(d / cl.REGISTRY, KEY)[0]) == 1
    nxt = FakeSource(rows=0)
    assert anchor.cycle(d, KEY, nxt).ok
    assert _registry(d) == ["retire:forced", "open:"]
    lines = []
    assert verify_audit.verify(nxt, d, KEY, False, None, 60, lines.append) == 0
    assert lines[0] == f"WARN retire forced chain={src.chain_id} break=no_registry@-"
    assert verify_audit.verify(nxt, d, KEY, True, None, 60, [].append) == 3


def test_unit_retire_without_registry_and_an_empty_chain_is_a_no_op(tmp_path, capsys):
    d, src = _dir(tmp_path), FakeSource(rows=0)          # fresh volume: genesis only
    assert anchor.retire(KEY, False, False, d, lambda: (src, lambda: None)) == 0
    assert "empty journal, nothing to close" in capsys.readouterr().out
    assert [x.name for x in d.iterdir()] in ([], [".lock"])
    # offline (no database volume) is unchanged: nothing to close, no question
    assert anchor.retire(KEY, False, True, d) == 0
    assert [x.name for x in d.iterdir()] in ([], [".lock"])


def test_unit_retire_without_registry_and_no_database_refuses_with_3(tmp_path):
    d = _dir(tmp_path)

    def down():
        raise ConnectionRefusedError()
    assert anchor.retire(KEY, False, False, d, down) == 3
    assert [x.name for x in d.iterdir()] in ([], [".lock"])


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


def test_unit_verify_audit_exit_2_without_key_or_database(tmp_path, monkeypatch):
    """Securo 2: no key / no database is not BROKEN (1) but "could not check" (2)."""
    out = []
    monkeypatch.setattr(verify_audit, "KEY_FILE", str(tmp_path / "missing_key"))
    assert verify_audit.main([], out.append) == 2
    assert out == ["ERROR cannot check: audit_anchor_key unavailable (FileNotFoundError)"]
    key_file = tmp_path / "key"
    key_file.write_text(KEY.hex())
    monkeypatch.setattr(verify_audit, "KEY_FILE", str(key_file))

    def refused():
        raise ConnectionRefusedError("db:5432")
    monkeypatch.setattr(cl, "connect", refused)
    out.clear()
    assert verify_audit.main([], out.append) == 2
    assert out == ["ERROR cannot check: database unavailable (ConnectionRefusedError)"]
    assert KEY.hex() not in "".join(out)


def test_unit_verify_audit_warns_on_forced_and_offline_retires(tmp_path):
    d = _dir(tmp_path)
    first = FakeSource(rows=2)
    assert anchor.cycle(d, KEY, first).ok
    first.rows[0]["action"] = "forged"
    assert anchor.retire(KEY, True, False, d, lambda: (first, lambda: None)) == 0
    second = FakeSource(rows=0)
    assert anchor.cycle(d, KEY, second).ok
    assert anchor.retire(KEY, False, True, d) == 0
    third = FakeSource(rows=1, genesis_rows=0)   # fresh volume, one event after genesis
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


# --- plan 18.1: full check every N seconds and the public status file ---------

PUBLIC_KEYS = {"v", "state", "checked_at", "full_checked_at", "full_ok", "anchored_at", "last_anchor_seq",
               "problem", "retired_forced", "retired_offline", "replaced_history"}
_UUID_TEXT = re.compile(r"[0-9a-f-]{36}")


def _service(d, src, full_every=600):
    """The loop of anchor.main without the sleep: (PublicStatus, step(now) -> data, list of full flags)."""
    public, fulls = anchor.PublicStatus(full_every), []

    def do_cycle(full):
        fulls.append(full)
        return anchor.cycle(d, KEY, src, full=full)

    return public, (lambda now: public.step(now, do_cycle)[1]), fulls


def test_full_check_runs_every_n_and_on_start(tmp_path):
    d, src = _dir(tmp_path), FakeSource(rows=3)
    public, step, fulls = _service(d, src, full_every=600)
    for now in (1000, 1060, 1599, 1600, 1660, 2199, 2200):
        data = step(now)
    assert fulls == [True, False, False, True, False, False, True]
    assert data["full_checked_at"] == 2200 and data["full_ok"] is True and data["state"] == "ok"


def test_full_check_failure_is_retried_on_the_next_cycle(tmp_path):
    public, fulls = anchor.PublicStatus(600), []

    def database_down(full):
        fulls.append(full)
        return anchor.Result(False, "error", "database", line="ERROR audit cycle failed: OperationalError")

    for now in (1000, 1060):
        public.step(now, database_down)
    assert fulls == [True, True] and public.full_checked_at is None


def test_full_check_catches_tampered_row_before_last_anchor(tmp_path):
    d, src = _dir(tmp_path), FakeSource(rows=5)
    public, step, _ = _service(d, src)
    assert step(1000)["state"] == "ok"          # full check on start, anchor at seq 5
    src.add(2)
    src.rows[1]["target_id"] = 99               # seq 2, before the last anchor
    data = step(1060)                           # incremental step only
    assert data["state"] == "ok" and data["full_ok"] is True
    assert anchor.cycle(d, KEY, src).ok         # the incremental check alone does not see it
    data = step(1600)                           # full check
    assert data["state"] == "broken" and data["full_ok"] is False
    assert data["problem"] == {"type": "row_hash", "seq": 2, "kind": None}
    data = step(1660)                           # stays broken until a full check is ok again
    assert data["state"] == "broken" and data["problem"]["type"] == "row_hash"


def _assert_public_schema(data):
    assert set(data) == PUBLIC_KEYS
    text = json.dumps(data)
    assert not _UUID_TEXT.search(text), text
    assert not re.search(r"[0-9a-f]{64}", text), text
    # no key or value names a detail, a MAC, a hash, a chain, a path (the
    # problem type is checked against the whitelist below)
    bare = json.dumps({**data, "problem": None})
    for word in ("detail", "mac", "hash", "chain", "path", "anchors", "/"):
        assert word not in bare, (word, bare)
    if data["problem"] is not None:
        assert set(data["problem"]) == {"type", "seq", "kind"}
        allowed = anchor.UNCHECKED_REASONS if data["state"] == "unchecked" else anchor.PROBLEM_TYPES
        assert data["problem"]["type"] in allowed


def test_public_status_schema_whitelist(tmp_path):
    d, src = _dir(tmp_path), FakeSource(rows=3)
    public, step, _ = _service(d, src)
    _assert_public_schema(step(1000))
    src.add(1)
    src.rows[-1]["action"] = "test.changed"          # a break after the last anchor
    data = step(1060)
    _assert_public_schema(data)
    assert data["state"] == "broken" and data["problem"] == {"type": "row_hash", "seq": 4, "kind": None}
    other = FakeSource(rows=1)                        # a new chain without retire
    _, step2, _ = _service(d, other)
    data = step2(1000)
    _assert_public_schema(data)
    assert data["state"] == "broken" and data["problem"]["type"] == "chain_replaced"
    assert data["problem"]["kind"] == "new"


def test_unknown_problem_type_is_written_as_unknown():
    public = anchor.PublicStatus(600)
    _, data = public.step(1000, lambda full: anchor.Result(False, "error", "something/else", seq=3))
    assert data["state"] == "broken" and data["problem"] == {"type": "unknown", "seq": 3, "kind": None}


def test_replaced_history_survives_retire_and_new_open(tmp_path):
    d, old = _dir(tmp_path), FakeSource(rows=2)
    _, step, _ = _service(d, old)
    assert step(1000)["state"] == "ok"
    new = FakeSource(rows=1)
    _, step, _ = _service(d, new)
    data = step(1000)
    assert data["state"] == "broken" and data["replaced_history"] == 1
    assert anchor.retire(KEY, True, False, d, lambda: (new, lambda: None)) == 0   # RETIRE_FORCE
    fresh = FakeSource(rows=0)                      # make reset: a new volume, a new chain
    _, step, _ = _service(d, fresh)
    for now in (5000, 5060, 5600):
        data = step(now)
        assert data["state"] == "broken" and data["replaced_history"] == 1, data
        assert data["retired_forced"] == 1
    assert _registry(d)[-1] == "open:"


def test_unchecked_on_database_error_and_retired(tmp_path):
    public = anchor.PublicStatus(600)
    for error in ("database", "anchor_dir"):
        _, data = public.step(1000, lambda full: anchor.Result(False, "error", error))
        assert data["state"] == "unchecked", error
        assert data["problem"] == {"type": error, "seq": None, "kind": None}
    d, src = _retired(tmp_path)
    _, step, _ = _service(d, src)
    data = step(1000)
    assert data["state"] == "unchecked" and data["full_ok"] is True
    assert data["problem"] == {"type": "retired", "seq": None, "kind": None}


@pytest.mark.skipif(os.geteuid() == 0, reason="root writes anywhere")
def test_unchecked_when_the_anchor_directory_is_not_writable(tmp_path):
    d, src = _dir(tmp_path), FakeSource(rows=1)
    _, step, _ = _service(d, src)
    assert step(1000)["state"] == "ok"
    d.chmod(0o500)
    try:
        data = step(1060)
    finally:
        d.chmod(0o700)
    assert data["state"] == "unchecked" and data["problem"]["type"] == "anchor_dir"


def test_atomic_write_never_partial(tmp_path):
    status = tmp_path / "status"
    status.mkdir()
    anchor.write_public_status(status, {"v": 1, "n": 0})
    errors = []

    def writer():
        for n in range(1000):
            anchor.write_public_status(status, {"v": 1, "n": n, "pad": "x" * (n % 50) * 40})

    def reader():
        for _ in range(1000):
            try:
                json.loads((status / anchor.PUBLIC_STATUS_NAME).read_text())
            except ValueError as exc:
                errors.append(exc)

    threads = [threading.Thread(target=writer), threading.Thread(target=reader)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert oct((status / anchor.PUBLIC_STATUS_NAME).stat().st_mode & 0o777) == "0o644"
    assert sorted(p.name for p in status.iterdir()) == [anchor.PUBLIC_STATUS_NAME]


def test_atomic_write_does_not_follow_a_planted_symlink(tmp_path):
    status, target = tmp_path / "status", tmp_path / "elsewhere"
    status.mkdir()
    target.write_text("keep")
    (status / f".{anchor.PUBLIC_STATUS_NAME}.tmp").symlink_to(target)
    with pytest.raises(OSError):
        anchor.write_public_status(status, {"v": 1})
    assert target.read_text() == "keep"


@pytest.mark.parametrize("value", ["59", "86401", "abc", "", "-60", "600.0"])
def test_full_check_every_validation(monkeypatch, value):
    monkeypatch.setenv("CLINIC_AUDIT_FULL_CHECK_EVERY", value)
    with pytest.raises(SystemExit):
        anchor.full_check_every()


def test_full_check_every_bounds_and_default(monkeypatch):
    monkeypatch.delenv("CLINIC_AUDIT_FULL_CHECK_EVERY", raising=False)
    assert anchor.full_check_every() == 600
    for value in ("60", "86400"):
        monkeypatch.setenv("CLINIC_AUDIT_FULL_CHECK_EVERY", value)
        assert anchor.full_check_every() == int(value)


def test_once_retire_and_health_do_not_write_the_public_status():
    source = (ROOT / "audit" / "anchor.py").read_text()
    main = source[source.index("def main("):]
    assert main.count("write_public_status(") == 1
    assert main.index("write_public_status(") > main.index("while True:")


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


AUDIT_SERVICES = ("audit_anchor", "audit_prepare")   # the loop and its one-shot first open (З-11)


def test_compose_mounts_the_key_only_on_audit_anchor_and_hardens_it():
    services = _compose_config()["services"]
    for name, service in services.items():
        mounted = {item["source"] for item in service.get("secrets") or []}
        if name in AUDIT_SERVICES:
            assert mounted == {"audit_db_password", "audit_anchor_key"}, name
        else:
            assert "audit_anchor_key" not in mounted, name
            assert ("audit_db_password" in mounted) == (name == "migrate"), name
    for name in AUDIT_SERVICES:
        anchor_service = services[name]
        assert set(anchor_service["networks"]) == {"backend"}, name
        assert anchor_service.get("read_only") is True, name
        assert anchor_service.get("cap_drop") == ["ALL"], name
        assert "no-new-privileges:true" in anchor_service.get("security_opt", []), name
        assert not anchor_service.get("ports"), name
    # the same anchor directory; /status (plan 18.1) only on the loop
    anchors = [v for v in services["audit_anchor"]["volumes"] if v["target"] == "/anchors"]
    assert services["audit_prepare"]["volumes"] == anchors
    assert {v["target"] for v in services["audit_anchor"]["volumes"]} == {"/anchors", "/status"}
    assert services["audit_prepare"]["command"] == ["python", "anchor.py", "--prepare"]


def test_compose_opens_the_registry_before_anything_writes_to_the_journal():
    """З-11: seed (and so api) waits for audit_prepare, which waits for migrate."""
    services = _compose_config()["services"]
    assert services["seed"]["depends_on"]["audit_prepare"]["condition"] == "service_completed_successfully"
    assert services["api"]["depends_on"]["seed"]["condition"] == "service_completed_successfully"
    assert services["audit_prepare"]["depends_on"]["migrate"]["condition"] == "service_completed_successfully"
    assert "restart" not in services["audit_prepare"] or services["audit_prepare"]["restart"] == "no"


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
    """600, or 600 + ACL u:10002:r (Б-B2): with an ACL the group bits of the mode
    show the mask, so the ACL itself is read: no group, no other, and the only
    named entry is the anchor user, read-only."""
    key = ROOT / "secrets" / "audit_anchor_key"
    mode = key.stat().st_mode
    assert not mode & (stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH)
    acl = None
    if shutil.which("getfacl"):
        done = subprocess.run(["getfacl", "-cpn", str(key)], capture_output=True, text=True)
        assert done.returncode == 0, done.stderr
        acl = [line for line in done.stdout.split() if line and not line.startswith("#")]
    if acl is None or acl == ["user::rw-", "group::---", "other::---"]:
        assert stat.S_IMODE(mode) == 0o600, oct(mode)
        return
    named = sorted(e for e in acl if e.startswith(("user:", "group:")) and e.split(":")[1])
    assert named == ["user:10002:r--"], acl
    assert "group::---" in acl and "other::---" in acl, acl
    assert stat.S_IMODE(mode) in (0o600, 0o640), oct(mode)   # 640 = owner rw + mask r


@pytest.mark.skipif(PROJECT != "e6", reason="only on a disposable stand -p e6 (make reset wipes its database)")
def test_live_reset_after_stop_closes_the_chain_with_run():
    """Н-1: after make stop audit_anchor is not running, the volume exists, so
    make reset goes through "compose run" (no --no-build) and passes."""
    env = dict(os.environ)
    compose = "docker compose"   # -p, files and env file come from COMPOSE_* of the caller
    stopped = subprocess.run(["make", "-s", "stop", f"COMPOSE={compose}"], cwd=ROOT, env=env,
                             capture_output=True, text=True, timeout=300)
    assert stopped.returncode == 0, stopped.stderr[-2000:]
    old_chain = cl.registry_state(cl.parse_registry(ANCHOR_DIR / cl.REGISTRY, _host_key())[0]).current
    assert old_chain
    done = subprocess.run(["make", "reset", "CONFIRM=yes", f"COMPOSE={compose}"], cwd=ROOT, env=env,
                          capture_output=True, text=True, timeout=1800)
    assert done.returncode == 0, done.stdout[-3000:] + done.stderr[-3000:]
    assert "run --rm audit_anchor python anchor.py --retire" in done.stdout
    entries, _ = cl.parse_registry(ANCHOR_DIR / cl.REGISTRY, _host_key())
    assert any(e.kind == "retire" and e.chain_id == old_chain and e.mode == "normal"
               for e in entries), [(e.kind, e.chain_id, e.mode) for e in entries]


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


def test_audit_anchor_healthcheck_still_turns_red_in_time():
    """A red status (chain_replaced, broken chain) must reach "unhealthy" well
    inside the 200 s that E6 waits: retries x (interval + timeout) under 200 s."""
    check = _compose_config()["services"]["audit_anchor"]["healthcheck"]
    assert check["test"] == ["CMD", "python", "anchor.py", "--health"]

    def seconds(value):
        value = str(value)
        return int(value[:-1]) if value.endswith("s") else int(value) / 1e9   # config gives "15s" or ns

    interval, timeout, retries = seconds(check["interval"]), seconds(check["timeout"]), int(check["retries"])
    assert timeout >= 20 and retries >= 4
    assert retries * (interval + timeout) < 200, check


def test_audit_anchor_is_healthy():
    # the status file itself must be green now ...
    own = subprocess.run(["docker", "compose", "exec", "-T", "audit_anchor", "python", "anchor.py", "--health"],
                         cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert own.returncode == 0, own.stdout + own.stderr
    # ... and Docker's view follows within two healthcheck intervals (a red status
    # needs 4 failed checks in a row, so a real fault does not pass this)
    deadline, state = time.time() + 30, ""
    while True:
        state = subprocess.run(["docker", "compose", "ps", "--format", "{{.Health}}", "audit_anchor"],
                               cwd=ROOT, capture_output=True, text=True, timeout=60).stdout.strip()
        if state == "healthy" or time.time() > deadline:
            break
        time.sleep(3)
    assert state == "healthy", state


def _public_status() -> dict:
    done = subprocess.run(["docker", "compose", "exec", "-T", "audit_anchor", "cat", "/status/status.json"],
                          cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def test_status_file_written_and_fresh():
    """18.1: the loop writes /status/status.json; full check on start."""
    every = int(os.environ.get("CLINIC_AUDIT_ANCHOR_INTERVAL", "60"))
    deadline = time.time() + 2 * every + 30
    while True:
        data = _public_status()
        if data["full_checked_at"] is not None or time.time() > deadline:
            break
        time.sleep(3)
    assert set(data) == PUBLIC_KEYS
    assert data["state"] == "ok", data
    assert time.time() - data["checked_at"] <= 2 * every + 15
    assert data["full_checked_at"] is not None and data["full_ok"] is True
    owner = subprocess.run(["docker", "compose", "exec", "-T", "audit_anchor", "stat", "-c", "%u %a",
                            "/status", "/status/status.json"],
                           cwd=ROOT, capture_output=True, text=True, timeout=60).stdout.split()
    assert owner == ["10002", "755", "10002", "644"], owner


def test_make_audit_verify_is_ok_on_an_intact_journal():
    compose = "docker compose" + (f" -p {PROJECT}" if PROJECT else "")
    done = subprocess.run(["make", "-s", "audit-verify", f"COMPOSE={compose}"], cwd=ROOT,
                          capture_output=True, text=True, timeout=300)
    assert done.returncode == 0, done.stdout + done.stderr
    assert done.stdout.strip().splitlines()[-1].startswith(f"OK chain={_head_chain()} ")


def test_registry_starts_with_an_open_line_and_anchors_are_git_ignored():
    entries, _ = cl.parse_registry(ANCHOR_DIR / cl.REGISTRY, _host_key())
    # a registry starts with open, or (З-10, after a forced reset without the old
    # registry) with retire ... forced no_registry@-
    assert entries and (entries[0].kind == "open"
                        or (entries[0].kind, entries[0].mode, entries[0].brk) == ("retire", "forced", "no_registry@-"))
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


@pytest.mark.skipif(PROJECT != "e6", reason="only on a disposable stand -p e6 (replaces the chain, then resets)")
def test_live_reset_after_chain_replaced_needs_retire_force():
    """Securo 90f093f §2 on a live stand: the chain is replaced without a retire
    (the database volume dropped behind make's back, so no SQL on the journal,
    §9.2); make reset CONFIRM=yes refuses and keeps the volume; with
    RETIRE_FORCE=yes it passes and the registry says forced chain_replaced@-."""
    compose = "docker compose"
    old = _head_chain()
    # no --wait: audit_anchor turns red on purpose
    for args in (["down", "-v"], ["up", "-d"]):
        done = subprocess.run(["docker", "compose", *args], cwd=ROOT, capture_output=True, text=True, timeout=1200)
        assert done.returncode == 0, done.stderr[-2000:]
    deadline, replaced = time.time() + 300, None
    while time.time() < deadline:
        head = _psql_try("SELECT chain_id FROM audit_chain_head")
        if head.returncode == 0 and head.stdout.strip():
            replaced = head.stdout.strip()
            break
        time.sleep(3)
    assert replaced and replaced != old
    once = subprocess.run(["docker", "compose", "exec", "-T", "audit_anchor", "python", "anchor.py", "--once"],
                          cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert once.returncode == 1 and "chain_replaced" in once.stdout, once.stdout
    registry = ANCHOR_DIR / cl.REGISTRY
    before = registry.read_bytes()
    assert cl.parse_registry(registry, _host_key())[0][-1].kind == "switch"
    volume = _compose_config()["volumes"]["db_data"]["name"]

    refused = subprocess.run(["make", "reset", "CONFIRM=yes", f"COMPOSE={compose}"], cwd=ROOT,
                             capture_output=True, text=True, timeout=600)
    assert refused.returncode != 0, refused.stdout[-2000:]
    assert "RETIRE_FORCE=yes CONFIRM=yes" in refused.stdout + refused.stderr
    assert "nothing was deleted" in refused.stderr and "brings the stand back" in refused.stderr
    assert "down -v" not in refused.stdout
    assert subprocess.run(["docker", "volume", "inspect", volume], capture_output=True).returncode == 0
    assert registry.read_bytes() == before
    assert _head_chain() == replaced            # the evidence is still in the database

    forced = subprocess.run(["make", "reset", "CONFIRM=yes", "RETIRE_FORCE=yes", f"COMPOSE={compose}"], cwd=ROOT,
                            capture_output=True, text=True, timeout=1800)
    assert forced.returncode == 0, forced.stdout[-3000:] + forced.stderr[-3000:]
    entries, _ = cl.parse_registry(registry, _host_key())
    assert any(e.kind == "switch" and e.new == replaced for e in entries)
    last_retire = [e for e in entries if e.kind == "retire"][-1]
    assert (last_retire.chain_id, last_retire.mode, last_retire.brk) == (replaced, "forced", "chain_replaced@-")


def _put_an_event() -> None:
    """A fresh volume can hold genesis only: log in once so that the journal
    holds a chain beyond it (the api may still be starting after a reset)."""
    before = _head()
    _wait_login(180)
    head = _head()
    assert head["last_seq"] > max(before["last_seq"], head["genesis_rows"])


def _wait_login(seconds: int) -> None:
    deadline = time.time() + seconds
    while True:
        with CsrfClient(base_url=BASE, follow_redirects=True, timeout=30.0) as c:
            try:
                page = c.post("/login", data={"email": ADMIN, "password": PASSWORD})
                if page.status_code == 200 and page.url.path == "/me":
                    return
            except httpx.HTTPError:
                pass
        assert time.time() < deadline, "the api did not come up"
        time.sleep(3)


def _anchors_live(chain: str):
    return cl.read_anchors(ANCHOR_DIR / f"{chain}.log", _host_key(), chain)[0]


def _anchor_health() -> str:
    return subprocess.run(["docker", "compose", "ps", "--format", "{{.Health}}", "audit_anchor"], cwd=ROOT,
                          capture_output=True, text=True, timeout=60).stdout.strip()


def _wait_health(want: str, seconds: int) -> float:
    started = time.time()
    while _anchor_health() != want:
        assert time.time() - started < seconds, f"audit_anchor is {_anchor_health()!r}, not {want} after {seconds} s"
        time.sleep(3)
    return time.time() - started


@pytest.mark.skipif(PROJECT != "e6", reason="only on a disposable stand -p e6 (archives its anchor directory)")
def test_live_start_without_anchor_directory_is_registry_missing_until_it_is_back():
    """З-11: rename the anchor directory and start/restart without a reset:
    no silent first open. audit_anchor writes nothing, turns unhealthy within
    the E6 window (< 200 s), make audit-verify says BROKEN registry_missing
    (rc 1); the directory put back: healthy again."""
    compose = "docker compose"
    _put_an_event()
    chain = _head_chain()
    stopped = subprocess.run(["make", "-s", "stop", f"COMPOSE={compose}"], cwd=ROOT,
                             capture_output=True, text=True, timeout=300)
    assert stopped.returncode == 0, stopped.stderr[-2000:]
    registry_before = (ANCHOR_DIR / cl.REGISTRY).read_bytes()
    archive = ANCHOR_DIR.with_name(f"{ANCHOR_DIR.name}-moved-{int(time.time())}")
    ANCHOR_DIR.rename(archive)
    since = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    started = subprocess.run(["make", "start", f"COMPOSE={compose}"], cwd=ROOT,
                             capture_output=True, text=True, timeout=1800)
    assert started.returncode == 0, started.stdout[-3000:] + started.stderr[-3000:]
    assert ANCHOR_DIR.is_dir() and ANCHOR_DIR.stat().st_uid == os.getuid()   # init_secrets made it, empty
    took = _wait_health("unhealthy", 200)
    for target in ("start", "restart"):
        if target == "restart":
            # make restart waits for healthy services: with the alarm it fails, loudly
            again = subprocess.run(["make", "restart", f"COMPOSE={compose}"], cwd=ROOT,
                                   capture_output=True, text=True, timeout=900)
            assert again.returncode != 0, again.stdout[-2000:]
            assert "restart: a service did not come up running/healthy" in again.stderr
            _wait_health("unhealthy", 200)     # red again after the restart, not a first open
            _wait_login(120)                   # the rest of the stand is up
        assert [p.name for p in ANCHOR_DIR.iterdir()] in ([], [".lock"]), list(ANCHOR_DIR.iterdir())
        logs = subprocess.run(["docker", "compose", "logs", "--since", since, "audit_anchor", "audit_prepare"],
                              cwd=ROOT, capture_output=True, text=True, timeout=60).stdout
        assert f"ERROR audit chain registry missing (no chains.log and no anchors, but chain={chain}" in logs
        assert "opened chain=" not in logs, logs[-3000:]
        verify = subprocess.run(["make", "-s", "audit-verify", f"COMPOSE={compose}"], cwd=ROOT,
                                capture_output=True, text=True, timeout=300)
        assert verify.returncode != 0
        assert verify.stdout.strip().splitlines()[-1].startswith(
            f"BROKEN type=registry_missing no registry and no anchors, but the database holds chain={chain}")
    assert _anchor_health() == "unhealthy"

    # way out 1: put the directory back (the reset way is the З-10 test below)
    stopped = subprocess.run(["docker", "compose", "stop", "audit_anchor"], cwd=ROOT,
                             capture_output=True, text=True, timeout=300)
    assert stopped.returncode == 0, stopped.stderr
    (ANCHOR_DIR / ".lock").unlink(missing_ok=True)
    ANCHOR_DIR.rmdir()
    archive.rename(ANCHOR_DIR)
    up = subprocess.run(["docker", "compose", "start", "audit_anchor"], cwd=ROOT,
                        capture_output=True, text=True, timeout=300)
    assert up.returncode == 0, up.stderr
    _wait_health("healthy", 200)
    assert (ANCHOR_DIR / cl.REGISTRY).read_bytes() == registry_before    # no switch, no new open
    assert any(a.seq == _head()["last_seq"] for a in _anchors_live(chain))
    verify = subprocess.run(["make", "-s", "audit-verify", f"COMPOSE={compose}"], cwd=ROOT,
                            capture_output=True, text=True, timeout=300)
    assert "registry_missing" not in verify.stdout, verify.stdout
    if b" switch " not in registry_before:  # an earlier chain_replaced test keeps verify red for good
        assert verify.returncode == 0, verify.stdout + verify.stderr
    print(f"unhealthy after {took:.0f} s")


@pytest.mark.skipif(PROJECT != "e6", reason="only on a disposable stand -p e6 (archives its anchor directory)")
def test_live_reset_without_anchor_directory_needs_force_and_leaves_a_record():
    """З-9 + З-10 + the README restart: stop, archive the anchor directory
    (rename, never delete). make reset CONFIRM=yes: the new directory belongs
    to the user (not root) with the ACL, but the retire refuses (the database
    still holds the chain) and the volume stays. With RETIRE_FORCE=yes the new
    registry starts with retire ... forced no_registry@-, verify shows a WARN."""
    compose = "docker compose"
    _put_an_event()
    stopped = subprocess.run(["make", "-s", "stop", f"COMPOSE={compose}"], cwd=ROOT,
                             capture_output=True, text=True, timeout=300)
    assert stopped.returncode == 0, stopped.stderr[-2000:]
    archive = ANCHOR_DIR.with_name(f"{ANCHOR_DIR.name}-archived-{int(time.time())}")
    old_chain = cl.registry_state(cl.parse_registry(ANCHOR_DIR / cl.REGISTRY, _host_key())[0]).current
    assert old_chain
    ANCHOR_DIR.rename(archive)
    volume = _compose_config()["volumes"]["db_data"]["name"]

    refused = subprocess.run(["make", "reset", "CONFIRM=yes", f"COMPOSE={compose}"], cwd=ROOT,
                             capture_output=True, text=True, timeout=1800)
    assert refused.returncode != 0, refused.stdout[-3000:]
    assert "retire refused: no chain registry" in refused.stdout
    assert "nothing was deleted" in refused.stderr and "brings the stand back" in refused.stderr
    assert "down -v" not in refused.stdout
    assert subprocess.run(["docker", "volume", "inspect", volume], capture_output=True).returncode == 0
    info = ANCHOR_DIR.stat()                               # З-9: made by the user, not by Docker as root
    assert info.st_uid == os.getuid() != 0
    acl = subprocess.run(["getfacl", "-cpn", str(ANCHOR_DIR)], capture_output=True, text=True).stdout.split()
    assert "user:10002:rwx" in acl and "other::---" in acl, acl
    assert not (ANCHOR_DIR / cl.REGISTRY).exists()

    forced = subprocess.run(["make", "reset", "CONFIRM=yes", "RETIRE_FORCE=yes", f"COMPOSE={compose}"], cwd=ROOT,
                            capture_output=True, text=True, timeout=1800)
    assert forced.returncode == 0, forced.stdout[-3000:] + forced.stderr[-3000:]
    assert f"retired chain={old_chain} forced no_registry@-" in forced.stdout
    assert (archive / cl.REGISTRY).exists()          # the old registry is kept, untouched
    deadline = time.time() + 180
    while time.time() < deadline:
        kinds = [e.kind for e in cl.parse_registry(ANCHOR_DIR / cl.REGISTRY, _host_key())[0]]
        if kinds == ["retire", "open"]:
            break
        time.sleep(3)
    entries, _ = cl.parse_registry(ANCHOR_DIR / cl.REGISTRY, _host_key())
    assert [(e.kind, e.mode, e.brk) for e in entries] == [("retire", "forced", "no_registry@-"), ("open", None, None)]
    assert entries[0].chain_id == old_chain and entries[1].chain_id == _head_chain()
    time.sleep(15)                                   # one anchor on the new chain
    verify = subprocess.run(["make", "-s", "audit-verify", f"COMPOSE={compose}"], cwd=ROOT,
                            capture_output=True, text=True, timeout=300)
    assert verify.returncode == 0, verify.stdout + verify.stderr
    assert f"WARN retire forced chain={old_chain} break=no_registry@-" in verify.stdout
    assert verify.stdout.strip().splitlines()[-1].startswith(f"OK chain={_head_chain()} ")


# --- init_secrets.sh for the audit secrets (Б-B2, П12, test 6), on a copy ----------

def _copy_scripts(tmp_path) -> Path:
    work = tmp_path / "repo"
    (work / "scripts").mkdir(parents=True)
    for name in ("init_secrets.sh", "tls_lib.sh", "anchor_dir.sh"):
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
  "config --format json") printf '%s\n' '{"name": "stubproj", "volumes": {"db_data": {"name": "stubproj_db_data"}}, "services": {"audit_anchor": {"volumes": [{"type": "bind", "source": "'"$STUB_ANCHORS"'", "target": "/anchors"}]}}}' ;;
  "ps --status running -q audit_anchor") [ "$STUB_MODE" = running ] && echo abc123 ;;
  *--retire*) [ -d "$STUB_ANCHORS" ] && echo "anchors-present" >> "$STUB_LOG"
    # STUB_HARNESS: the real anchor.retire on a fake journal (tests/audit_fake.py)
    [ -n "${STUB_HARNESS:-}" ] && exec "$STUB_PYTHON" "$STUB_HARNESS" "$@"
    exit "${STUB_RETIRE_RC:-0}" ;;
esac
exit 0
"""

# Fake docker for "volume inspect" (Н-2: no "docker compose volumes" before
# Compose 2.33). STUB_INSPECT picks the answer: ok, missing (the daemon's
# "no such volume"), denied, nodaemon, password (Н-3: only "missing" may lead
# to the offline retire).
DOCKER_STUB = r"""#!/bin/sh
echo "docker $*" >> "$STUB_LOG"
if [ "$1 $2" = "volume inspect" ]; then
  case "$STUB_INSPECT" in
    ok) exit 0 ;;
    missing) echo "Error response from daemon: get $3: no such volume" >&2 ;;
    denied) echo "permission denied while trying to connect to the docker API at unix:///var/run/docker.sock" >&2 ;;
    nodaemon) echo "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?" >&2 ;;
    password) echo "sudo: a password is required" >&2 ;;
  esac
fi
exit 1
"""

# "docker" in PATH: a user without the docker group. Never to be used when
# COMPOSE (or DOCKER) says otherwise.
BARE_DOCKER = r"""#!/bin/sh
echo "BARE docker $*" >> "$STUB_LOG"
echo "permission denied while trying to connect to the docker API at unix:///var/run/docker.sock" >&2
exit 1
"""

# Fake "sudo -n": "docker compose ..." goes to the compose stub, "docker ..." to
# the docker stub, both logged with the sudo prefix.
SUDO_STUB = r"""#!/bin/sh
[ "$1" = -n ] || { echo "stub sudo wants -n" >&2; exit 1; }
shift
echo "sudo -n $*" >> "$STUB_LOG"
[ "$1" = docker ] || exit 1
shift
if [ "$1" = compose ]; then shift; exec "$STUB_COMPOSE" "$@"; fi
exec "$STUB_DOCKER" "$@"
"""


def _exe(path, text):
    path.write_text(text)
    path.chmod(0o755)
    return path


def _make_with_stub(tmp_path, mode: str, *args, rc: int = 0, inspect: str | None = None, sudo: bool = False,
                    anchors: Path | None = None):
    stub = _exe(tmp_path / "compose.sh", STUB)
    if anchors is None:
        anchors = tmp_path / "anchors"
        anchors.mkdir(mode=0o700, exist_ok=True)
    fake_docker = _exe(tmp_path / "fake-docker", DOCKER_STUB)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    _exe(bin_dir / "docker", BARE_DOCKER)
    _exe(bin_dir / "sudo", SUDO_STUB)
    log = tmp_path / "calls.log"
    log.write_text("")
    if inspect is None:
        inspect = "ok" if mode == "volume" else "missing"
    env = dict(os.environ, STUB_LOG=str(log), STUB_MODE=mode, STUB_RETIRE_RC=str(rc), STUB_INSPECT=inspect,
               STUB_COMPOSE=str(stub), STUB_DOCKER=str(fake_docker), STUB_ANCHORS=str(anchors),
               PATH=f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    env.pop("DOCKER", None)
    if sudo:
        compose = ["COMPOSE=sudo -n docker compose"]           # DOCKER derived: "sudo -n docker"
    else:
        compose = [f"COMPOSE={stub}", f"DOCKER={fake_docker}"]
    done = subprocess.run(["make", *args, *compose], cwd=ROOT, env=env,
                          capture_output=True, text=True, timeout=60)
    calls = log.read_text().splitlines()
    assert not any(c.startswith("BARE docker") for c in calls), calls
    return done, [c for c in calls if not c.startswith("sudo -n ")]   # the sudo log lines doubled


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
    ("volume", ["run --rm audit_anchor python anchor.py --retire"]),
    ("none", ["run --rm --no-deps audit_anchor python anchor.py --retire --offline"]),
])
def test_wipe_stack_retires_the_chain_before_down(tmp_path, mode, expected):
    done, calls = _make_with_stub(tmp_path, mode, "fclean", "CONFIRM=yes")
    assert done.returncode == 0, done.stdout + done.stderr
    retire = [c.strip() for c in calls if "--retire" in c]
    assert retire == expected
    assert calls.index("stop proxy api") < calls.index(next(c for c in calls if "--retire" in c)) \
        < calls.index(next(c for c in calls if c.startswith("down -v")))
    assert "volumes -q" not in calls
    if mode != "running":
        assert "docker volume inspect stubproj_db_data" in calls


@pytest.mark.parametrize("inspect, hint", [
    ("denied", "permission denied"),
    ("nodaemon", "Cannot connect to the Docker daemon"),
    ("password", "a password is required"),
])
def test_volume_lookup_error_fails_closed(tmp_path, inspect, hint):
    """Н-3: an error other than "no such volume" is not "no volume": no offline
    retire (it skips the chain check), no down -v, rc != 0, how to get back."""
    for target in ("fclean", "reset"):
        done, calls = _make_with_stub(tmp_path, "volume", target, "CONFIRM=yes", inspect=inspect)
        assert done.returncode != 0, (target, done.stdout)
        assert not any("--retire" in c for c in calls), calls
        assert not any(c.startswith("down") or c.startswith("up") for c in calls), calls
        assert "cannot tell whether the volume stubproj_db_data exists" in done.stderr
        assert hint in done.stderr and "nothing was deleted" in done.stderr
        assert "proxy and api are stopped" in done.stderr and "start COMPOSE=" in done.stderr


def test_no_such_volume_is_the_only_way_to_offline(tmp_path):
    done, calls = _make_with_stub(tmp_path, "none", "fclean", "CONFIRM=yes", inspect="missing")
    assert done.returncode == 0, done.stderr
    assert [c.strip() for c in calls if "--retire" in c] == [
        "run --rm --no-deps audit_anchor python anchor.py --retire --offline"]
    assert "no volume stubproj_db_data:" in done.stdout


def test_volume_lookup_uses_the_compose_prefix(tmp_path):
    """COMPOSE="sudo -n docker compose" -> "sudo -n docker volume inspect", never a bare docker."""
    raw = tmp_path / "calls.log"
    for inspect, expected in (("ok", "run --rm audit_anchor python anchor.py --retire"),
                              ("missing", "run --rm --no-deps audit_anchor python anchor.py --retire --offline")):
        done, calls = _make_with_stub(tmp_path, "volume", "fclean", "CONFIRM=yes", inspect=inspect, sudo=True)
        assert done.returncode == 0, done.stderr
        lines = raw.read_text().splitlines()
        assert "sudo -n docker volume inspect stubproj_db_data" in lines, lines
        assert "sudo -n docker compose stop proxy api" in lines
        assert [c.strip() for c in calls if "--retire" in c] == [expected]
    # denied through sudo too: fail closed
    done, calls = _make_with_stub(tmp_path, "volume", "fclean", "CONFIRM=yes", inspect="denied", sudo=True)
    assert done.returncode != 0 and not any(c.startswith("down") for c in calls)


def test_docker_prefix_is_derived_from_compose():
    for compose, docker in (("docker compose -p fixer", "docker"),
                            ("sudo -n docker compose -p planera -f docker-compose.yml -f docker-compose.planera.yml",
                             "sudo -n docker"),
                            ("env A=1 /usr/bin/docker compose", "env A=1 /usr/bin/docker"),
                            ("/tmp/compose-stub.sh", "")):
        env = {k: v for k, v in os.environ.items() if k != "DOCKER"}
        done = subprocess.run(["make", "-s", "help", f"COMPOSE={compose}"], cwd=ROOT, env=env,
                              capture_output=True, text=True, timeout=60)
        assert done.stdout.rstrip().endswith(f"now: {docker})"), (compose, done.stdout)
        # an exported DOCKER is ignored ...
        env_docker = subprocess.run(["make", "-s", "help", f"COMPOSE={compose}"], cwd=ROOT,
                                    env=dict(env, DOCKER="/other/docker"), capture_output=True, text=True, timeout=60)
        assert env_docker.stdout.rstrip().endswith(f"now: {docker})"), (compose, env_docker.stdout)
        # ... the command line wins
        line = subprocess.run(["make", "-s", "help", f"COMPOSE={compose}", "DOCKER=/cli/docker"], cwd=ROOT,
                              env=env, capture_output=True, text=True, timeout=60)
        assert line.stdout.rstrip().endswith("now: /cli/docker)"), (compose, line.stdout)


def test_compose_without_a_compose_word_needs_docker(tmp_path):
    stub = _exe(tmp_path / "compose.sh", STUB)
    log = tmp_path / "calls.log"
    env = {k: v for k, v in os.environ.items() if k != "DOCKER"}
    env.update(STUB_LOG=str(log), STUB_MODE="volume")
    done = subprocess.run(["make", "fclean", "CONFIRM=yes", f"COMPOSE={stub}"], cwd=ROOT, env=env,
                          capture_output=True, text=True, timeout=60)
    assert done.returncode != 0 and "set DOCKER=" in done.stderr
    assert not log.exists() or log.read_text() == ""
    # DOCKER from the environment does not count either
    done = subprocess.run(["make", "fclean", "CONFIRM=yes", f"COMPOSE={stub}"], cwd=ROOT,
                          env=dict(env, DOCKER=str(_exe(tmp_path / "fake-docker", DOCKER_STUB))),
                          capture_output=True, text=True, timeout=60)
    assert done.returncode != 0 and "set DOCKER=" in done.stderr
    assert not log.exists() or log.read_text() == ""


@pytest.mark.parametrize("mode", ["running", "volume", "none"])
def test_missing_anchor_directory_is_created_before_the_retire(tmp_path, mode):
    """З-9: without the directory Docker would create it as root for the bind
    mount; reset/fclean create it first (scripts/anchor_dir.sh: 700 + ACL)."""
    anchors = tmp_path / "gone" / "audit_anchors"
    done, calls = _make_with_stub(tmp_path, mode, "fclean", "CONFIRM=yes", anchors=anchors)
    assert done.returncode == 0, done.stdout + done.stderr
    assert anchors.is_dir() and anchors.stat().st_uid == os.getuid()
    assert stat.S_IMODE(anchors.stat().st_mode) & 0o077 in (0, 0o070)   # 700, or 770 shown as the ACL mask
    if shutil.which("getfacl") and shutil.which("setfacl"):
        acl = subprocess.run(["getfacl", "-cpn", str(anchors)], capture_output=True, text=True).stdout.split()
        assert "user:10002:rwx" in acl and "other::---" in acl and "group::---" in acl, acl
    assert "created " in done.stdout and "anchor_dir.sh --strict" in done.stdout
    retire = next(i for i, c in enumerate(calls) if "--retire" in c)
    assert calls[retire + 1] == "anchors-present"          # the directory was there before the retire


def test_anchor_directory_that_cannot_be_made_fails_closed(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    done, calls = _make_with_stub(tmp_path, "volume", "fclean", "CONFIRM=yes", anchors=blocker / "audit_anchors")
    assert done.returncode != 0
    assert "cannot prepare the anchor directory" in done.stderr and "nothing was deleted" in done.stderr
    assert "proxy and api are stopped" in done.stderr
    assert not any("--retire" in c or c.startswith("down") for c in calls), calls


def test_anchor_directory_without_acl_access_fails_closed_in_strict_mode(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root can chown instead")
    work = tmp_path / "w"
    env = dict(os.environ, PATH=_path_without(tmp_path, "setfacl"))
    done = subprocess.run(["sh", str(ROOT / "scripts" / "anchor_dir.sh"), "--strict", str(work)],
                          env=env, capture_output=True, text=True)
    assert done.returncode == 1 and "cannot grant write access" in done.stderr
    loose = subprocess.run(["sh", str(ROOT / "scripts" / "anchor_dir.sh"), str(tmp_path / "w2")],
                           env=env, capture_output=True, text=True)
    assert loose.returncode == 0 and "cannot grant write access" in loose.stderr   # init_secrets: a warning


RETIRE_HARNESS = r"""
import os, sys
from pathlib import Path
root = Path(os.environ["STUB_ROOT"])
sys.path.insert(0, str(root))
sys.path.insert(0, str(root / "audit"))
from tests.audit_fake import FakeSource, KEY
import anchor
src = FakeSource(chain_id="11111111-2222-4333-8444-555555555555", rows=int(os.environ["STUB_ROWS"]))
sys.exit(anchor.retire(KEY, "--force" in sys.argv, "--offline" in sys.argv,
                       Path(os.environ["STUB_ANCHORS"]), lambda: (src, lambda: None)))
"""


@pytest.mark.parametrize("mode", ["running", "volume"])
def test_reset_without_registry_but_a_chain_refuses_unless_forced(tmp_path, mode, monkeypatch):
    """З-10 through make: the anchor directory is empty (renamed and recreated),
    the database holds a chain (fake journal, real anchor.retire)."""
    harness = tmp_path / "harness.py"
    harness.write_text(RETIRE_HARNESS)
    for name, value in (("STUB_HARNESS", str(harness)), ("STUB_PYTHON", sys.executable),
                        ("STUB_ROOT", str(ROOT)), ("STUB_ROWS", "5")):
        monkeypatch.setenv(name, value)
    anchors = tmp_path / "anchors"
    for target in ("fclean", "reset"):
        done, calls = _make_with_stub(tmp_path, mode, target, "CONFIRM=yes")
        assert done.returncode != 0, done.stdout
        assert "retire refused: no chain registry" in done.stdout
        assert "nothing was deleted" in done.stderr and "brings the stand back" in done.stderr
        assert not any(c.startswith("down") or c.startswith("up") for c in calls), calls
        assert not (anchors / cl.REGISTRY).exists()
    done, calls = _make_with_stub(tmp_path, mode, "fclean", "CONFIRM=yes", "RETIRE_FORCE=yes")
    assert done.returncode == 0, done.stdout + done.stderr
    assert any(c.startswith("down -v") for c in calls)
    entries, _ = cl.parse_registry(anchors / cl.REGISTRY, KEY)
    assert [(e.kind, e.mode, e.brk) for e in entries] == [("retire", "forced", "no_registry@-")]


def test_reset_without_registry_and_an_empty_chain_passes(tmp_path, monkeypatch):
    harness = tmp_path / "harness.py"
    harness.write_text(RETIRE_HARNESS)
    for name, value in (("STUB_HARNESS", str(harness)), ("STUB_PYTHON", sys.executable),
                        ("STUB_ROOT", str(ROOT)), ("STUB_ROWS", "0")):
        monkeypatch.setenv(name, value)
    done, calls = _make_with_stub(tmp_path, "volume", "fclean", "CONFIRM=yes")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "empty journal, nothing to close" in done.stdout
    assert any(c.startswith("down -v") for c in calls)


@pytest.mark.skipif(os.geteuid() == 0, reason="root may own anything")
@pytest.mark.parametrize("setup, message", [
    ("foreign_owner", "belongs to uid"),
    ("extra_acl", "is not 700 + ACL u:10002:rwx"),
])
def test_anchor_directory_with_a_wrong_owner_or_acl_stops_make(tmp_path, setup, message):
    """З-10 (small): an existing directory owned by someone else (root 755 after
    Docker made it) or with extra ACL entries stops reset/fclean before the retire."""
    if not (shutil.which("getfacl") and shutil.which("setfacl")):
        pytest.skip("needs the acl tools")
    if setup == "foreign_owner":
        anchors = Path("/")            # exists, owned by root, 755
    else:
        anchors = tmp_path / "anchors"
        anchors.mkdir(mode=0o700)
        subprocess.run(["setfacl", "-m", "u:10002:rwx,g:" + str(os.getgid()) + ":r-x", str(anchors)], check=True)
    done, calls = _make_with_stub(tmp_path, "volume", "fclean", "CONFIRM=yes", anchors=anchors)
    assert done.returncode != 0
    assert message in done.stderr and "cannot prepare the anchor directory" in done.stderr
    assert "nothing was deleted" in done.stderr
    assert not any("--retire" in c or c.startswith("down") for c in calls), calls


def test_makefile_run_has_no_no_build_flag():
    # Н-1: "docker compose run" has no --no-build (Compose 2.32 and 5.x reject it)
    text = (ROOT / "Makefile").read_text()
    for line in text.splitlines():
        if " run " in line:
            assert "--no-build" not in line, line


def test_failed_retire_stops_before_down(tmp_path):
    for mode in ("running", "volume", "none"):
        done, calls = _make_with_stub(tmp_path, mode, "fclean", "CONFIRM=yes", rc=2)
        assert done.returncode != 0, mode
        assert not any(c.startswith("down") for c in calls), (mode, calls)
        # З-4: proxy and api stay stopped; the message says how to get them back
        assert "nothing was deleted" in done.stderr, (mode, done.stderr)
        assert "proxy and api are stopped" in done.stderr and "start COMPOSE=" in done.stderr, mode


def test_forced_retire_passes_force_and_falls_back_offline(tmp_path):
    done, calls = _make_with_stub(tmp_path, "running", "fclean", "CONFIRM=yes", "RETIRE_FORCE=yes")
    assert done.returncode == 0
    assert [c.strip() for c in calls if "--retire" in c] == ["exec -T audit_anchor python anchor.py --retire --force"]
    done, calls = _make_with_stub(tmp_path, "volume", "fclean", "CONFIRM=yes", "RETIRE_FORCE=yes", rc=3)
    assert done.returncode != 0      # the stub also fails the offline retire
    assert "RETIRE_FORCE=yes -> offline forced" in done.stdout
    assert [c.strip() for c in calls if "--retire" in c] == [
        "run --rm audit_anchor python anchor.py --retire --force",
        "run --rm --no-deps audit_anchor python anchor.py --retire --offline"]
    assert not any(c.startswith("down") for c in calls)


# --- E6 guard (§10.1 П-3c.2): never the main anchor directory or another stand -------

def _e6_module():
    sys.path.insert(0, str(ROOT / "experiments"))
    import e6_tamper
    return e6_tamper


@pytest.mark.parametrize("anchor, port, ok", [
    ("./audit_anchors_e6/20261116-1910", 8456, True),
    ("./audit_anchors", 8456, False),
    ("./audit_anchors/inner", 8456, False),
    ("", 8456, False),
    ("./audit_anchors_e6/x", 8452, False),
    ("./audit_anchors_e6/x", 8453, False),
])
def test_unit_e6_guard_refuses_the_main_anchor_dir_and_other_stands(tmp_path, anchor, port, ok):
    e6 = _e6_module()
    env = tmp_path / ".env.e6"
    env.write_text(f"CLINIC_AUDIT_ANCHOR_DIR={anchor}\nCLINIC_PROXY_PORT=8086\nCLINIC_PROXY_TLS_PORT={port}\n")
    if ok:
        e6.guard(env)
    else:
        with pytest.raises(SystemExit):
            e6.guard(env)
