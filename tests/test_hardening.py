"""15_hardening: POST /register rate limit and reschedule limits (one event per
move, daily patient limit, two-key advisory lock)."""
import os
import re
import subprocess
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

import httpx

from tests.csrf_client import CsrfClient
from tests.registration import (
    MAILPIT,
    clear_registration_attempts,
    registration_form,
    registration_limit_reset,  # noqa: F401 (autouse)
)
from tests.test_ux_filters import (
    ADMIN,
    DOC,
    PAT,
    PAT2,
    REG,
    _Setup,
    _as_role,
    _book_sql,
    _login,
    _post_reschedule,
    _psql,
    _psql_try,
    _reschedule_events,
    _run_migrate,
    _status,
    _user_id,
    age_patient_reschedules,
    patient_reschedule_limit_reset,  # noqa: F401 (autouse)
)

ROOT = Path(__file__).resolve().parents[1]
BASE = os.environ.get("CLINIC_TEST_BASE", "http://localhost:8080")
REG_PASSWORD = "Limit-Check-2026!"
CSRF_VALUE = re.compile(r'name="csrf_token" value="[^"]*"')


# --- 1. Registration rate limit ----------------------------------------------

def _client(follow_redirects: bool = True):
    return CsrfClient(base_url=BASE, follow_redirects=follow_redirects, timeout=15.0)


def _prefix() -> str:
    return f"reglimit-{uuid.uuid4().hex[:10]}"


def _attempts() -> int:
    return int(_psql("SELECT count(*) FROM registration_attempts")[0])


def _drop_users(like: str) -> None:
    _psql(
        f"DELETE FROM audit_events WHERE actor_user_id IN (SELECT id FROM users WHERE email LIKE '{like}') "
        f"OR (target_type IN ('user', 'patient') AND target_id IN (SELECT id FROM users WHERE email LIKE '{like}')); "
        f"DELETE FROM users WHERE email LIKE '{like}'"
    )


def _mails_to(address: str) -> int:
    found = httpx.get(f"{MAILPIT}/api/v1/search", params={"query": f'to:"{address}"'}, timeout=5)
    found.raise_for_status()
    return len(found.json().get("messages") or [])


def _register(c, email: str, password: str = REG_PASSWORD, **kwargs) -> httpx.Response:
    return c.post("/register", data=registration_form(email, password), **kwargs)


def _registration_events(mark: int) -> list[str]:
    return _psql(
        "SELECT actor_role || '|' || coalesce(actor_user_id::text, '') || '|' || "
        "coalesce(target_id::text, '') || '|' || coalesce(source, '') FROM audit_events "
        f"WHERE id > {mark} AND action = 'auth.rate_limited' AND reason = 'registration'"
    )


def _mark() -> int:
    return int(_psql("SELECT coalesce(max(id), 0) FROM audit_events")[0])


def test_source_limit_twenty_then_429_same_for_any_email_and_one_event():
    prefix = _prefix()
    httpx.delete(f"{MAILPIT}/api/v1/messages", timeout=5)
    # earlier runs inside 15 minutes would hide the event (record_auth_event dedup)
    _psql("DELETE FROM audit_events WHERE action = 'auth.rate_limited' AND reason = 'registration'")
    mark = _mark()
    try:
        with _client(follow_redirects=False) as c:
            for index in range(20):
                done = _register(c, f"{prefix}-{index}@example.com")
                assert done.status_code == 303, (index, done.status_code)
                assert "registered=1" in done.headers["location"]
            over = f"{prefix}-over@example.com"
            refused = _register(c, over)
            assert refused.status_code == 429
            assert refused.headers["retry-after"] == "900"
            assert "Too many registration attempts" in refused.text
            assert over not in refused.text
            assert _psql(f"SELECT count(*) FROM users WHERE email = '{over}'") == ["0"]
            assert _mails_to(over) == 0
            # (10) the refused attempt is not stored
            assert _attempts() == 20
            # (2) existing and new email: the same 429 body, never 409
            existing = _register(c, PAT)
            fresh = _register(c, f"{prefix}-fresh@example.com")
            assert existing.status_code == fresh.status_code == 429
            assert CSRF_VALUE.sub("", existing.text) == CSRF_VALUE.sub("", fresh.text)
            assert existing.headers["retry-after"] == fresh.headers["retry-after"] == "900"
            assert _attempts() == 20
        # (4) exactly one anonymous rate_limited event, no email in it
        events = _registration_events(mark)
        assert len(events) == 1, events
        role, actor, target, source = events[0].split("|")
        assert role == "anonymous" and actor == "" and target == ""
        assert source and "@" not in source
        row = _psql(
            f"SELECT row_to_json(a)::text FROM audit_events a WHERE id > {mark} "
            "AND action = 'auth.rate_limited' AND reason = 'registration'"
        )[0]
        assert prefix not in row and PAT not in row
        assert _psql(f"SELECT count(*) FROM users WHERE email LIKE '{prefix}-%'") == ["20"]
    finally:
        _drop_users(f"{prefix}-%")
        clear_registration_attempts()


def test_email_limit_five_per_day():
    prefix = _prefix()
    email = f"{prefix}@example.com"
    try:
        with _client(follow_redirects=False) as c:
            codes = [_register(c, email).status_code for _ in range(6)]
        assert codes == [303, 303, 303, 303, 303, 429], codes
        assert _attempts() == 5
    finally:
        _drop_users(email)
        clear_registration_attempts()


def test_registration_attempts_store_only_hashes_and_have_no_grants():
    prefix = _prefix()
    email = f"{prefix}@example.com"
    try:
        with _client(follow_redirects=False) as c:
            assert _register(c, email).status_code == 303
        assert _psql(
            "SELECT count(*), bool_and(length(email_fingerprint) = 32 AND length(source_fingerprint) = 32), "
            f"bool_or(position(convert_to('{prefix}', 'UTF8') in email_fingerprint) > 0) "
            "FROM registration_attempts"
        ) == ["1|t|f"]
        assert _psql(
            "SELECT count(*) FROM registration_attempts "
            f"WHERE email_fingerprint = public.digest('{email}', 'sha256')"
        ) == ["1"]
        for role in ("app_guest", "app_patient", "clinic_api"):
            for sql in (
                "SELECT count(*) FROM public.registration_attempts",
                "INSERT INTO public.registration_attempts (email_fingerprint, source_fingerprint) "
                "VALUES ('\\x00', '\\x00')",
            ):
                denied = _as_role(role, 0, sql)
                assert denied.returncode != 0 and "permission denied" in denied.stderr, (role, sql)
        for role in ("app_guest", "app_patient", "app_admin"):
            denied = _as_role(role, 0, "SELECT public.note_registration_attempt('x@example.com', '1.2.3.4')")
            assert denied.returncode != 0 and "permission denied" in denied.stderr, role
        definition = _psql(
            "SELECT p.prosecdef::text || '|' || array_to_string(p.proconfig, ',') "
            "FROM pg_proc p WHERE p.proname = 'note_registration_attempt'"
        )
        assert definition == ["true|search_path=pg_catalog, public, pg_temp"], definition
        grantees = _psql(
            "SELECT grantee FROM information_schema.routine_privileges "
            "WHERE routine_name = 'note_registration_attempt' AND privilege_type = 'EXECUTE' "
            "AND grantee <> 'clinic' ORDER BY 1"
        )
        assert grantees == ["clinic_api"], grantees
    finally:
        _drop_users(email)
        clear_registration_attempts()


def test_spoofed_forwarding_headers_do_not_reset_registration_limit():
    prefix = _prefix()
    try:
        with _client(follow_redirects=False) as c:
            for index in range(20):
                assert _register(c, f"{prefix}-{index}@example.com").status_code == 303
            for index in range(3):
                fake = f"198.51.100.{index + 1}"
                refused = _register(
                    c, f"{prefix}-spoof{index}@example.com",
                    headers={"X-Real-IP": fake, "X-Forwarded-For": fake, "Forwarded": f"for={fake}"},
                )
                assert refused.status_code == 429, refused.status_code
    finally:
        _drop_users(f"{prefix}-%")
        clear_registration_attempts()


def test_get_invalid_form_and_missing_csrf_are_not_counted():
    with _client(follow_redirects=False) as c:
        for _ in range(30):
            assert c.get("/register").status_code == 200
        assert _attempts() == 0
        for index in range(20):
            short = c.post("/register", data=registration_form(f"short{index}@example.com", "short"))
            assert short.status_code == 400
        assert _attempts() == 0
        no_token = c.post("/register", data=registration_form("nocsrf@example.com", REG_PASSWORD), csrf=False)
        assert no_token.status_code == 403
        assert _attempts() == 0
    assert _psql("SELECT count(*) FROM users WHERE email = 'nocsrf@example.com'") == ["0"]


def _reason_check() -> tuple[str, str]:
    oid, definition = _psql(
        "SELECT oid, pg_get_constraintdef(oid) FROM pg_constraint "
        "WHERE conname = 'audit_events_reason_check'"
    )[0].split("|", 1)
    return oid, definition


def test_reason_check_rebuilt_only_when_registration_is_missing():
    oid, definition = _reason_check()
    assert "'registration'" in definition
    _run_migrate()
    assert _reason_check() == (oid, definition)
    # an old volume: the CHECK without 'registration' is rebuilt once
    _psql(
        "DELETE FROM audit_events WHERE reason = 'registration'; "
        "ALTER TABLE audit_events DROP CONSTRAINT audit_events_reason_check; "
        "ALTER TABLE audit_events ADD CONSTRAINT audit_events_reason_check "
        "CHECK (reason IS NULL OR reason IN ('bad_credentials', 'blocked', 'login', 'password_reset', "
        "'email_change', 'idle_timeout', 'absolute_timeout', 'unverified', 'email_verification'))"
    )
    old_oid, old_definition = _reason_check()
    assert "'registration'" not in old_definition
    _run_migrate()
    new_oid, new_definition = _reason_check()
    assert new_oid != old_oid and "'registration'" in new_definition
    _run_migrate()
    assert _reason_check() == (new_oid, new_definition)


def test_registration_limit_db_failure_fails_closed_with_503():
    """Static check of the 503 branch; the live REVOKE check is manual on the fixer stack."""
    source = (ROOT / "app" / "routes_auth.py").read_text()
    body = source[source.index("def register(\n"):source.index('@router.post("/login")')]
    start = body.index("    try:\n        conn = db()")
    branch = body[start:body.index("    if limited:")]
    assert "public.note_registration_attempt(%s, %s)" in branch
    assert "client_ip(request)" in branch
    assert "except psycopg2.Error:" in branch
    assert "Registration is temporarily unavailable. Try again later." in branch
    assert 'response.headers["Retry-After"] = "60"' in branch
    assert "503" in branch
    assert "pwd.hash" not in branch and "register_patient" not in branch
    log_line = next(line for line in branch.splitlines() if "log.exception" in line)
    assert "email" not in log_line
    # the limit runs before bcrypt and register_patient
    limit_at = body.index("note_registration_attempt")
    assert limit_at < body.index("pwd.hash(") and limit_at < body.index("public.register_patient(")
    assert body.index("Passwords do not match") < body.index("note_registration_attempt")


# --- 3. Reschedule: one event per move, daily patient limit, own lock space ---

FAKE_BASE = 2_100_000_000
LIMIT_TEXT = "You can reschedule up to 3 times a day."


@contextmanager
def _pat_client():
    with _client() as c:
        _login(c, PAT)
        yield c


def _current_visit(s) -> int:
    ids = ",".join(str(i) for i in s.slots + s.extra_slots)
    rows = _psql(f"SELECT id FROM appointments WHERE slot_id IN ({ids}) AND status = 'scheduled' "
                 f"AND patient_user_id = {s.patient} ORDER BY id DESC")
    return int(rows[0])


def _fake_events(actor_id: int, role: str, count: int) -> None:
    """count reschedule events of actor_id made just now, on ids no visit has."""
    base = FAKE_BASE + int(uuid.uuid4().int % 1_000_000) * 10
    _psql(
        "INSERT INTO audit_events (actor_user_id, actor_role, action, target_type, target_id, "
        "old_value, new_value) "
        f"SELECT {actor_id}, '{role}', 'appointment.reschedule', 'appointment', {base} + 2 * g + 1, "
        f"{base} + 2 * g, {base} + 2 * g + 1 FROM generate_series(0, {count - 1}) AS g"
    )


def _drop_fake_events() -> None:
    _psql(f"DELETE FROM audit_events WHERE action = 'appointment.reschedule' AND old_value >= {FAKE_BASE}")


def _own_count(role: str, user_id: int) -> subprocess.CompletedProcess:
    """stdout is only the count (the set_config line of _as_role is dropped)."""
    result = _as_role(role, user_id, "SELECT public.own_reschedules_last_day()")
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    result.stdout = lines[-1] if len(lines) > 1 else ""
    return result


def _rescheduled_mails() -> int:
    found = httpx.get(f"{MAILPIT}/api/v1/search",
                      params={"query": f'to:"{PAT}" subject:"Appointment rescheduled"'}, timeout=5)
    found.raise_for_status()
    return len(found.json().get("messages") or [])


def _hand_move_sql(patient: int, old_id: int, slot_id: int, tail: str = "") -> str:
    """One transaction as app_patient: cancel, insert, journal call (what the app does)."""
    return (
        f"BEGIN; SET LOCAL ROLE app_patient; SELECT set_config('app.user_id', '{patient}', true); "
        f"UPDATE appointments SET status = 'cancelled' WHERE id = {old_id}; "
        "INSERT INTO appointments (slot_id, patient_user_id, doctor_id, starts_at, ends_at, reserved_ends_at) "
        f"SELECT s.id, {patient}, s.doctor_id, s.starts_at, "
        "s.starts_at + make_interval(mins => s.duration_minutes), s.ends_at "
        f"FROM slots s WHERE s.id = {slot_id}; "
        "SELECT public.record_appointment_reschedule("
        f"{old_id}, (SELECT max(id) FROM appointments WHERE slot_id = {slot_id})); {tail}"
    )


def test_hand_made_pair_cannot_be_reported_as_a_move():
    """R3-1: cancel A and book B through the UI, then call the journal function."""
    s = _Setup()
    try:
        with _pat_client() as pat:
            cancelled = pat.post(f"/appointments/{s.old}/cancel")
            assert cancelled.status_code == 200 and _status(s.old) == "cancelled"
            booked = pat.post(f"/slots/{s.targets[0]}/book")
            assert "booked=1" in str(booked.url), booked.url
        new = _current_visit(s)
        forged = _as_role("app_patient", s.patient,
                          f"SELECT public.record_appointment_reschedule({s.old}, {new})")
        assert forged.returncode != 0 and "reschedule pair is not allowed" in forged.stderr, forged.stderr
        assert [e for e in _reschedule_events(s.old) if "reschedule" in e] == []
    finally:
        s.cleanup()


def test_http_move_writes_one_event_and_a_repeat_call_is_refused():
    s = _Setup()
    try:
        with _pat_client() as pat:
            done = _post_reschedule(pat, s.old, s.targets[0])
            assert "rescheduled=1" in str(done.url), done.url
        new = _current_visit(s)
        assert len(_reschedule_events(s.old, new)) == 1
        again = _as_role("app_patient", s.patient,
                         f"SELECT public.record_appointment_reschedule({s.old}, {new})")
        assert again.returncode != 0
        assert "not allowed" in again.stderr or "duplicate key" in again.stderr, again.stderr
        assert len(_reschedule_events(s.old, new)) == 1
    finally:
        s.cleanup()


def test_unique_indexes_exist_and_refuse_a_duplicate_event():
    names = _psql("SELECT indexname FROM pg_indexes WHERE tablename = 'audit_events' "
                  "AND indexname LIKE 'audit_events_reschedule_%' ORDER BY 1")
    assert names == ["audit_events_reschedule_actor_idx", "audit_events_reschedule_new_unique",
                     "audit_events_reschedule_old_unique"], names
    reg = _user_id(REG)
    try:
        _fake_events(reg, "registrar", 1)
        old_value, new_value = _psql(
            "SELECT old_value || '|' || new_value FROM audit_events "
            f"WHERE action = 'appointment.reschedule' AND old_value >= {FAKE_BASE}")[0].split("|")
        for old_v, new_v in ((old_value, int(new_value) + 100), (int(old_value) + 100, new_value)):
            dup = _psql_try(
                "INSERT INTO audit_events (actor_user_id, actor_role, action, target_type, target_id, "
                f"old_value, new_value) VALUES ({reg}, 'registrar', 'appointment.reschedule', "
                f"'appointment', {new_v}, {old_v}, {new_v})"
            )
            assert dup.returncode != 0 and "duplicate key value violates unique constraint" in dup.stderr
    finally:
        _drop_fake_events()


def _migrate_output() -> str:
    completed = subprocess.run(
        ["docker", "compose", "run", "--rm", "--no-deps", "-T", "migrate"],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    return completed.stdout + completed.stderr


def _index_oid(name: str) -> str:
    return _psql(f"SELECT coalesce(to_regclass('public.{name}')::oid::text, 'none')")[0]


def test_old_volume_with_duplicates_starts_and_index_comes_back():
    reg = _user_id(REG)
    try:
        _psql("DROP INDEX public.audit_events_reschedule_old_unique")
        base = FAKE_BASE + 5
        _psql(
            "INSERT INTO audit_events (actor_user_id, actor_role, action, target_type, target_id, "
            f"old_value, new_value) VALUES "
            f"({reg}, 'registrar', 'appointment.reschedule', 'appointment', {base} + 1, {base}, {base} + 1), "
            f"({reg}, 'registrar', 'appointment.reschedule', 'appointment', {base} + 3, {base}, {base} + 3)"
        )
        output = _migrate_output()
        assert "duplicate appointment.reschedule old_value, unique index skipped" in output
        assert _index_oid("audit_events_reschedule_old_unique") == "none"
        new_oid = _index_oid("audit_events_reschedule_new_unique")
        assert new_oid != "none"
        _drop_fake_events()
        _migrate_output()
        old_oid = _index_oid("audit_events_reschedule_old_unique")
        assert old_oid != "none"
        _migrate_output()
        assert _index_oid("audit_events_reschedule_old_unique") == old_oid
        assert _index_oid("audit_events_reschedule_new_unique") == new_oid
    finally:
        _drop_fake_events()
        if _index_oid("audit_events_reschedule_old_unique") == "none":
            _run_migrate()


def test_patient_daily_limit_three_moves_then_too_many_and_again_after_a_day():
    httpx.delete(f"{MAILPIT}/api/v1/messages", timeout=5)
    s = _Setup(times=("09:00", "10:00", "11:00", "12:00", "13:00", "14:00"))
    try:
        with _pat_client() as pat:
            current = s.old
            for target in s.targets[:3]:
                done = _post_reschedule(pat, current, target)
                assert "rescheduled=1" in str(done.url), done.url
                current = _current_visit(s)
            assert int(_psql(f"SELECT count(*) FROM audit_events WHERE action = 'appointment.reschedule' "
                             f"AND actor_user_id = {s.patient} "
                             "AND created_at > CURRENT_TIMESTAMP - INTERVAL '24 hours'")[0]) == 3
            assert _rescheduled_mails() == 3
            form = pat.get(f"/appointments/{current}/reschedule", params={"day": s.day, "view": "day"})
            assert LIMIT_TEXT in form.text
            refused = pat.post(f"/appointments/{current}/reschedule", data={"slot_id": str(s.targets[3])},
                               follow_redirects=False)
            assert refused.status_code == 303
            assert refused.headers["location"] == f"/appointments/{current}/reschedule?error=too_many"
            page = pat.get(refused.headers["location"])
            assert LIMIT_TEXT in page.text
            assert _status(current) == "scheduled" and _current_visit(s) == current
            assert _rescheduled_mails() == 3
            # a day later the patient may move again
            age_patient_reschedules()
            again = _post_reschedule(pat, current, s.targets[3])
            assert "rescheduled=1" in str(again.url), again.url
            assert _status(current) == "cancelled"
            assert _rescheduled_mails() == 4
    finally:
        s.cleanup()


def test_registrar_is_not_limited_and_does_not_use_the_patient_limit():
    s = _Setup(times=("09:00", "10:00", "11:00", "12:00", "13:00", "14:00"))
    try:
        with _client() as reg:
            _login(reg, REG)
            current = s.old
            for target in s.targets:
                done = _post_reschedule(reg, current, target)
                assert "rescheduled=1" in str(done.url), done.url
                current = _current_visit(s)
        assert len([e for e in _psql(
            "SELECT id FROM audit_events WHERE action = 'appointment.reschedule' "
            f"AND actor_user_id = {_user_id(REG)} AND created_at > CURRENT_TIMESTAMP - INTERVAL '1 minute'"
        )]) >= 5
        own = _own_count("app_patient", s.patient)
        assert own.returncode == 0 and own.stdout.strip() == "0", own.stdout + own.stderr
        with _pat_client() as pat:
            form = pat.get(f"/appointments/{current}/reschedule", params={"day": s.day, "view": "day"})
            assert form.status_code == 200 and LIMIT_TEXT not in form.text
    finally:
        s.cleanup()


def test_database_layer_refuses_the_fourth_move_in_a_proper_transaction():
    s = _Setup()
    try:
        _fake_events(s.patient, "patient", 3)
        result = _psql_try(_hand_move_sql(s.patient, s.old, s.targets[0], "COMMIT;"))
        assert result.returncode != 0 and "reschedule limit reached" in result.stderr, result.stderr
        assert _status(s.old) == "scheduled"
        assert _psql(f"SELECT count(*) FROM appointments WHERE slot_id = {s.targets[0]}") == ["0"]
        # control: with fewer than 3 the same transaction is accepted (then rolled back)
        _drop_fake_events()
        ok = _psql_try(_hand_move_sql(s.patient, s.old, s.targets[0], "ROLLBACK;"))
        assert ok.returncode == 0, ok.stderr
    finally:
        _drop_fake_events()
        s.cleanup()


def test_own_reschedules_last_day_is_patient_only_and_own_only():
    pat, pat2 = _user_id(PAT), _user_id(PAT2)
    try:
        _fake_events(pat2, "patient", 2)
        assert _own_count("app_patient", pat).stdout.strip() == "0"
        assert _own_count("app_patient", pat2).stdout.strip() == "2"
        for role, email in (("app_registrar", REG), ("app_doctor", DOC), ("app_admin", ADMIN)):
            denied = _own_count(role, _user_id(email))
            assert denied.returncode != 0 and "permission denied" in denied.stderr, role
        guest = _own_count("app_guest", 0)
        assert guest.returncode != 0 and "permission denied" in guest.stderr
        grantees = _psql(
            "SELECT grantee FROM information_schema.routine_privileges "
            "WHERE routine_name = 'own_reschedules_last_day' AND privilege_type = 'EXECUTE' "
            "AND grantee <> 'clinic' ORDER BY 1"
        )
        assert grantees == ["app_patient"], grantees
    finally:
        _drop_fake_events()


def test_foreign_visit_with_exhausted_limit_gets_the_generic_refusal():
    other = _Setup(patient=PAT2)
    try:
        _fake_events(_user_id(PAT), "patient", 3)
        with _pat_client() as pat:
            refused = pat.post(f"/appointments/{other.old}/reschedule",
                               data={"slot_id": str(other.targets[0])}, follow_redirects=False)
            assert refused.headers["location"] == "/my?reschedule_error=1"
            garbage = pat.post("/appointments/2147000000/reschedule",
                               data={"slot_id": str(other.targets[0])}, follow_redirects=False)
            assert garbage.headers["location"] == "/my?reschedule_error=1"
        assert _status(other.old) == "scheduled"
    finally:
        _drop_fake_events()
        other.cleanup()


class _Holder:
    """A superuser psql session that holds the patient's two-key advisory lock."""

    def __init__(self, patient: int):
        self.proc = subprocess.Popen(
            ["docker", "compose", "exec", "-T", "db", "psql", "-X", "-q", "-U", "clinic", "-d", "clinic"],
            cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.proc.stdin.write(f"SELECT pg_advisory_lock(1, {patient});\n")
        self.proc.stdin.flush()

    def release(self):
        if self.proc.poll() is not None:
            return
        try:
            self.proc.communicate("SELECT pg_advisory_unlock_all();\n\\q\n", timeout=20)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def _waiting_on(patient: int) -> list[str]:
    return _psql(
        "SELECT l.classid || '|' || l.objid || '|' || l.objsubid FROM pg_locks l "
        f"WHERE l.locktype = 'advisory' AND NOT l.granted AND l.classid = 1 AND l.objid = {patient}"
    )


def test_booking_and_reschedule_wait_on_the_two_key_patient_lock():
    s = _Setup()
    try:
        patient = s.patient
        for action in ("book", "reschedule"):
            holder = _Holder(patient)
            results = {}
            try:
                deadline = time.time() + 15
                while time.time() < deadline and not _psql(
                    f"SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND granted "
                    f"AND classid = 1 AND objid = {patient} AND objsubid = 2"
                ):
                    time.sleep(0.2)
                with _pat_client() as pat:
                    def run():
                        if action == "book":
                            results["r"] = pat.post(f"/slots/{s.targets[1]}/book")
                        else:
                            results["r"] = _post_reschedule(pat, _current_visit(s), s.targets[2])
                    thread = threading.Thread(target=run)
                    thread.start()
                    waiting = []
                    deadline = time.time() + 15
                    while time.time() < deadline and not waiting:
                        waiting = _waiting_on(patient)
                        time.sleep(0.2)
                    assert waiting == [f"1|{patient}|2"], (action, waiting)
                    holder.release()
                    thread.join(30)
                assert results["r"].status_code == 200, (action, results["r"].status_code)
            finally:
                holder.release()
        assert len([e for e in _reschedule_events(s.old) if "reschedule" in e]) <= 1
    finally:
        s.cleanup()


def test_limit_constant_is_the_same_in_python_and_sql():
    source = (ROOT / "app" / "routes_booking.py").read_text()
    python_limit = int(re.search(r"^RESCHEDULE_DAILY_LIMIT = (\d+)$", source, re.M).group(1))
    definition = "\n".join(_psql(
        "SELECT pg_get_functiondef('public.record_appointment_reschedule(integer, integer)'::regprocedure)"
    ))
    sql_limit = int(re.search(r"INTERVAL '24 hours'\s*\)\s*>=\s*(\d+)", definition).group(1))
    assert python_limit == sql_limit == 3
    assert "pg_advisory_xact_lock(1::int, old_row.patient_user_id::int)" in definition
    assert definition.index("pg_advisory_xact_lock") < definition.index("reschedule limit reached")
    assert definition.index("row_xmin IS DISTINCT FROM") < definition.index("INSERT INTO public.audit_events")
    assert "PATIENT_LOCK_CLASS = 1" in source
    assert source.count("pg_advisory_xact_lock(%s::int, %s::int)") == 2
    assert "pg_advisory_xact_lock(%s)\"" not in source


def test_parallel_hand_moves_at_two_events_let_only_one_through():
    """Б4: the count runs under the patient lock, so two parallel transactions cannot both pass."""
    s = _Setup(times=("10:00", "12:00", "13:00", "14:00"))
    second_old = _book_sql(s.targets[0], s.patient)
    try:
        _fake_events(s.patient, "patient", 2)
        results = [None, None]
        barrier = threading.Barrier(2)

        def run(index, old_id, slot_id):
            barrier.wait()
            results[index] = _psql_try(_hand_move_sql(s.patient, old_id, slot_id,
                                                      "SELECT pg_sleep(1); COMMIT;"))

        threads = [threading.Thread(target=run, args=(0, s.old, s.targets[1])),
                   threading.Thread(target=run, args=(1, second_old, s.targets[2]))]
        for t in threads:
            t.start()
        for t in threads:
            t.join(60)
        codes = sorted(r.returncode for r in results)
        assert codes[0] == 0 and codes[1] != 0, [(r.returncode, r.stderr) for r in results]
        failed = next(r for r in results if r.returncode != 0)
        assert "reschedule limit reached" in failed.stderr, failed.stderr
        assert _psql(
            "SELECT count(*) FROM audit_events WHERE action = 'appointment.reschedule' "
            f"AND actor_user_id = {s.patient} AND created_at > CURRENT_TIMESTAMP - INTERVAL '24 hours'"
        ) == ["3"]
    finally:
        _drop_fake_events()
        s.cleanup()
