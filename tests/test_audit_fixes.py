"""Fixes from the security audit: read journal on /my, auth events, time-off overlap."""
import os
import re
import subprocess
import uuid
from pathlib import Path

from tests.clinical_notes import (
    NOTE_DOCTOR1_PATIENT_A,
    cleanup_cross_doctor_notes,
    insert_cross_doctor_notes,
)
from tests.csrf_client import CsrfClient
from tests.demo_secret import demo_password
from tests.field_key import seal_pending, sql_packet

ROOT = Path(__file__).resolve().parents[1]
BASE = os.environ.get("CLINIC_TEST_BASE", "http://localhost:8080")
PASSWORD = demo_password()
PAT = "pat@clinic.local"
PAT2 = "pat2@clinic.local"


def _client(**kwargs):
    return CsrfClient(base_url=BASE, follow_redirects=True, timeout=10.0, **kwargs)


def _psql(sql: str) -> list[str]:
    completed = subprocess.run(
        ["docker", "compose", "exec", "-T", "db", "psql", "-X", "-U", "clinic", "-d", "clinic",
         "-v", "ON_ERROR_STOP=1", "-At", "-F", "|", "-c", sql],
        cwd=ROOT, capture_output=True, text=True,
    )
    seal_pending()
    assert completed.returncode == 0, completed.stderr or completed.stdout
    return [line for line in completed.stdout.splitlines() if line.strip()]


def _user_id(email: str) -> int:
    return int(_psql(f"SELECT id FROM users WHERE email = '{email}'")[0])


def _records_views(user_id: int) -> int:
    return int(_psql(
        "SELECT count(*) FROM audit_events "
        f"WHERE action = 'medical.records.view' AND actor_user_id = {user_id}"
    )[0])


def _login(c, email):
    page = c.post("/login", data={"email": email, "password": PASSWORD})
    assert page.status_code == 200 and "/me" in str(page.url), email
    return page


def test_my_page_logs_one_records_view_only_when_it_shows_records():
    cleanup_cross_doctor_notes()
    pat_id, pat2_id = _user_id(PAT), _user_id(PAT2)
    assert _psql(
        f"SELECT (SELECT count(*) FROM visit_notes WHERE patient_user_id = {pat2_id})"
        f" + (SELECT count(*) FROM prescriptions WHERE patient_user_id = {pat2_id})"
    ) == ["0"]
    try:
        with _client() as c:
            _login(c, PAT2)
            before = _records_views(pat2_id)
            assert c.get("/my").status_code == 200
            assert _records_views(pat2_id) == before

        created = insert_cross_doctor_notes()
        appointment_id = created["appointment_a_id"]
        _psql(
            "INSERT INTO prescriptions (appointment_id, doctor_id, patient_user_id, body) "
            f"SELECT id, doctor_id, patient_user_id, {sql_packet('prescriptions', 'rx:audit-my-page')} "
            f"FROM appointments WHERE id = {appointment_id}"
        )
        with _client() as c:
            _login(c, PAT)
            before = _records_views(pat_id)
            page = c.get("/my")
            assert page.status_code == 200
            assert NOTE_DOCTOR1_PATIENT_A in page.text and "rx:audit-my-page" in page.text
            # One event per page view, not one per record.
            assert _records_views(pat_id) == before + 1
            assert c.get("/my/records").status_code == 200
            assert _records_views(pat_id) == before + 2
        bodies = _psql("SELECT action || ' ' || target_type FROM audit_events ORDER BY id DESC LIMIT 5")
        assert not any(NOTE_DOCTOR1_PATIENT_A in line or "rx:audit-my-page" in line for line in bodies)
    finally:
        cleanup_cross_doctor_notes()


AUTH_COLUMNS = "action, actor_user_id, actor_role, coalesce(reason, ''), coalesce(source, ''), target_type"


def _audit_mark() -> int:
    return int(_psql("SELECT coalesce(max(id), 0) FROM audit_events")[0])


def _auth_events_since(mark: int) -> list[tuple]:
    rows = _psql(
        f"SELECT {AUTH_COLUMNS} FROM audit_events "
        f"WHERE id > {mark} AND action LIKE 'auth.%' ORDER BY id"
    )
    return [tuple(row.split("|")) for row in rows]


def _assert_nothing_secret_since(mark: int, *needles: str) -> None:
    for needle in needles:
        found = _psql(
            "SELECT count(*) FROM audit_events AS e "
            f"WHERE id > {mark} AND strpos(lower(row_to_json(e)::text), lower('{needle}')) > 0"
        )
        assert found == ["0"], needle


def test_login_success_and_failures_are_journaled_without_secrets():
    pat_id = _user_id(PAT)
    unknown = f"nobody-{uuid.uuid4().hex}@example.com"
    with _client() as c:
        mark = _audit_mark()
        assert c.post("/login", data={"email": PAT, "password": "wrong-" + uuid.uuid4().hex}).status_code == 401
        events = _auth_events_since(mark)
        assert len(events) == 1
        action, actor, role, reason, source, _ = events[0]
        assert (action, actor, role, reason) == ("auth.login.failure", str(pat_id), "patient", "bad_credentials")
        assert source

        mark = _audit_mark()
        assert c.post("/login", data={"email": unknown, "password": "Wrong-Password-1"}).status_code == 401
        events = _auth_events_since(mark)
        assert [e[:4] for e in events] == [("auth.login.failure", "", "anonymous", "bad_credentials")]
        _assert_nothing_secret_since(mark, unknown, unknown.split("@")[0], "Wrong-Password-1")

        mark = _audit_mark()
        _login(c, PAT)
        events = _auth_events_since(mark)
        assert [e[:4] for e in events] == [("auth.login.success", str(pat_id), "patient", "")]
        _assert_nothing_secret_since(mark, PASSWORD, c.csrf_token())

        mark = _audit_mark()
        assert c.post("/logout").status_code == 200
        events = _auth_events_since(mark)
        assert [e[:4] for e in events] == [("auth.logout", str(pat_id), "patient", "")]

    with _client() as anonymous:
        mark = _audit_mark()
        # No valid session: logout writes nothing.
        anonymous.post("/logout")
        assert _auth_events_since(mark) == []


def test_blocked_login_is_journaled_as_failure():
    pat2_id = _user_id(PAT2)
    _psql(f"UPDATE users SET blocked = TRUE WHERE id = {pat2_id}")
    try:
        with _client() as c:
            mark = _audit_mark()
            page = c.post("/login", data={"email": PAT2, "password": PASSWORD})
            assert page.status_code == 403
            events = _auth_events_since(mark)
            assert [e[:4] for e in events] == [("auth.login.failure", str(pat2_id), "patient", "blocked")]
    finally:
        _psql(f"UPDATE users SET blocked = FALSE WHERE id = {pat2_id}")


def test_rate_limit_is_journaled_once_per_window():
    email = f"limit-{uuid.uuid4().hex}@example.com"
    with _client() as c:
        mark = _audit_mark()
        codes = [c.post("/login", data={"email": email, "password": "Wrong-Password-1"}).status_code
                 for _ in range(7)]
    assert codes == [401] * 5 + [429] * 2, codes
    events = _auth_events_since(mark)
    failures = [e for e in events if e[0] == "auth.login.failure"]
    assert len(failures) == 5 and all(e[1:4] == ("", "anonymous", "bad_credentials") for e in failures)
    source = failures[0][4]
    assert len([e for e in events if e[0] == "auth.rate_limited"]) <= 1
    in_window = _psql(
        "SELECT count(*) FROM audit_events WHERE action = 'auth.rate_limited' AND reason = 'login' "
        f"AND source = '{source}' AND actor_user_id IS NULL "
        "AND created_at > CURRENT_TIMESTAMP - INTERVAL '15 minutes'"
    )
    assert in_window == ["1"]
    _assert_nothing_secret_since(mark, email, email.split("@")[0], "Wrong-Password-1")
    _psql(f"DELETE FROM login_attempts WHERE email_fingerprint = public.digest('{email}', 'sha256')")


def test_password_reset_rate_limit_is_journaled():
    email = f"reset-limit-{uuid.uuid4().hex}@example.com"
    with _client() as c:
        mark = _audit_mark()
        codes = [c.post("/forgot-password", data={"email": email}, follow_redirects=False).status_code
                 for _ in range(6)]
    assert codes[-1] == 429, codes
    assert all(code == 303 for code in codes[:5]), codes
    events = _auth_events_since(mark)
    assert len(events) <= 1 and all(e[:4] == ("auth.rate_limited", "", "anonymous", "password_reset") for e in events)
    in_window = _psql(
        "SELECT count(*) FROM audit_events WHERE action = 'auth.rate_limited' "
        "AND reason = 'password_reset' AND actor_user_id IS NULL "
        "AND created_at > CURRENT_TIMESTAMP - INTERVAL '15 minutes'"
    )
    assert int(in_window[0]) >= 1
    _assert_nothing_secret_since(mark, email, email.split("@")[0])
    _psql(f"DELETE FROM password_reset_attempts WHERE email_fingerprint = public.digest('{email}', 'sha256')")


def test_login_timing_is_equal_with_journal():
    """Median authenticate_user time for an existing and an unknown email, in one rolled-back transaction."""
    completed = subprocess.run(
        ["docker", "compose", "exec", "-T", "db", "psql", "-X", "-U", "clinic", "-d", "clinic",
         "-v", "ON_ERROR_STOP=1", "-At"],
        input=f"""
BEGIN;
CREATE TEMP TABLE timing (kind text, ms double precision);
DO $$
DECLARE
  started timestamptz;
BEGIN
  FOR i IN 1..8 LOOP
    started := clock_timestamp();
    PERFORM * FROM public.authenticate_user('{PAT}', 'wrong-timing-password', 'timing-e-' || i);
    INSERT INTO timing VALUES ('existing', extract(epoch FROM clock_timestamp() - started) * 1000);
    started := clock_timestamp();
    PERFORM * FROM public.authenticate_user(
      'missing-' || i || '-{uuid.uuid4().hex}@example.com', 'wrong-timing-password', 'timing-m-' || i
    );
    INSERT INTO timing VALUES ('missing', extract(epoch FROM clock_timestamp() - started) * 1000);
  END LOOP;
END
$$;
SELECT kind, percentile_cont(0.5) WITHIN GROUP (ORDER BY ms) FROM timing GROUP BY kind ORDER BY kind;
ROLLBACK;
""",
        cwd=ROOT, capture_output=True, text=True, timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    medians = dict(
        (kind, float(value))
        for kind, value in re.findall(r"^(existing|missing)\|([0-9.]+)$", completed.stdout, re.M)
    )
    existing, missing = medians["existing"], medians["missing"]
    assert abs(existing - missing) <= 0.15 * max(existing, missing), medians


def test_admin_audit_shows_anonymous_events():
    with _client() as c:
        c.post("/login", data={"email": f"nobody-{uuid.uuid4().hex}@example.com", "password": "Wrong-Password-1"})
    with _client() as admin:
        _login(admin, "admin@clinic.local")
        page = admin.get("/admin/audit")
    assert page.status_code == 200
    assert "auth.login.failure" in page.text and "anonymous" in page.text and "bad_credentials" in page.text
    assert "<th>Reason</th><th>Source</th>" in page.text
    with _client() as patient:
        _login(patient, PAT)
        assert patient.get("/admin/audit").status_code == 403
