"""15_hardening: POST /register rate limit and reschedule limits (one event per
move, daily patient limit, two-key advisory lock)."""
import os
import re
import uuid
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
    PAT,
    _as_role,
    _psql,
    _psql_try,
    _run_migrate,
    _user_id,
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
        assert codes == [303, 409, 409, 409, 409, 429], codes
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
