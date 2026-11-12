"""AUDIT_ROLES_2 fixes: neutral answer for a blocked account at sign-in."""
import os
import subprocess
import uuid
from pathlib import Path

from tests.csrf_client import CsrfClient
from tests.demo_secret import demo_password

ROOT = Path(__file__).resolve().parents[1]
BASE = os.environ.get("CLINIC_TEST_BASE", "http://localhost:8080")
PASSWORD = demo_password()
PAT = "pat@clinic.local"
PAT2 = "pat2@clinic.local"
INVALID = "Invalid email or password"


def _client(**kwargs):
    return CsrfClient(base_url=BASE, follow_redirects=True, timeout=10.0, **kwargs)


def _psql(sql: str) -> list[str]:
    completed = subprocess.run(
        ["docker", "compose", "exec", "-T", "db", "psql", "-X", "-U", "clinic", "-d", "clinic",
         "-v", "ON_ERROR_STOP=1", "-At", "-F", "|", "-c", sql],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    return [line for line in completed.stdout.splitlines() if line.strip()]


def _clear_login_attempts(email: str) -> None:
    _psql(f"DELETE FROM login_attempts WHERE email_fingerprint = public.digest('{email}', 'sha256')")


# --- R2-C-enum-blocked-msg ---------------------------------------------------

def test_blocked_account_answers_like_unknown_email():
    unknown = f"nobody-{uuid.uuid4().hex}@example.com"
    _clear_login_attempts(PAT2)
    _psql(f"UPDATE users SET blocked = TRUE WHERE email = '{PAT2}'")
    try:
        with _client() as c:
            blocked = c.post("/login", data={"email": PAT2, "password": PASSWORD})
        with _client() as c:
            missing = c.post("/login", data={"email": unknown, "password": PASSWORD})
        assert blocked.status_code == missing.status_code == 401
        assert INVALID in blocked.text and INVALID in missing.text
        assert "Account is blocked" not in blocked.text
        assert "blocked" not in blocked.text.lower()
    finally:
        _psql(f"UPDATE users SET blocked = FALSE WHERE email = '{PAT2}'")
        _clear_login_attempts(PAT2)
        _clear_login_attempts(unknown)


def test_blocked_right_password_counts_toward_rate_limit():
    _clear_login_attempts(PAT2)
    _psql(f"UPDATE users SET blocked = TRUE WHERE email = '{PAT2}'")
    try:
        with _client() as c:
            for _ in range(5):
                page = c.post("/login", data={"email": PAT2, "password": PASSWORD})
                assert page.status_code == 401 and INVALID in page.text
            sixth = c.post("/login", data={"email": PAT2, "password": PASSWORD})
            assert sixth.status_code == 429
    finally:
        _psql(f"UPDATE users SET blocked = FALSE WHERE email = '{PAT2}'")
        _clear_login_attempts(PAT2)


def test_session_revoked_by_block_still_says_blocked():
    _clear_login_attempts(PAT2)
    with _client() as c:
        page = c.post("/login", data={"email": PAT2, "password": PASSWORD})
        assert page.status_code == 200 and page.url.path == "/me"
        _psql(f"UPDATE users SET blocked = TRUE WHERE email = '{PAT2}'")
        try:
            revoked = c.get("/me")
            assert revoked.status_code == 403
            assert "Account is blocked" in revoked.text
        finally:
            _psql(f"UPDATE users SET blocked = FALSE WHERE email = '{PAT2}'")
