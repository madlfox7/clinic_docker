"""Session limits: id-only cookie, idle timeout from clinic settings, 12 h absolute limit."""
import base64
import json
import os
import re
import subprocess
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlparse

import pytest

from tests.csrf_client import CsrfClient
from tests.demo_secret import demo_password
from tests.test_rls_boundary import compose_exec, compose_exec_run

ROOT = Path(__file__).resolve().parents[1]
BASE = os.environ.get("CLINIC_TEST_BASE", "http://localhost:8080")
PASSWORD = demo_password()
PAT = "pat@clinic.local"
DOC = "doc@clinic.local"
REG = "reg@clinic.local"
ADMIN = "admin@clinic.local"


def _psql(sql: str) -> list[str]:
    completed = subprocess.run(
        ["docker", "compose", "exec", "-T", "db", "psql", "-X", "-U", "clinic", "-d", "clinic",
         "-v", "ON_ERROR_STOP=1", "-At", "-F", "|", "-c", sql],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    return [line for line in completed.stdout.splitlines() if line.strip()]


def _psql_run(sql: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "exec", "-T", "db", "psql", "-X", "-U", "clinic", "-d", "clinic",
         "-v", "ON_ERROR_STOP=1", "-At", "-c", sql],
        cwd=ROOT, capture_output=True, text=True,
    )


def _client(cookie=None, follow=False):
    c = CsrfClient(base_url=BASE, follow_redirects=follow, timeout=10.0)
    if cookie:
        # Same domain the server's Set-Cookie lands on, so updates replace it.
        c.cookies.set("session", cookie, domain=urlparse(BASE).hostname, path="/")
    return c


def _set_cookie_value(response) -> str:
    match = re.match(r"session=([^;]+);", response.headers.get("set-cookie", ""))
    assert match, response.headers
    return match.group(1)


def _payload(cookie: str) -> dict:
    raw = cookie.split(".", 1)[0]
    return json.loads(base64.b64decode(raw + "=" * (-len(raw) % 4)))


def _sign(payload: dict) -> str:
    """Sign a cookie payload inside the api container; the secret never leaves it."""
    script = (
        "import base64, json, itsdangerous\n"
        "from secret_files import read_secret\n"
        f"data = json.loads({json.dumps(json.dumps(payload))})\n"
        "signer = itsdangerous.TimestampSigner(read_secret('session_secret'))\n"
        "print(signer.sign(base64.b64encode(json.dumps(data).encode())).decode())\n"
    )
    return compose_exec("api", ["python", "-"], input_text=script)


def _login_cookie(email: str, password: str = PASSWORD) -> str:
    with _client(follow=True) as c:
        page = c.post("/login", data={"email": email, "password": password})
        assert page.status_code == 200 and page.url.path == "/me", email
        return c.cookies.get("session")


def _user_id(email: str) -> int:
    return int(_psql(f"SELECT id FROM users WHERE email = '{email}'")[0])


def _expired_events(user_id: int, reason: str) -> list[str]:
    return _psql(
        "SELECT coalesce(source, '') FROM audit_events "
        f"WHERE action = 'auth.session_expired' AND actor_user_id = {user_id} AND reason = '{reason}' "
        "ORDER BY id"
    )


def _forget_expired_events(user_id: int) -> None:
    # One event per account and reason in 15 minutes: start each check clean.
    _psql(f"DELETE FROM audit_events WHERE action = 'auth.session_expired' AND actor_user_id = {user_id}")


def _aged_cookie(email: str, *, seen_ago: int = 0, iat_ago: int | None = None, drop=(), extra=None) -> str:
    payload = _payload(_login_cookie(email))
    now = int(time.time())
    payload["seen"] = now - seen_ago
    payload["iat"] = now - (iat_ago if iat_ago is not None else seen_ago)
    for key in drop:
        payload.pop(key, None)
    payload.update(extra or {})
    return _sign(payload)


def _set_idle(minutes: int) -> None:
    _psql(f"UPDATE clinic_settings SET session_idle_minutes = {minutes} WHERE id = 1")


def _idle() -> int:
    return int(_psql("SELECT session_idle_minutes FROM clinic_settings WHERE id = 1")[0])


@pytest.fixture(autouse=True)
def _default_idle():
    _set_idle(30)
    yield
    _set_idle(30)


def test_cookie_holds_only_ids_and_timestamps():
    with _client(follow=True) as c:
        c.post("/login", data={"email": PAT, "password": PASSWORD})
        cookie = c.cookies.get("session")
        payload = _payload(cookie)
        assert set(payload) == {"user_id", "auth_version", "iat", "seen", "csrf_token"}, payload
        assert "@" not in json.dumps(payload)
        assert all(type(payload[key]) is int for key in ("user_id", "auth_version", "iat", "seen"))
        first = c.get("/me")
        second = c.get("/me")
        assert first.status_code == second.status_code == 200
        # seen is refreshed at most once a minute, so no cookie is re-sent here.
        assert "set-cookie" not in second.headers


def test_set_cookie_attributes():
    with _client() as c:
        response = c.get("/login")
    header = response.headers["set-cookie"]
    assert re.search(r"; Max-Age=43200;", header), header
    assert "httponly" in header and "samesite=lax" in header
    assert "secure" not in header.lower()


def test_idle_timeout_expires_session_once():
    pat_id = _user_id(PAT)
    _forget_expired_events(pat_id)
    cookie = _aged_cookie(PAT, seen_ago=31 * 60)
    with _client(cookie) as c:
        response = c.get("/me")
        assert response.status_code == 303
        assert response.headers["location"] == "/login?expired=1"
        assert re.match(r"session=null; path=/; expires=Thu, 01 Jan 1970", response.headers["set-cookie"])
    events = _expired_events(pat_id, "idle_timeout")
    assert len(events) == 1 and events[0], events
    with _client(cookie) as replay:
        assert replay.get("/me").status_code == 303
    assert len(_expired_events(pat_id, "idle_timeout")) == 1
    with _client(follow=True) as page:
        shown = page.get("/login?expired=1")
        assert "Your session has expired. Please sign in again." in shown.text


def test_fresh_activity_keeps_session_and_refreshes_seen():
    cookie = _aged_cookie(PAT, seen_ago=5 * 60, iat_ago=60 * 60)
    with _client(cookie) as c:
        response = c.get("/me")
        assert response.status_code == 200
        refreshed = _payload(_set_cookie_value(response))
    assert refreshed["seen"] >= int(time.time()) - 5
    assert refreshed["iat"] == _payload(cookie)["iat"]


def test_absolute_timeout():
    pat_id = _user_id(PAT)
    _forget_expired_events(pat_id)
    cookie = _aged_cookie(PAT, seen_ago=0, iat_ago=13 * 3600)
    with _client(cookie) as c:
        response = c.get("/me")
    assert response.status_code == 303 and response.headers["location"] == "/login?expired=1"
    assert len(_expired_events(pat_id, "absolute_timeout")) == 1


@pytest.mark.parametrize("kind", ["legacy", "future_seen"])
def test_legacy_or_forged_timestamps_are_cleared_without_event(kind):
    pat_id = _user_id(PAT)
    _forget_expired_events(pat_id)
    if kind == "legacy":
        cookie = _aged_cookie(PAT, drop=("iat", "seen"), extra={"email": PAT})
    else:
        cookie = _aged_cookie(PAT, extra={"seen": int(time.time()) + 3600})
    with _client(cookie) as c:
        response = c.get("/me")
        assert response.status_code == 303
        assert response.headers["location"].startswith("/login")
        assert "session=null" in response.headers["set-cookie"]
        assert c.get("/").status_code == 200
    assert _psql(
        f"SELECT count(*) FROM audit_events WHERE action = 'auth.session_expired' AND actor_user_id = {pat_id}"
    ) == ["0"]


def test_expired_session_keeps_way_back_to_doctor():
    doctor_id = int(_psql(
        f"SELECT d.id FROM doctors d JOIN users u ON u.id = d.user_id WHERE u.email = '{DOC}'"
    )[0])
    cookie = _aged_cookie(PAT, seen_ago=31 * 60)
    with _client(cookie) as c:
        response = c.get(f"/doctors/{doctor_id}/slots")
        assert response.status_code == 303
        assert response.headers["location"] == f"/login?expired=1&doctor={doctor_id}"
        page = c.get(response.headers["location"])
        assert "Your session has expired" in page.text
        assert f'name="doctor" value="{doctor_id}"' in page.text
        back = c.post("/login", data={"email": PAT, "password": PASSWORD, "doctor": str(doctor_id)})
        assert back.status_code == 303
        assert back.headers["location"] == f"/doctors/{doctor_id}/slots"


def test_post_with_expired_session_goes_to_login_without_booking():
    pat_id = _user_id(PAT)
    slot = _psql(
        "SELECT s.id FROM slots s WHERE s.starts_at > CURRENT_TIMESTAMP "
        "AND NOT EXISTS (SELECT 1 FROM appointments a WHERE a.slot_id = s.id AND a.status = 'scheduled') "
        "ORDER BY s.starts_at LIMIT 1"
    )
    assert slot, "no free future slot"
    before = _psql(f"SELECT count(*) FROM appointments WHERE patient_user_id = {pat_id}")
    cookie = _aged_cookie(PAT, seen_ago=31 * 60)
    with _client(cookie) as c:
        response = c.post(f"/slots/{slot[0]}/book")
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login?expired=1")
    assert _psql(f"SELECT count(*) FROM appointments WHERE patient_user_id = {pat_id}") == before


def test_logout_with_expired_session():
    pat_id = _user_id(PAT)
    _forget_expired_events(pat_id)
    logouts = _psql(f"SELECT count(*) FROM audit_events WHERE action = 'auth.logout' AND actor_user_id = {pat_id}")
    cookie = _aged_cookie(PAT, seen_ago=31 * 60)
    with _client(cookie) as c:
        response = c.post("/logout")
    assert response.status_code == 303 and response.headers["location"] == "/"
    assert _psql(
        f"SELECT count(*) FROM audit_events WHERE action = 'auth.logout' AND actor_user_id = {pat_id}"
    ) == logouts
    assert len(_expired_events(pat_id, "idle_timeout")) == 1


def test_password_change_keeps_sign_in_time():
    email = f"session-{uuid.uuid4().hex}@clinic.local"
    password = "Session-Check-2026!"
    new_password = "Session-Changed-2026!"
    with _client(follow=True) as c:
        created = c.post("/register", data={"email": email, "password": password, "confirm_password": password})
        assert "registered=1" in str(created.url)
    try:
        cookie = _aged_cookie_for(email, password, iat_ago=2 * 3600)
        iat = _payload(cookie)["iat"]
        with _client(cookie) as c:
            changed = c.post("/me/password", data={
                "current_password": password, "new_password": new_password, "confirm_password": new_password,
            })
            assert changed.headers["location"] == "/me?password_changed=1"
            new_cookie = _set_cookie_value(changed)
            assert _payload(new_cookie)["iat"] == iat
        with _client(new_cookie) as c:
            assert c.get("/me").status_code == 200
    finally:
        _psql(
            f"DELETE FROM audit_events WHERE actor_user_id = (SELECT id FROM users WHERE email = '{email}') "
            f"OR target_id = (SELECT id FROM users WHERE email = '{email}'); "
            f"DELETE FROM login_attempts WHERE email_fingerprint = public.digest('{email}', 'sha256'); "
            f"DELETE FROM users WHERE email = '{email}'"
        )


def _aged_cookie_for(email: str, password: str, *, iat_ago: int) -> str:
    payload = _payload(_login_cookie(email, password))
    payload["iat"] = int(time.time()) - iat_ago
    payload["seen"] = int(time.time())
    return _sign(payload)


@pytest.mark.parametrize(
    "env",
    [
        {"SESSION_ABSOLUTE_HOURS": "0"},
        {"SESSION_ABSOLUTE_HOURS": "2"},
        {"SESSION_ABSOLUTE_HOURS": "25"},
        {"SESSION_ABSOLUTE_HOURS": "abc"},
        {"SESSION_ABSOLUTE_HOURS": ""},
        {"SESSION_ABSOLUTE_HOURS": "12 "},
        {"SESSION_ABSOLUTE_HOURS": "1e1"},
        {"SESSION_ABSOLUTE_HOURS": "-1"},
        {"SESSION_SAME_SITE": "none"},
        {"SESSION_HTTPS_ONLY": "yes"},
    ],
)
def test_bad_session_env_stops_startup(env):
    result = compose_exec_run("api", ["python", "-c", "import session_config"], env=env)
    assert result.returncode != 0, env
    assert "RuntimeError" in result.stderr


def test_default_session_env_is_accepted():
    out = compose_exec(
        "api",
        ["python", "-c", "import session_config as s; print(s.ABSOLUTE_SECONDS, s.SAME_SITE, s.HTTPS_ONLY)"],
        env={"SESSION_ABSOLUTE_HOURS": "12", "SESSION_SAME_SITE": "lax", "SESSION_HTTPS_ONLY": "false"},
    )
    assert out == "43200 lax False"
    env_names = compose_exec("api", ["sh", "-c", "env | cut -d= -f1"])
    assert not [name for name in env_names.split() if name.startswith("SESSION_IDLE")]


# --- idle timeout set by the admin ---------------------------------------------


@contextmanager
def _admin():
    with _client(follow=False) as c:
        page = c.post("/login", data={"email": ADMIN, "password": PASSWORD})
        assert page.status_code == 303
        yield c


def _idle_events() -> list[str]:
    return _psql(
        "SELECT actor_user_id || '|' || target_type || '|' || target_id || '|' || old_value || '|' || new_value "
        "FROM audit_events WHERE action = 'clinic.session_idle.update' ORDER BY id"
    )


@pytest.mark.parametrize("value", ["4", "121", "0", "-5", "abc", "30.5", "", "1e2", "+"])
def test_admin_idle_rejects_out_of_range(value):
    with _admin() as admin:
        response = admin.post("/admin/settings/session", data={"idle_minutes": value})
    assert response.status_code == 303
    assert response.headers["location"] == "/admin/settings?error=invalid_idle"
    assert _idle() == 30


@pytest.mark.parametrize("value,stored", [("5", 5), ("120", 120), (" 30 ", 30)])
def test_admin_idle_accepts_range(value, stored):
    with _admin() as admin:
        response = admin.post("/admin/settings/session", data={"idle_minutes": value})
        assert response.headers["location"] == "/admin/settings?saved=session"
        page = admin.get("/admin/settings?saved=session")
    assert _idle() == stored
    assert "Session timeout saved." in page.text
    assert f'name="idle_minutes" min="5" max="120" step="1" required value="{stored}"' in page.text


def test_database_guards_the_idle_setting():
    assert _psql_run("UPDATE clinic_settings SET session_idle_minutes = 4 WHERE id = 1").returncode != 0
    admin_id = _user_id(ADMIN)
    too_big = _psql_run(
        f"BEGIN; SET LOCAL ROLE app_admin; SELECT set_config('app.user_id', '{admin_id}', true); "
        "SELECT public.set_session_idle_minutes(121); ROLLBACK;"
    )
    assert too_big.returncode != 0 and "between 5 and 120" in too_big.stderr
    for role, email in (("app_doctor", DOC), ("app_patient", PAT), ("app_registrar", REG), ("app_guest", None)):
        uid = _user_id(email) if email else 0
        denied = _psql_run(
            f"BEGIN; SET LOCAL ROLE {role}; SELECT set_config('app.user_id', '{uid}', true); "
            "SELECT public.set_session_idle_minutes(60); ROLLBACK;"
        )
        assert denied.returncode != 0, role
        assert "permission denied" in denied.stderr or "invalid admin context" in denied.stderr, denied.stderr
    direct = _psql_run(
        f"BEGIN; SET LOCAL ROLE app_admin; SELECT set_config('app.user_id', '{admin_id}', true); "
        "UPDATE clinic_settings SET session_idle_minutes = 60 WHERE id = 1; ROLLBACK;"
    )
    assert direct.returncode != 0 and "permission denied" in direct.stderr
    hidden = _psql_run("BEGIN; SET LOCAL ROLE clinic_api; SELECT address FROM clinic_settings; ROLLBACK;")
    assert hidden.returncode != 0 and "permission denied" in hidden.stderr
    visible = _psql("BEGIN; SET LOCAL ROLE clinic_api; SELECT session_idle_minutes FROM clinic_settings; ROLLBACK;")
    assert "30" in visible
    assert _idle() == 30


@pytest.mark.parametrize("email", [PAT, DOC, REG])
def test_non_admin_cannot_change_idle(email):
    with _client(follow=False) as c:
        c.post("/login", data={"email": email, "password": PASSWORD})
        response = c.post("/admin/settings/session", data={"idle_minutes": "60"})
    assert response.status_code == 403
    assert _idle() == 30


def test_guest_cannot_change_idle():
    with _client(follow=False) as c:
        response = c.post("/admin/settings/session", data={"idle_minutes": "60"})
    assert response.status_code == 303 and response.headers["location"] == "/login"
    assert _idle() == 30


def test_idle_change_requires_csrf():
    before = _idle_events()
    with _admin() as admin:
        missing = admin.post("/admin/settings/session", data={"idle_minutes": "60"}, csrf=False)
        wrong = admin.post("/admin/settings/session", data={"idle_minutes": "60", "csrf_token": "x" * 43})
    for response in (missing, wrong):
        assert response.status_code == 403
        assert "Session expired, please refresh the page" in response.text
    assert _idle() == 30
    assert _idle_events() == before


def test_idle_change_is_journaled_with_old_and_new_value():
    admin_id = _user_id(ADMIN)
    before = _idle_events()
    with _admin() as admin:
        admin.post("/admin/settings/session", data={"idle_minutes": "45"})
        admin.post("/admin/settings/session", data={"idle_minutes": "45"})
        admin.post("/admin/settings", data={"address": "Educational stand", "phone": "000-00-00"})
        audit = admin.get("/admin/audit")
    after = _idle_events()
    assert after[len(before):] == [f"{admin_id}|clinic|1|30|45"]
    assert "30 → 45" in audit.text


def test_new_idle_value_applies_on_next_request():
    pat_id = _user_id(PAT)
    _forget_expired_events(pat_id)
    with _admin() as admin:
        admin.post("/admin/settings/session", data={"idle_minutes": "10"})
    with _client(_aged_cookie(PAT, seen_ago=11 * 60)) as c:
        assert c.get("/me").headers["location"] == "/login?expired=1"
    with _admin() as admin:
        admin.post("/admin/settings/session", data={"idle_minutes": "120"})
    with _client(_aged_cookie(PAT, seen_ago=60 * 60)) as c:
        assert c.get("/me").status_code == 200


def test_unreadable_idle_setting_falls_back_to_30_minutes():
    _psql("REVOKE SELECT (session_idle_minutes) ON clinic_settings FROM clinic_api")
    try:
        with _client(_aged_cookie(PAT, seen_ago=31 * 60)) as c:
            assert c.get("/me").headers["location"] == "/login?expired=1"
        with _client(_aged_cookie(PAT, seen_ago=10 * 60)) as c:
            assert c.get("/me").status_code == 200
    finally:
        _psql("GRANT SELECT (id, session_idle_minutes) ON clinic_settings TO clinic_api")
    logs = subprocess.run(["docker", "compose", "logs", "--since", "2m", "api"], cwd=ROOT,
                          capture_output=True, text=True, timeout=30)
    assert "session idle setting unavailable, using 30" in logs.stdout
