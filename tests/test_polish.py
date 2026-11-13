"""16_polish: error pages, confirmations, neutral registration, one login
answer, patient cancel/reschedule deadline."""
import html
import os
import re
import subprocess
import uuid
from pathlib import Path

import httpx

from tests.csrf_client import CsrfClient
from tests.registration import (
    account_notices,
    clear_registration_attempts,
    confirm_registration,
    registration_form,
    registration_limit_reset,  # noqa: F401 (autouse)
    verification_messages,
)
from tests.test_ux_filters import (
    ADMIN,
    DOC,
    PAT,
    PASSWORD,
    REG,
    _Setup,
    _doctor_id,
    _login,
    _make_slot,
    _psql,
    _psql_try,
    _user_id,
)

ROOT = Path(__file__).resolve().parents[1]
BASE = os.environ.get("CLINIC_TEST_BASE", "http://localhost:8080")
MAILPIT = os.environ.get("CLINIC_MAILPIT", "http://localhost:8025")


def _client(follow_redirects: bool = True):
    return CsrfClient(base_url=BASE, follow_redirects=follow_redirects, timeout=15.0)


def _api_logs(since: str = "2m") -> str:
    return subprocess.run(
        ["docker", "compose", "logs", "--no-log-prefix", "--since", since, "api"],
        cwd=ROOT, capture_output=True, text=True,
    ).stdout


# --- 4. Error pages ----------------------------------------------------------

def test_unexpected_error_gives_the_clinic_page_with_a_reference_only():
    _psql("REVOKE EXECUTE ON FUNCTION public.request_password_reset(text, text, boolean) FROM clinic_api")
    try:
        with _client(follow_redirects=False) as c:
            page = c.post("/forgot-password?probe=secret-query-value",
                          data={"email": f"err-{uuid.uuid4().hex[:8]}@example.com"})
    finally:
        _psql("GRANT EXECUTE ON FUNCTION public.request_password_reset(text, text, boolean) TO clinic_api")
    assert page.status_code == 500, page.status_code
    assert page.headers["content-type"].startswith("text/html")
    assert "Something went wrong" in page.text
    found = re.search(r"Reference: ([0-9a-f]{8})\.", page.text)
    assert found, page.text[:500]
    for leak in ("Traceback", "psycopg2", "permission denied", "request_password_reset",
                 "SELECT", "InsufficientPrivilege", "secret-query-value"):
        assert leak not in page.text, leak
    assert "set-cookie" not in page.headers
    logs = _api_logs()
    line = next((l for l in logs.splitlines() if f"ref={found.group(1)}" in l), "")
    assert "POST /forgot-password InsufficientPrivilege" in line, line
    assert "secret-query-value" not in line and "probe=" not in line


def test_404_405_and_csrf_pages_stay_html_without_detail():
    with _client(follow_redirects=False) as c:
        missing = c.get("/no-such-page")
        assert missing.status_code == 404 and "Page not found" in missing.text
        assert missing.headers["content-type"].startswith("text/html")
        assert '{"detail"' not in missing.text and "Not Found" not in missing.text
        wrong = c.get("/logout")
        assert wrong.status_code == 405 and "Method not allowed" in wrong.text
        assert "POST" in wrong.headers["allow"]
        assert "Method Not Allowed" not in wrong.text
        no_token = c.post("/logout", csrf=False)
        assert no_token.status_code == 403
        assert "Session expired, please refresh the page" in no_token.text


def test_error_handler_source_shape():
    source = (ROOT / "app" / "main.py").read_text()
    assert "@app.exception_handler(Exception)" in source
    assert "\nimport secrets\n" in source
    assert "from fastapi.responses import HTMLResponse" in source
    handler = source[source.index("async def unexpected_error"):]
    handler = handler[:handler.index("\n\n\n") if "\n\n\n" in handler else len(handler)]
    assert "load_role=False" in handler and "load_session_user" not in handler
    assert "request.url.path" in handler
    assert re.search(r"request\.url(?!\.path)", handler) is None
    fallback = source[source.index("_FALLBACK_500 = ("):source.index("@app.exception_handler(Exception)")]
    for banned in ("<style", "style=", "<script"):
        assert banned not in fallback


def test_nginx_unavailable_page_names_match():
    page = ROOT / "docker" / "proxy" / "errors" / "clinic-unavailable.html"
    text = page.read_text()
    assert "The clinic service is temporarily unavailable." in text
    assert "<script" not in text and "<style" not in text and "style=" not in text
    conf = (ROOT / "docker" / "proxy" / "nginx.conf").read_text()
    assert "error_page 502 504 /clinic-unavailable.html;" in conf
    assert "location = /clinic-unavailable.html {" in conf
    assert "root /etc/nginx/clinic/errors;" in conf
    assert "proxy_intercept_errors" not in conf
    dockerfile = (ROOT / "docker" / "proxy" / "Dockerfile").read_text()
    assert "COPY docker/proxy/errors/clinic-unavailable.html /etc/nginx/clinic/errors/" in dockerfile


# --- 1. Confirmations ----------------------------------------------------------

FORM_TAG = re.compile(r"<form\b[^>]*>", re.S)


def _forms(page: str, action_pattern: str) -> list[str]:
    return [tag for tag in FORM_TAG.findall(page) if re.search(f'action="{action_pattern}"', tag)]


def _attr(tag: str, name: str):
    found = re.search(rf'\s{name}="([^"]*)"', tag)
    return html.unescape(found.group(1)) if found else None


def _when(sql_value: str) -> str:
    """visit_when (start only) for an SQL timestamp expression, from the database."""
    return _psql(f"SELECT to_char({sql_value}, 'Dy, DD Mon YYYY HH24:MI')")[0]


def _names(slot_id: int) -> tuple[str, str, str]:
    doctor, service, when = _psql(
        "SELECT d.full_name || '|' || svc.name || '|' || to_char(s.starts_at, 'Dy, DD Mon YYYY HH24:MI') "
        f"FROM slots s JOIN doctors d ON d.id = s.doctor_id JOIN services svc ON svc.id = s.service_id "
        f"WHERE s.id = {slot_id}"
    )[0].split("|")
    return doctor, service, when


def test_patient_and_registrar_booking_forms_ask_with_visit_details():
    s = _Setup(times=("10:00", "12:00", "13:00"))
    try:
        doctor, service, when = _names(s.targets[0])
        with _client() as pat, _client() as reg:
            _login(pat, PAT)
            _login(reg, REG)
            params = {"service_id": "1", "day": s.day, "view": "day"}
            page = pat.get(f"/doctors/{s.doctor}/slots", params=params).text
            booking = _forms(page, r"/slots/\d+/book")
            assert len(booking) == 2, booking
            for tag in booking:
                message = _attr(tag, "data-confirm")
                assert message and message.startswith(f"Book {service} with {doctor} on "), tag
                assert _attr(tag, "data-confirm-patient") is None
            target_tag = _forms(page, f"/slots/{s.targets[0]}/book")[0]
            assert _attr(target_tag, "data-confirm") == f"Book {service} with {doctor} on {when}?"
            page = reg.get(f"/doctors/{s.doctor}/slots", params=params).text
            target_tag = _forms(page, f"/slots/{s.targets[0]}/book")[0]
            assert _attr(target_tag, "data-confirm") == f"Book {service} with {doctor} on {when} for {{patient}}?"
            assert _attr(target_tag, "data-confirm-patient") == "1"
            # the registrar's cancel form for the booked old visit
            old_doctor, old_service, old_when = _names(s.old_slot)
            cancel = _forms(page, f"/appointments/{s.old}/cancel")[0]
            assert _attr(cancel, "data-confirm") == \
                f"Cancel the appointment: {old_service} with {old_doctor} on {old_when}?"
    finally:
        s.cleanup()
    templates = (ROOT / "app" / "templates")
    flagged = [p.name for p in templates.glob("*.html") if "data-confirm-patient" in p.read_text()]
    assert flagged == ["slots.html"], flagged
    assert (templates / "slots.html").read_text().count("data-confirm-patient") == 1


def test_cancel_and_reschedule_forms_carry_visit_details_everywhere():
    s = _Setup(times=("10:00", "12:00"))
    try:
        doctor, service, when = _names(s.old_slot)
        _, _, new_when = _names(s.targets[0])
        cancel_text = f"Cancel the appointment: {service} with {doctor} on {when}?"
        with _client() as pat, _client() as reg, _client() as admin:
            _login(pat, PAT)
            _login(reg, REG)
            _login(admin, ADMIN)
            my = pat.get("/my", params={"from": s.day, "to": s.day}).text
            assert _attr(_forms(my, f"/appointments/{s.old}/cancel")[0], "data-confirm") == cancel_text
            form = pat.get(f"/appointments/{s.old}/reschedule", params={"day": s.day, "view": "day"}).text
            move = _forms(form, f"/appointments/{s.old}/reschedule")[0]
            assert _attr(move, "data-confirm") == \
                f"Move the appointment ({service} with {doctor}) from {when} to {new_when}?"
            for view in ("day", "week"):
                cal = reg.get("/registrar/appointments", params={"day": s.day, "view": view}).text
                tags = _forms(cal, f"/appointments/{s.old}/cancel")
                assert tags and _attr(tags[0], "data-confirm") == cancel_text, view
            schedule = admin.get("/admin/schedule").text
            tags = _forms(schedule, f"/appointments/{s.old}/cancel")
            assert tags
            for tag in tags:
                assert _attr(tag, "data-confirm") == \
                    f"Cancel the appointment: {service} with {doctor} on {when} for Narek Hakobyan?"
    finally:
        s.cleanup()
    for template in (ROOT / "app" / "templates").glob("*.html"):
        text = template.read_text()
        assert 'data-confirm="Cancel this appointment?"' not in text, template.name
        assert 'data-confirm="Move the appointment to this time?"' not in text, template.name


def test_confirm_text_is_escaped():
    name = f'Check & "X" <b> {uuid.uuid4().hex[:6]}'
    service_id = int(_psql(
        "INSERT INTO services (name, duration_minutes, buffer_minutes, active) "
        f"VALUES ('{name}', 30, 0, TRUE) RETURNING id"
    )[0])
    doctor = _doctor_id(DOC)
    slot = None
    try:
        _psql(f"INSERT INTO doctor_services (doctor_id, service_id) VALUES ({doctor}, {service_id})")
        day = _psql("SELECT (CURRENT_DATE + 450)::text")[0]
        slot = _make_slot(doctor, f"{day} 09:00", service_id)
        with _client() as pat:
            _login(pat, PAT)
            page = pat.get(f"/doctors/{doctor}/slots",
                           params={"service_id": str(service_id), "day": day, "view": "day"}).text
        tag = _forms(page, f"/slots/{slot}/book")[0]
        assert "&amp;" in tag and ("&#34;" in tag or "&quot;" in tag) and "&lt;b&gt;" in tag
        assert "<b>" not in tag
        assert _attr(tag, "data-confirm").startswith(f"Book {name} with ")
    finally:
        if slot:
            _psql(f"DELETE FROM slots WHERE id = {slot}")
        _psql(f"DELETE FROM doctor_services WHERE service_id = {service_id}; "
              f"DELETE FROM services WHERE id = {service_id}")


def test_confirmation_is_not_a_control_csrf_and_methods_stay():
    s = _Setup(times=("10:00", "12:00"))
    try:
        with _client() as pat:
            _login(pat, PAT)
            assert pat.post(f"/slots/{s.targets[0]}/book", data={"service_id": "1"}, csrf=False).status_code == 403
            assert pat.get(f"/slots/{s.targets[0]}/book").status_code == 405
            assert pat.get(f"/appointments/{s.old}/cancel").status_code == 405
            assert _psql(f"SELECT count(*) FROM appointments WHERE slot_id = {s.targets[0]}") == ["0"]
            assert _psql(f"SELECT status FROM appointments WHERE id = {s.old}") == ["scheduled"]
            # without the browser dialog the POST works as before
            booked = pat.post(f"/slots/{s.targets[0]}/book", data={"service_id": "1"},
                              follow_redirects=False)
            assert booked.status_code == 303 and "booked=1" in booked.headers["location"]
    finally:
        s.cleanup()


def test_app_js_fills_patient_only_with_the_flag_and_without_html():
    script = (ROOT / "app" / "static" / "app.js").read_text()
    for banned in ("innerHTML", "eval(", "new Function"):
        assert banned not in script
    assert 'split("{patient}")' in script
    assert 'form.dataset.confirmPatient === "1"' in script


# --- 2. Neutral registration -------------------------------------------------

NEW_PASSWORD = "Neutral-Check-2026!"
RESET_LINK = re.compile(r"/reset-password\?token=([0-9a-f]{64})")


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}@example.com"


def _drop_user(email: str) -> None:
    _psql(
        f"DELETE FROM audit_events WHERE actor_user_id = (SELECT id FROM users WHERE email = '{email}') "
        f"OR (target_type IN ('user', 'patient') AND target_id = (SELECT id FROM users WHERE email = '{email}')); "
        f"DELETE FROM login_attempts WHERE email_fingerprint = public.digest('{email}', 'sha256'); "
        f"DELETE FROM password_reset_attempts WHERE email_fingerprint = public.digest('{email}', 'sha256'); "
        f"DELETE FROM email_verification_attempts WHERE email_fingerprint = public.digest('{email}', 'sha256'); "
        f"DELETE FROM users WHERE email = '{email}'"
    )


def _account_state(email: str) -> str:
    return _psql(
        "SELECT u.password_hash || '|' || u.auth_version || '|' || coalesce(u.email_verified_at::text, '') "
        "|| '|' || (SELECT count(*) FROM password_reset_tokens t WHERE t.user_id = u.id) "
        "|| '|' || (SELECT count(*) FROM password_reset_tokens t WHERE t.user_id = u.id AND t.used_at IS NULL) "
        "|| '|' || (SELECT count(*) FROM email_verification_tokens t WHERE t.user_id = u.id) "
        "|| '|' || (SELECT count(*) FROM email_verification_tokens t WHERE t.user_id = u.id AND t.used_at IS NULL) "
        f"FROM users u WHERE u.email = '{email}'"
    )[0]


def _register_raw(c, email: str, password: str = NEW_PASSWORD) -> httpx.Response:
    return c.post("/register", data=registration_form(email, password), follow_redirects=False)


def _shape(response: httpx.Response) -> tuple:
    headers = sorted((k, v) for k, v in response.headers.items() if k.lower() != "date")
    return response.status_code, response.headers.get("location"), response.content, headers


def _reset_tokens(address: str) -> list[str]:
    found = httpx.get(f"{MAILPIT}/api/v1/search",
                      params={"query": f'to:"{address}" subject:"Reset your clinic password"'}, timeout=5)
    found.raise_for_status()
    tokens = []
    for summary in found.json().get("messages") or []:
        message = httpx.get(f"{MAILPIT}/api/v1/message/{summary.get('ID') or summary.get('Id')}", timeout=5)
        match = RESET_LINK.search(message.json().get("Text") or "")
        if match:
            tokens.append(match.group(1))
    return tokens


def test_taken_and_new_email_get_the_same_answer_and_the_owner_a_notice():
    httpx.delete(f"{MAILPIT}/api/v1/messages", timeout=5)
    fresh = _unique("neutral-new")
    fresh2 = _unique("neutral-new2")
    before = _account_state(PAT)
    try:
        with _client(follow_redirects=False) as c:
            c.get("/register")
            taken = _register_raw(c, PAT)
            new = _register_raw(c, fresh)
            assert taken.status_code == 303 and taken.headers["location"] == "/login?registered=1"
            assert _shape(taken) == _shape(new)
            spaced = _register_raw(c, "  " + PAT.upper())
            new2 = _register_raw(c, fresh2)
            assert _shape(spaced) == _shape(new2) == _shape(taken)
            assert ("set-cookie" in taken.headers) == ("set-cookie" in new.headers)
        notices = account_notices(PAT)
        assert len(notices) == 2
        for notice in notices:
            text = notice.get("Text") or ""
            assert "/forgot-password" in text and "/login" in text
            assert "token=" not in text and "Narek" not in text and "Hakobyan" not in text
        assert verification_messages(PAT) == []
        assert len(verification_messages(fresh)) == 1
        assert _account_state(PAT) == before
        # the new account still confirms and signs in as before
        confirm_registration(fresh)
        with _client() as c:
            done = c.post("/login", data={"email": fresh, "password": NEW_PASSWORD})
            assert done.url.path == "/me", done.url
    finally:
        _drop_user(fresh)
        _drop_user(fresh2)


def test_registration_on_a_taken_email_does_not_cancel_a_live_reset_link():
    httpx.delete(f"{MAILPIT}/api/v1/messages", timeout=5)
    email = _unique("neutral-reset")
    try:
        with _client(follow_redirects=False) as c:
            assert _register_raw(c, email).status_code == 303
            confirm_registration(email)
            assert c.post("/forgot-password", data={"email": email}).status_code == 303
            tokens = _reset_tokens(email)
            assert len(tokens) == 1
            assert _register_raw(c, email).headers["location"] == "/login?registered=1"
        with _client() as c:
            page = c.get("/reset-password", params={"token": tokens[0]})
            assert page.status_code == 200 and 'name="new_password"' in page.text
    finally:
        _drop_user(email)


def test_unconfirmed_account_gets_a_notice_and_the_owner_takes_it_back_by_reset():
    httpx.delete(f"{MAILPIT}/api/v1/messages", timeout=5)
    email = _unique("neutral-unconfirmed")
    p1, p2, p3 = "First-Owner-2026!", "Second-Try-2026!", "Real-Owner-2026!"
    try:
        with _client(follow_redirects=False) as c:
            assert _register_raw(c, email, p1).status_code == 303
            before = _account_state(email)
            again = _register_raw(c, email, p2)
            assert again.headers["location"] == "/login?registered=1"
        assert _account_state(email) == before
        assert len(verification_messages(email)) == 1
        assert len(account_notices(email)) == 1
        with _client() as c:
            assert "sent=1" in str(c.post("/forgot-password", data={"email": email}).url)
            token = _reset_tokens(email)[0]
            done = c.post("/reset-password", data={"token": token, "new_password": p3, "confirm_password": p3})
            assert done.status_code == 200, done.status_code
        assert _psql(f"SELECT email_verified_at IS NOT NULL FROM users WHERE email = '{email}'") == ["t"]
        with _client() as c:
            assert c.post("/login", data={"email": email, "password": p1}).status_code == 401
            assert c.post("/login", data={"email": email, "password": p3}).url.path == "/me"
    finally:
        _drop_user(email)


def test_blocked_patient_and_staff_get_the_same_answer_and_a_notice():
    httpx.delete(f"{MAILPIT}/api/v1/messages", timeout=5)
    blocked = _unique("neutral-blocked")
    fresh = _unique("neutral-fresh")
    try:
        with _client(follow_redirects=False) as c:
            assert _register_raw(c, blocked).status_code == 303
            confirm_registration(blocked)
            _psql(f"UPDATE users SET blocked = TRUE WHERE email = '{blocked}'")
            new = _register_raw(c, fresh)
            for email in (blocked, DOC):
                answer = _register_raw(c, email)
                assert _shape(answer) == _shape(new), email
                assert len(account_notices(email)) == 1, email
    finally:
        _drop_user(blocked)
        _drop_user(fresh)


def test_taken_email_limit_five_notices_then_429():
    httpx.delete(f"{MAILPIT}/api/v1/messages", timeout=5)
    clear_registration_attempts()
    with _client(follow_redirects=False) as c:
        codes = [_register_raw(c, PAT).status_code for _ in range(6)]
    assert codes == [303] * 5 + [429], codes
    assert len(account_notices(PAT)) == 5
    clear_registration_attempts()


def test_smtp_failure_is_the_same_for_new_and_taken_email_and_logs_one_line():
    fresh = _unique("neutral-smtp")
    script = f"""
import json
from starlette.requests import Request
import routes_auth
import smtplib

def boom(*args, **kwargs):
    raise smtplib.SMTPRecipientsRefused({{args[0] if args else "x": (550, b"no")}})

routes_auth.send_email_verification = boom
routes_auth.send_existing_account_notice = boom

def request(path):
    return Request({{"type": "http", "method": "POST", "path": path, "headers": [],
                    "query_string": b"", "client": ("10.200.0.9", 4000), "session": {{}},
                    "server": ("test", 80), "scheme": "http"}})

answers = []
for email in ({fresh!r}, {PAT!r}):
    r = routes_auth.register(request("/register"), email=email, password={NEW_PASSWORD!r},
                             confirm_password={NEW_PASSWORD!r}, full_name="Smtp Down", phone="+374 10 101010")
    answers.append([r.status_code, r.headers["location"]])
print(json.dumps(answers))
"""
    try:
        completed = subprocess.run(
            ["docker", "compose", "exec", "-T", "api", "python", "-"],
            input=script, cwd=ROOT, capture_output=True, text=True,
        )
        assert completed.returncode == 0, completed.stderr[-2000:]
        import json
        answers = json.loads(completed.stdout.strip().splitlines()[-1])
        assert answers == [[303, "/login?registered=1&mail=failed"]] * 2, answers
        output = completed.stdout + completed.stderr
        assert output.count("could not send registration email (SMTPRecipientsRefused)") == 2, output
        for leak in (fresh, PAT, "send_existing_account_notice", "send_email_verification", "Traceback"):
            assert leak not in output, leak
    finally:
        _drop_user(fresh)
        clear_registration_attempts()


def test_register_route_and_login_page_have_no_taken_answer():
    source = (ROOT / "app" / "routes_auth.py").read_text()
    body = source[source.index("def register(\n"):source.index('@router.post("/login")')]
    assert "already exists" not in body and "409" not in body
    assert "exc_info" not in body and "log.exception" not in body[body.index("send_existing_account_notice"):]
    assert "Account created" not in (ROOT / "app" / "templates" / "login.html").read_text()
