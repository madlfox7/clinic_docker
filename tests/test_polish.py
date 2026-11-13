"""16_polish: error pages, confirmations, neutral registration, one login
answer, patient cancel/reschedule deadline."""
import os
import re
import subprocess
import uuid
from pathlib import Path

import httpx

from tests.csrf_client import CsrfClient
from tests.test_ux_filters import _psql, _psql_try

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

