"""UI refresh guard rails: security headers, CSP-safe templates and static files."""
import hashlib
import os
import re
from html.parser import HTMLParser
from pathlib import Path

import httpx
import pytest

from tests.csrf_client import CsrfClient
from tests.demo_secret import demo_password

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "app" / "templates"
STATIC = ROOT / "app" / "static"
BOOTSTRAP = STATIC / "vendor" / "bootstrap" / "bootstrap.min.css"
BASE = os.environ.get("CLINIC_TEST_BASE", "http://localhost:8080")
PASSWORD = demo_password()

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "font-src 'self'; connect-src 'self'; frame-src 'none'; worker-src 'none'; "
    "manifest-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; "
    "frame-ancestors 'none'"
)
SECURITY_HEADERS = {
    "content-security-policy": CSP,
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "x-frame-options": "DENY",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
}

ROLE_PAGES = {
    "patient": ("pat@clinic.local", ["/", "/doctors", "/me", "/my", "/my/records"]),
    "doctor": ("doc@clinic.local", ["/", "/doctors", "/me", "/doctor/appointments",
                                    "/doctor/patients", "/doctor/calendar",
                                    "/doctor/calendar?view=week"]),
    "registrar": ("reg@clinic.local", ["/", "/doctors", "/me", "/registrar/appointments",
                                       "/registrar/appointments?view=week", "/registrar/patients"]),
    "admin": ("admin@clinic.local", ["/", "/doctors", "/me", "/admin/users", "/admin/doctors",
                                     "/admin/doctors/new", "/admin/services", "/admin/settings",
                                     "/admin/schedule", "/admin/audit"]),
}
GUEST_PAGES = ["/", "/doctors", "/login", "/register", "/forgot-password",
               "/reset-password?token=" + "0" * 64, "/confirm-email?token=" + "0" * 64]


def _client(**kwargs):
    return CsrfClient(base_url=BASE, follow_redirects=True, timeout=10.0, **kwargs)


def _assert_security_headers(response, where):
    for name, value in SECURITY_HEADERS.items():
        values = response.headers.get_list(name)
        assert values == [value], f"{where}: {name} = {values!r}"
    assert "content-security-policy-report-only" not in response.headers, where
    assert "strict-transport-security" not in response.headers, where
    assert "x-xss-protection" not in response.headers, where


class _Assets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "link" and attrs.get("href"):
            self.urls.append(attrs["href"])
        if tag in ("script", "img") and attrs.get("src"):
            self.urls.append(attrs["src"])


def _asset_urls(html):
    parser = _Assets()
    parser.feed(html)
    return parser.urls


# --- headers on every kind of response -------------------------------------

@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/login",
        "/doctors",
        "/reset-password?token=" + "0" * 64,
        "/confirm-email?token=" + "0" * 64,
        "/no-such-page",
        "/static/app.css",
        "/static/no-such-file.css",
        "/static/",
    ],
)
def test_security_headers_on_every_location(path):
    response = httpx.get(BASE + path, timeout=10.0)
    _assert_security_headers(response, path)


def test_security_headers_on_post_and_redirect():
    with _client() as c:
        wrong = c.post("/login", data={"email": "nobody@clinic.local", "password": "x"})
        _assert_security_headers(wrong, "POST /login")
    redirect = httpx.get(BASE + "/me", timeout=10.0, follow_redirects=False)
    assert redirect.status_code in (302, 303, 307)
    _assert_security_headers(redirect, "redirect /me")


def test_html_is_not_stored_and_static_is_versioned():
    with _client() as c:
        c.post("/login", data={"email": "pat@clinic.local", "password": PASSWORD})
        page = c.get("/my/records")
        assert page.status_code == 200
        assert page.headers.get_list("cache-control") == ["no-store"]
        urls = _asset_urls(page.text)
    static_urls = [u for u in urls if u.startswith("/static/")]
    assert static_urls and all(re.search(r"\?v=[0-9a-f]{16}$", u) for u in static_urls), urls
    for url in static_urls:
        asset = httpx.get(BASE + url, timeout=10.0)
        assert asset.status_code == 200, url
        assert asset.headers["cache-control"] == "public, max-age=31536000, immutable", url
    plain = httpx.get(BASE + "/static/app.css", timeout=10.0)
    assert plain.headers["cache-control"] == "no-cache"


def test_static_never_carries_a_session_cookie():
    with _client() as c:
        c.post("/login", data={"email": "pat@clinic.local", "password": PASSWORD})
        asset = c.get("/static/app.css")
        assert asset.status_code == 200
        assert "set-cookie" not in asset.headers


@pytest.mark.parametrize(
    "path,mime",
    [
        ("/static/vendor/bootstrap/bootstrap.min.css", "text/css"),
        ("/static/app.css", "text/css"),
        ("/static/app.js", ("text/javascript", "application/javascript")),
        ("/static/img/logo.svg", "image/svg+xml"),
    ],
)
def test_static_mime_types(path, mime):
    response = httpx.get(BASE + path, timeout=10.0)
    assert response.status_code == 200
    content_type = response.headers["content-type"].split(";")[0].strip()
    assert content_type in (mime if isinstance(mime, tuple) else (mime,)), content_type


@pytest.mark.parametrize("path", ["/static/", "/static/img/", "/static/vendor/", "/static/vendor/bootstrap/"])
def test_static_has_no_directory_listing(path):
    response = httpx.get(BASE + path, timeout=10.0)
    assert response.status_code == 404
    assert "Index of" not in response.text
    assert not re.search(r'href="(app\.css|app\.js|logo\.svg|img/|vendor/)', response.text)


@pytest.mark.parametrize("path", ["/static/../main.py", "/static/%2e%2e/main.py", "/static/..%2fmain.py",
                                  "/static/%2e%2e/%2e%2e/run/secrets/session_secret"])
def test_static_cannot_escape_its_folder(path):
    response = httpx.get(BASE + path, timeout=10.0)
    assert response.status_code in (400, 404)
    assert "SESSION_SECRET" not in response.text and "from fastapi" not in response.text


# --- every role renders its pages, all assets same-origin --------------------

def _check_page(c, path):
    response = c.get(path)
    assert response.status_code == 200, (path, response.status_code)
    assert "Traceback" not in response.text and "jinja2" not in response.text.lower(), path
    _assert_security_headers(response, path)
    assert response.headers.get_list("cache-control") == ["no-store"], path
    for url in _asset_urls(response.text):
        assert url.startswith("/") and not url.startswith("//"), (path, url)


@pytest.mark.parametrize("role", sorted(ROLE_PAGES))
def test_role_pages_render(role):
    email, pages = ROLE_PAGES[role]
    with _client() as c:
        assert "Cabinet" in c.post("/login", data={"email": email, "password": PASSWORD}).text
        for path in pages:
            _check_page(c, path)
        doctors = c.get("/doctors").text
        slot_link = re.search(r'href="(/doctors/\d+/slots[^"]*)"', doctors)
        if role in ("patient", "registrar", "admin"):
            assert slot_link, role
            _check_page(c, slot_link.group(1).replace("&amp;", "&"))


def test_guest_pages_render():
    with _client() as c:
        for path in GUEST_PAGES:
            response = c.get(path)
            assert response.status_code in (200, 400), (path, response.status_code)
            assert "Traceback" not in response.text, path
            _assert_security_headers(response, path)


# --- static checks: templates, JS, CSS, SVG, vendored Bootstrap ---------------

def _templates():
    files = sorted(TEMPLATES.glob("*.html"))
    assert files
    return files


@pytest.mark.parametrize("pattern,why", [
    (r"\sstyle\s*=", "inline style attribute"),
    (r"<style\b", "inline <style> block"),
    (r"\son[a-z]+\s*=", "inline event handler"),
    (r"<script\b(?![^>]*\bsrc=)", "inline <script>"),
    (r"javascript:", "javascript: URL"),
    (r"\bdata:", "data: URI"),
    (r"\|\s*safe\b|Markup\(", "autoescape bypass"),
    (r"https?://", "external URL"),
])
def test_templates_are_csp_clean(pattern, why):
    for path in _templates():
        text = path.read_text(encoding="utf-8")
        match = re.search(pattern, text, re.I)
        assert not match, f"{path.name}: {why}: {match.group(0)!r}"


def test_data_attributes_are_quoted_and_carry_no_personal_data():
    for path in _templates():
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"\sdata-[a-z-]+(\s*=\s*)?([^\s>]*)", text):
            if match.group(1) is None:
                continue  # boolean data attribute
            value = match.group(2)
            assert value.startswith('"'), f"{path.name}: unquoted {match.group(0)!r}"
        for match in re.finditer(r'\sdata-[a-z-]+="([^"]*)"', text):
            value = match.group(1).lower()
            for forbidden in ("email", "token", "csrf", "note", "prescription", "body"):
                assert forbidden not in value, f"{path.name}: {match.group(0)!r}"


def test_app_js_avoids_dangerous_apis():
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    for pattern in (r"innerHTML", r"outerHTML", r"insertAdjacentHTML", r"document\.write",
                    r"\beval\s*\(", r"new\s+Function", r"set(Timeout|Interval)\s*\(\s*['\"`]",
                    r"document\.cookie", r"localStorage", r"sessionStorage", r"csrf",
                    r"\.setAttribute\(\s*['\"]style", r"https?://"):
        assert not re.search(pattern, js, re.I), pattern


def test_static_folder_allowlist():
    files = [p for p in STATIC.rglob("*") if p.is_file() or p.is_symlink()]
    assert files
    for path in files:
        rel = path.relative_to(STATIC).as_posix()
        assert not path.is_symlink(), rel
        assert not any(part.startswith(".") for part in path.relative_to(STATIC).parts), rel
        assert path.suffix in (".css", ".js", ".svg") or path.name == "LICENSE", rel


def test_svgs_are_inert():
    svgs = list(STATIC.rglob("*.svg"))
    assert svgs
    for path in svgs:
        text = path.read_text(encoding="utf-8")
        for pattern in (r"<script", r"\son[a-z]+\s*=", r"href\s*=", r"<foreignObject", r"data:",
                        r"javascript:", r"<!ENTITY", r"<style"):
            assert not re.search(pattern, text, re.I), (path.name, pattern)


def test_app_css_uses_only_same_origin_urls():
    css = re.sub(r"/\*.*?\*/", "", (STATIC / "app.css").read_text(encoding="utf-8"), flags=re.S)
    assert "@import" not in css
    for url in re.findall(r"url\(\s*['\"]?([^'\")]+)", css):
        # Absolute: url() inside a custom property resolves against the stylesheet using it.
        assert url.startswith("/static/") and not url.startswith("//"), url
        assert (STATIC / url.removeprefix("/static/")).is_file(), url


def test_bootstrap_data_uris_are_overridden_or_unused():
    """img-src is 'self' only: Bootstrap's data: icons must never be requested."""
    css = BOOTSTRAP.read_text(encoding="utf-8")
    assert "sourceMappingURL" not in css
    assert "@import" not in css and "@font-face" not in css
    assert not re.search(r"url\((?!\"?data:)", css), "Bootstrap must not load external files"
    app_css = (STATIC / "app.css").read_text(encoding="utf-8")
    for overridden in ("--bs-form-select-bg-img", "--bs-form-check-bg-image"):
        assert f"{overridden}: url(\"/static/img/" in app_css, overridden
    unused = ("is-valid", "is-invalid", "was-validated", "form-switch", "navbar-toggler",
              "accordion", "btn-close", "carousel")
    for path in _templates():
        text = path.read_text(encoding="utf-8")
        for name in unused:
            assert not re.search(rf"class=\"[^\"]*\b{name}\b", text), (path.name, name)
    assert not re.search(r"\b(is-valid|is-invalid|was-validated)\b", (STATIC / "app.js").read_text())


def test_bootstrap_checksum_matches_docs():
    digest = hashlib.sha256(BOOTSTRAP.read_bytes()).hexdigest()
    docs = (ROOT / "docs" / "sec_doc.md").read_text(encoding="utf-8")
    assert "Bootstrap 5.3.8" in docs
    assert digest in docs, digest
    assert (BOOTSTRAP.parent / "LICENSE").read_text(encoding="utf-8").startswith("The MIT License")


def test_nginx_includes_security_headers_in_every_location():
    conf = (ROOT / "docker" / "proxy" / "nginx.conf").read_text(encoding="utf-8")
    snippet = (ROOT / "docker" / "proxy" / "security_headers.conf").read_text(encoding="utf-8")
    blocks = re.findall(r"location\s+[^{]+\{(.*?)\n    \}", conf, re.S)
    assert len(blocks) >= 4
    for block in blocks:
        assert "include /etc/nginx/clinic/security_headers.conf;" in block, block
        if "proxy_pass" in block:
            for header in ("Host", "Cookie", "X-Real-IP"):
                assert f"proxy_set_header {header}" in block, block
    for line in snippet.splitlines():
        if line.startswith("add_header"):
            assert line.rstrip().endswith(" always;"), line
    assert "unsafe-inline" not in snippet and "unsafe-eval" not in snippet
    assert "Content-Security-Policy-Report-Only" not in snippet
    assert "access_log /var/log/nginx/access.log clinic_path;" in conf.split("location", 1)[0]
