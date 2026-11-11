"""Small UI fixes after the Bootstrap redesign."""
import os
import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlencode

import pytest

from tests.csrf_client import CsrfClient
from tests.demo_secret import demo_password

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = demo_password()

BASE = os.environ.get("CLINIC_TEST_BASE", "http://localhost:8080")


def _client(**kwargs):
    return CsrfClient(base_url=BASE, follow_redirects=True, timeout=10.0, **kwargs)


def test_home_has_no_made_up_hours():
    with _client() as c:
        page = c.get("/")
    assert page.status_code == 200
    assert "demo hours" not in page.text
    assert "Hours:" not in page.text



def test_status_badge_classes_come_from_a_fixed_table():
    templates = ROOT / "app" / "templates"
    macro = (templates / "_status.html").read_text(encoding="utf-8")
    for status, css in (("scheduled", "text-bg-primary"), ("completed", "text-bg-success"),
                        ("cancelled", "text-bg-secondary")):
        assert f'"{status}": "{css}"' in macro
    assert "{{ classes.get(status, 'text-bg-light border') }}\">{{ status }}</span>" in macro
    for path in templates.glob("*.html"):
        text = path.read_text(encoding="utf-8")
        # A raw status must never be written into a class attribute.
        assert not re.search(r'class="[^"]*\{\{[^}]*status[^}]*\}\}', text.replace("classes.get(status", "")), path.name



def test_admin_menu_uses_short_labels_and_keeps_every_link():
    with _client() as c:
        assert "Cabinet" in c.post("/login", data={"email": "admin@clinic.local", "password": PASSWORD}).text
        html = c.get("/admin/audit").text
    desktop = html.split('<nav class="d-none d-lg-block"', 1)[1].split("</nav>", 1)[0]
    for href, label in (("/admin/users", "Staff"), ("/admin/doctors", "Doctors"), ("/admin/services", "Services"),
                        ("/admin/schedule", "Schedule"), ("/admin/audit", "Audit")):
        assert re.search(rf'href="{href}"[^>]*>{label}</a>', desktop), label
    menu = desktop.split('<details class="cabinet-menu">', 1)[1].split("</details>", 1)[0]
    assert 'href="/me"' in menu and 'href="/admin/settings"' in menu
    assert '<form class="nav-form" method="post" action="/logout" data-confirm="Выйти из системы?"><input type="hidden" name="csrf_token" value="' in menu
    assert "Manage staff" not in desktop


def test_non_admin_menu_has_no_admin_links():
    with _client() as c:
        assert "Cabinet" in c.post("/login", data={"email": "reg@clinic.local", "password": PASSWORD}).text
        html = c.get("/registrar/patients").text
    assert "/admin/" not in html and "cabinet-menu" not in html


def test_week_grid_only_from_lg_and_day_list_below():
    with _client() as c:
        assert "Cabinet" in c.post("/login", data={"email": "reg@clinic.local", "password": PASSWORD}).text
        html = c.get("/registrar/appointments?view=week").text
    assert '<div class="card d-none d-lg-block">' in html and "calendar-week" in html
    assert '<div class="d-lg-none">' in html
    assert "d-md-block" not in html.split("Week of", 1)[1]


# --- guest "Book" -> login -> that doctor's slots (item 4) -------------------
# Only ?doctor=<int> is supported. The server builds the slots path itself; a free-form
# "next" is never read, and every bad value ends at the role's default page (/me).

PAT = "pat@clinic.local"
DOC = "doc@clinic.local"
DOC2 = "doc2@clinic.local"
REG = "reg@clinic.local"
ADMIN = "admin@clinic.local"


def _active_doctor_id():
    with _client() as c:
        match = re.search(r'href="/login\?doctor=(\d+)"', c.get("/doctors").text)
    assert match, "guest doctor card has no Book link"
    return match.group(1)


def _login_with(email, fields=(), query=""):
    with _client() as c:
        c.get("/login" + query)
        data = [("email", email), ("password", PASSWORD), ("csrf_token", c.csrf_token()), *fields]
        # Raw urlencoded body so repeated fields (doctor=1&doctor=2) really are sent twice.
        return c.post(
            "/login" + query,
            content=urlencode(data),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            csrf=False,
        )


def test_guest_book_leads_to_login_then_to_that_doctors_slots():
    doctor_id = _active_doctor_id()
    with _client() as c:
        login_page = c.get(f"/login?doctor={doctor_id}")
        assert login_page.status_code == 200
        assert f'<input type="hidden" name="doctor" value="{doctor_id}">' in login_page.text
        landed = c.post("/login", data={"email": PAT, "password": PASSWORD, "doctor": doctor_id})
    assert landed.status_code == 200
    assert landed.url.path == f"/doctors/{doctor_id}/slots"
    assert "Slots:" in landed.text


@pytest.mark.parametrize("value", [
    "abc", "-1", "+1", "0", " 1", "1 ", "\u00b2", "\u0661", "1e3", "0x1",
    "99999999999999999999", "2147483648", "1234567890", "",
])
def test_bad_doctor_values_end_at_the_default_page(value):
    response = _login_with(PAT, [("doctor", value)])
    assert response.status_code == 200
    assert response.url.path == "/me"


def test_nonexistent_doctor_ends_at_the_default_page():
    response = _login_with(PAT, [("doctor", "999999999")])
    assert response.status_code == 200 and response.url.path == "/me"


def test_inactive_doctor_ends_at_the_default_page():
    from tests.test_stage4 import psql

    doctor_id = psql(f"SELECT d.id FROM doctors d JOIN users u ON u.id = d.user_id WHERE u.email = '{DOC2}'")
    assert doctor_id.isdigit()
    psql(f"UPDATE users SET blocked = TRUE WHERE email = '{DOC2}'")
    try:
        response = _login_with(PAT, [("doctor", doctor_id)])
        assert response.status_code == 200 and response.url.path == "/me"
    finally:
        psql(f"UPDATE users SET blocked = FALSE WHERE email = '{DOC2}'")


def test_duplicate_doctor_values_are_ignored():
    doctor_id = _active_doctor_id()
    response = _login_with(PAT, [("doctor", doctor_id), ("doctor", doctor_id)])
    assert response.status_code == 200 and response.url.path == "/me"
    response = _login_with(PAT, [("doctor", "1"), ("doctor", "2")])
    assert response.status_code == 200 and response.url.path == "/me"


@pytest.mark.parametrize("email", [DOC, REG, ADMIN])
def test_staff_logins_ignore_the_doctor_value(email):
    doctor_id = _active_doctor_id()
    for value in (doctor_id, ""):
        response = _login_with(email, [("doctor", value)])
        assert response.status_code == 200 and response.url.path == "/me", (email, value)


@pytest.mark.parametrize("target", [
    "//evil.com", "https://evil.com", "/\\evil.com", "javascript:alert(1)", "/%2f%2fevil.com", "/doctors/1/slots",
])
def test_next_parameter_is_ignored(target):
    from urllib.parse import quote

    response = _login_with(PAT, [("next", target)], query="?next=" + quote(target, safe=""))
    assert response.status_code == 200 and response.url.path == "/me"
    assert all(r.headers.get("location", "/").startswith("/") and not r.headers.get("location", "/").startswith("//")
               for r in response.history)
    doctor_id = _active_doctor_id()
    response = _login_with(PAT, [("doctor", doctor_id), ("next", target)])
    assert response.url.path == f"/doctors/{doctor_id}/slots"


def test_login_form_never_reflects_a_raw_doctor_value():
    raw = '1"><b>x</b>'
    with _client() as c:
        page = c.get("/login", params={"doctor": raw})
        assert 'name="doctor"' not in page.text and "<b>x</b>" not in page.text
        failed = c.post("/login", data={"email": PAT, "password": "wrong-password-1", "doctor": raw})
        assert failed.status_code == 401
        assert 'name="doctor"' not in failed.text and "<b>x</b>" not in failed.text
        failed = c.post("/login", data={"email": PAT, "password": "wrong-password-1", "doctor": "7"})
        assert failed.status_code == 401
        assert '<input type="hidden" name="doctor" value="7">' in failed.text


def test_register_and_reset_links_do_not_carry_the_doctor():
    with _client() as c:
        page = c.get("/login?doctor=1").text
    assert 'href="/register"' in page and 'href="/forgot-password"' in page
    assert "doctor=" not in page.split("</form>", 1)[1]


def test_blocked_patient_with_doctor_value_stays_logged_out():
    from tests.test_stage4 import PAT2, psql

    doctor_id = _active_doctor_id()
    psql(f"UPDATE users SET blocked = TRUE WHERE email = '{PAT2}'")
    try:
        with _client() as c:
            response = c.post("/login", data={"email": PAT2, "password": PASSWORD, "doctor": doctor_id})
            assert response.status_code == 403 and "Account is blocked" in response.text
            assert c.get(f"/doctors/{doctor_id}/slots").url.path == "/login"
    finally:
        psql(f"UPDATE users SET blocked = FALSE WHERE email = '{PAT2}'")


# --- logout confirmation -----------------------------------------------------
# Every logout form (nav, admin <details>, mobile menu, already-logged-in login
# page) asks before submitting. Cancel is handled in app.js via data-confirm.

LOGOUT_CONFIRM = "Выйти из системы?"

_ROLE_PAGES = {
    PAT: ("/", "/doctors", "/me", "/my", "/my/records", "/login"),
    DOC: ("/", "/me", "/doctor/appointments", "/doctor/patients", "/doctor/calendar", "/login"),
    REG: ("/", "/me", "/registrar/appointments", "/registrar/patients", "/login"),
    ADMIN: ("/", "/me", "/admin/users", "/admin/doctors", "/admin/services",
            "/admin/schedule", "/admin/audit", "/admin/settings", "/login"),
}


class _LogoutForms(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self._in_form = 0

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "form" and attrs_dict.get("action") == "/logout":
            self.forms.append({
                "attrs": attrs_dict,
                "handlers": [name for name, _ in attrs if name.lower().startswith("on")],
                "inline_script": False,
            })
            self._in_form += 1
        elif self._in_form:
            if tag == "form":
                self._in_form += 1
            if any(name.lower().startswith("on") for name, _ in attrs):
                self.forms[-1]["handlers"].extend(
                    name for name, _ in attrs if name.lower().startswith("on")
                )
            if tag == "script" and "src" not in attrs_dict:
                self.forms[-1]["inline_script"] = True

    def handle_endtag(self, tag):
        if self._in_form and tag == "form":
            self._in_form -= 1


def _logout_forms(html):
    parser = _LogoutForms()
    parser.feed(html)
    return parser.forms


def test_templates_put_data_confirm_on_every_logout_form():
    templates = ROOT / "app" / "templates"
    found = 0
    for path in templates.glob("*.html"):
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r'<form\b[^>]*action="/logout"[^>]*>', text):
            found += 1
            tag = match.group(0)
            assert f'data-confirm="{LOGOUT_CONFIRM}"' in tag, path.name
            assert not re.search(r"\son[a-z]+\s*=", tag, re.I), path.name
    assert found == 2


@pytest.mark.parametrize("email,pages", list(_ROLE_PAGES.items()))
def test_logout_forms_ask_for_confirmation(email, pages):
    with _client() as c:
        assert "Cabinet" in c.post("/login", data={"email": email, "password": PASSWORD}).text
        for path in pages:
            page = c.get(path)
            assert page.status_code == 200, (email, path, page.status_code)
            forms = _logout_forms(page.text)
            expected = 3 if path == "/login" else 2
            assert len(forms) == expected, (email, path, len(forms))
            for form in forms:
                assert form["attrs"].get("method", "").lower() == "post"
                assert form["attrs"].get("data-confirm") == LOGOUT_CONFIRM
                assert form["handlers"] == []
                assert not form["inline_script"]
            assert not re.search(r"<script\b(?![^>]*\bsrc=)", page.text, re.I)
            # Admin desktop: logout lives inside the cabinet <details>.
            if email == ADMIN and path != "/login":
                desktop = page.text.split('<nav class="d-none d-lg-block"', 1)[1].split("</nav>", 1)[0]
                menu = desktop.split('<details class="cabinet-menu">', 1)[1].split("</details>", 1)[0]
                menu_forms = _logout_forms(menu)
                assert len(menu_forms) == 1
                assert menu_forms[0]["attrs"].get("data-confirm") == LOGOUT_CONFIRM
            # Mobile menu always carries its own logout form.
            mobile = page.text.split('<details class="mobile-nav', 1)[1].split("</details>", 1)[0]
            mobile_forms = _logout_forms(mobile)
            assert len(mobile_forms) == 1
            assert mobile_forms[0]["attrs"].get("data-confirm") == LOGOUT_CONFIRM
