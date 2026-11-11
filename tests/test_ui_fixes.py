"""Small UI fixes after the Bootstrap redesign."""
import os
import re
from pathlib import Path

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
    assert '<form class="nav-form" method="post" action="/logout"><input type="hidden" name="csrf_token" value="' in menu
    assert "Manage staff" not in desktop


def test_non_admin_menu_has_no_admin_links():
    with _client() as c:
        assert "Cabinet" in c.post("/login", data={"email": "reg@clinic.local", "password": PASSWORD}).text
        html = c.get("/registrar/patients").text
    assert "/admin/" not in html and "cabinet-menu" not in html
