"""Fixes from the security audit: read journal on /my, auth events, time-off overlap."""
import os
import subprocess
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
