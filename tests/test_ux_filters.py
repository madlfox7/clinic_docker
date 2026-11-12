"""UX filters, pagination and reschedule (14_ux_filters.md): /doctors, slots,
/my, audit log, appointment reschedule, registrar calendar."""
import os
import re
import subprocess
import uuid
from pathlib import Path

import httpx

from tests.csrf_client import CsrfClient
from tests.demo_secret import demo_password
from tests.field_key import seal_pending, sql_packet

ROOT = Path(__file__).resolve().parents[1]
BASE = os.environ.get("CLINIC_TEST_BASE", "http://localhost:8080")
MAILPIT = os.environ.get("CLINIC_MAILPIT", "http://localhost:8025")
PASSWORD = demo_password()
PAT = "pat@clinic.local"
PAT2 = "pat2@clinic.local"
DOC = "doc@clinic.local"
DOC2 = "doc2@clinic.local"
REG = "reg@clinic.local"
ADMIN = "admin@clinic.local"
PAT_NAME, PAT_PHONE = "Narek Hakobyan", "+374 10 123456"
RAW_DATETIME = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")


def _client(**kwargs):
    return CsrfClient(base_url=BASE, follow_redirects=True, timeout=15.0, **kwargs)


def _psql_try(sql: str) -> subprocess.CompletedProcess:
    completed = subprocess.run(
        ["docker", "compose", "exec", "-T", "db", "psql", "-X", "-q", "-U", "clinic",
         "-d", "clinic", "-v", "ON_ERROR_STOP=1", "-At", "-F", "|", "-c", sql],
        cwd=ROOT, capture_output=True, text=True,
    )
    return completed


def _psql(sql: str) -> list[str]:
    completed = _psql_try(sql)
    assert completed.returncode == 0, completed.stderr or completed.stdout
    return [line for line in completed.stdout.splitlines() if line.strip()]


def _as_role(role: str, user_id: int, sql: str) -> subprocess.CompletedProcess:
    """Run sql inside a rolled-back transaction as an application role."""
    return _psql_try(
        f"BEGIN; SET LOCAL ROLE {role}; "
        f"SELECT set_config('app.user_id', '{user_id}', true); {sql}; ROLLBACK;"
    )


def _user_id(email: str) -> int:
    return int(_psql(f"SELECT id FROM users WHERE email = '{email}'")[0])


def _doctor_id(email: str) -> int:
    return int(_psql(
        f"SELECT d.id FROM doctors d JOIN users u ON u.id = d.user_id WHERE u.email = '{email}'"
    )[0])


def _login(c, email):
    page = c.post("/login", data={"email": email, "password": PASSWORD})
    assert page.status_code == 200 and page.url.path == "/me", (email, page.status_code)
    return page


def _free_days(count: int = 1, low: int = 400, high: int = 700) -> list[str]:
    """Far-future days with no slots, holidays or time off for anyone."""
    return _psql(
        "SELECT d::date FROM generate_series(CURRENT_DATE + %d, CURRENT_DATE + %d, "
        "INTERVAL '1 day') AS d "
        "WHERE NOT EXISTS (SELECT 1 FROM holidays h WHERE h.day = d::date) "
        "AND NOT EXISTS (SELECT 1 FROM time_off t WHERE d::date BETWEEN t.starts_on AND t.ends_on) "
        "AND NOT EXISTS (SELECT 1 FROM slots s WHERE s.starts_at::date = d::date) "
        "ORDER BY random() LIMIT %d" % (low, high, count)
    )


def _make_slot(doctor_id: int, starts_at: str, service_id: int = 1) -> int:
    """A slot with the service's own duration and buffer; starts_at is an SQL literal."""
    return int(_psql(
        "INSERT INTO slots (doctor_id, service_id, starts_at, ends_at, duration_minutes, "
        "buffer_minutes) "
        f"SELECT {doctor_id}, svc.id, TIMESTAMP '{starts_at}', TIMESTAMP '{starts_at}' "
        "+ make_interval(mins => svc.duration_minutes + svc.buffer_minutes), "
        "svc.duration_minutes, svc.buffer_minutes "
        f"FROM services svc WHERE svc.id = {service_id} RETURNING id"
    )[0])


def _book_sql(slot_id: int, patient_id: int, status: str = "scheduled") -> int:
    return int(_psql(
        "INSERT INTO appointments (slot_id, patient_user_id, doctor_id, starts_at, ends_at, "
        "reserved_ends_at, status) "
        f"SELECT s.id, {patient_id}, s.doctor_id, s.starts_at, "
        "s.starts_at + make_interval(mins => s.duration_minutes), s.ends_at, "
        f"'{status}' FROM slots s WHERE s.id = {slot_id} RETURNING id"
    )[0])


def _cleanup_slots(slot_ids) -> None:
    ids = ",".join(str(int(i)) for i in slot_ids) or "0"
    _psql(
        "DELETE FROM visit_notes WHERE appointment_id IN "
        f"(SELECT id FROM appointments WHERE slot_id IN ({ids})); "
        "DELETE FROM prescriptions WHERE appointment_id IN "
        f"(SELECT id FROM appointments WHERE slot_id IN ({ids})); "
        "DELETE FROM audit_events WHERE target_type = 'appointment' AND target_id IN "
        f"(SELECT id FROM appointments WHERE slot_id IN ({ids})); "
        f"DELETE FROM appointments WHERE slot_id IN ({ids}); "
        f"DELETE FROM slots WHERE id IN ({ids})"
    )


def _status(appointment_id: int) -> str:
    return _psql(f"SELECT status FROM appointments WHERE id = {appointment_id}")[0]


# --- 1. /doctors filters and the slot date window -----------------------------

def test_doctors_filter_by_specialty_and_name_for_guest_and_patient():
    rows = _psql(
        "SELECT d.id, d.specialty, d.full_name FROM doctors d JOIN users u ON u.id = d.user_id "
        "WHERE u.role = 'doctor' AND NOT u.blocked ORDER BY d.id"
    )
    doctors = [row.split("|") for row in rows]
    first_id, first_specialty, first_name = doctors[0]
    others = [d for d in doctors if d[1] != first_specialty]
    with _client() as guest, _client() as patient:
        _login(patient, PAT)
        for c in (guest, patient):
            page = c.get("/doctors", params={"specialty": first_specialty})
            assert page.status_code == 200
            assert f"/doctors/{first_id}/slots" in page.text or f"doctor={first_id}" in page.text
            for other in others:
                assert f"/doctors/{other[0]}/slots" not in page.text
                assert f"doctor={other[0]}\"" not in page.text
            by_name = c.get("/doctors", params={"q": first_name.split()[-1][:4].lower()})
            assert first_name in by_name.text
            unknown = c.get("/doctors", params={"specialty": "No such ' OR 1=1 --"})
            assert unknown.status_code == 200
            assert "were not valid" in unknown.text
            assert all(d[2] in unknown.text for d in doctors)
            for wildcard in ("%", "_", "%%", "\\"):
                page = c.get("/doctors", params={"q": wildcard})
                assert page.status_code == 200
                assert "No doctors match these filters." in page.text
            xss = c.get("/doctors", params={"q": "<script>alert(1)</script>"})
            assert xss.status_code == 200
            assert "<script>alert(1)</script>" not in xss.text
            assert "&lt;script&gt;" in xss.text
            too_long = c.get("/doctors", params={"q": "a" * 101})
            assert too_long.status_code == 200 and "were not valid" in too_long.text
            control = c.get("/doctors", params={"q": "ab\x01"})
            assert control.status_code == 200 and "were not valid" in control.text


def test_registrar_doctor_filter_keeps_patient_email():
    with _client() as reg:
        _login(reg, REG)
        page = reg.get("/doctors", params={"patient_email": PAT2, "q": "a"})
        assert page.status_code == 200
        assert "patient_email=pat2%40clinic.local" in page.text
        assert 'name="patient_email" value="pat2@clinic.local"' in page.text


def test_slots_show_selected_window_and_hide_past_by_default():
    doctor = _doctor_id(DOC)
    past = _make_slot(doctor, _psql("SELECT (CURRENT_DATE - 3) + TIME '03:00'")[0])
    future_day = _free_days(1)[0]
    far = _make_slot(doctor, f"{future_day} 03:00")
    try:
        with _client() as reg, _client() as pat:
            _login(reg, REG)
            _login(pat, PAT)
            default = reg.get(f"/doctors/{doctor}/slots", params={"service_id": "1"})
            assert default.status_code == 200
            assert f'/slots/{far}/book' not in default.text
            past_day = _psql(f"SELECT starts_at::date FROM slots WHERE id = {past}")[0]
            assert past_day not in default.text
            back = reg.get(
                f"/doctors/{doctor}/slots",
                params={"service_id": "1", "day": past_day, "view": "day"},
            )
            assert "Past — unavailable" in back.text and past_day in back.text
            ahead = reg.get(
                f"/doctors/{doctor}/slots",
                params={"service_id": "1", "day": future_day, "view": "day"},
            )
            assert f'/slots/{far}/book' in ahead.text
            other_week = reg.get(
                f"/doctors/{doctor}/slots",
                params={"service_id": "1", "day": future_day, "view": "week",
                        "patient_email": PAT2},
            )
            assert f'/slots/{far}/book' in other_week.text
            assert "patient_email=pat2%40clinic.local" in other_week.text
            assert "service_id=1" in other_week.text
            # patient: never past or other patients' data, even for a past day
            pat_back = pat.get(
                f"/doctors/{doctor}/slots",
                params={"service_id": "1", "day": past_day, "view": "day"},
            )
            assert pat_back.status_code == 200
            assert "Past — unavailable" not in pat_back.text
            assert PAT2 not in pat_back.text
            for bad in ("2026-13-01", "x' OR 1=1", "1800-01-01", "2026-1-1"):
                page = pat.get(f"/doctors/{doctor}/slots", params={"day": bad})
                assert page.status_code == 200, bad
                assert "showing today" in page.text, bad
            bad_view = pat.get(f"/doctors/{doctor}/slots", params={"view": "month"})
            assert bad_view.status_code == 200 and "Invalid view" in bad_view.text
    finally:
        _cleanup_slots([past, far])


def test_registrar_can_hide_taken_slots():
    doctor = _doctor_id(DOC)
    day = _free_days(1)[0]
    taken = _make_slot(doctor, f"{day} 04:00")
    free = _make_slot(doctor, f"{day} 05:00")
    _book_sql(taken, _user_id(PAT2))
    try:
        with _client() as reg:
            _login(reg, REG)
            params = {"service_id": "1", "day": day, "view": "day"}
            page = reg.get(f"/doctors/{doctor}/slots", params=params)
            assert "Booked" in page.text and f"/slots/{free}/book" in page.text
            only_free = reg.get(f"/doctors/{doctor}/slots", params={**params, "hide_taken": "1"})
            assert "Booked" not in only_free.text and f"/slots/{free}/book" in only_free.text
    finally:
        _cleanup_slots([taken, free])
