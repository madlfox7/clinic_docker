"""UX filters, pagination and reschedule (14_ux_filters.md): /doctors, slots,
/my, audit log, appointment reschedule, registrar calendar."""
import os
import re
import subprocess
import uuid
from pathlib import Path

import httpx
import pytest

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


def age_patient_reschedules() -> None:
    """Move patients' reschedule events 25 hours back (superuser psql, tests only).

    Patients may make 3 moves in 24 hours and the volume survives between runs;
    the limit is not raised for tests and the app has no bypass.
    """
    _psql(
        "UPDATE audit_events SET created_at = created_at - INTERVAL '25 hours' "
        "WHERE action = 'appointment.reschedule' AND actor_role = 'patient'"
    )


@pytest.fixture(autouse=True)
def patient_reschedule_limit_reset():
    age_patient_reschedules()
    yield


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


# --- 3. /my: filters, pagination, readable dates ------------------------------

def _my_ids(html: str) -> list[int]:
    return [int(x) for x in re.findall(r'action="/appointments/(\d+)/cancel"', html)]


def _records_view_count(patient_id: int) -> int:
    return int(_psql(
        "SELECT count(*) FROM audit_events WHERE action = 'medical.records.view' "
        f"AND target_type = 'patient' AND target_id = {patient_id}"
    )[0])


def test_my_pagination_records_and_readable_dates():
    pat = _user_id(PAT)
    doctor = _doctor_id(DOC)
    day = _free_days(1)[0]
    slots = [
        _make_slot(doctor, f"{day} {hour:02d}:{minute:02d}")
        for hour in range(0, 13) for minute in (0, 30)
    ][:25]
    try:
        visits = [_book_sql(slot, pat) for slot in slots]
        _psql(
            "INSERT INTO visit_notes (appointment_id, doctor_id, patient_user_id, body) "
            f"SELECT a.id, a.doctor_id, a.patient_user_id, {sql_packet('visit_notes', 'ux-page-note')} "
            f"FROM appointments a WHERE a.id = {visits[0]}"
        )
        seal_pending()
        with _client() as c:
            _login(c, PAT)
            params = {"status": "upcoming", "from": day, "to": day}
            before = _records_view_count(pat)
            first = c.get("/my", params=params)
            assert first.status_code == 200
            first_ids = _my_ids(first.text)
            assert len(first_ids) == 20
            assert "ux-page-note" in first.text
            assert _records_view_count(pat) == before + 1
            assert not RAW_DATETIME.search(first.text)
            assert re.search(r"\w{3}, \d{2} \w{3} \d{4} \d{2}:\d{2}\u2013\d{2}:\d{2}", first.text)
            assert "page=2" in first.text and "Next" in first.text
            second = c.get("/my", params={**params, "page": "2"})
            second_ids = _my_ids(second.text)
            assert len(second_ids) == 5
            assert "ux-page-note" not in second.text
            assert _records_view_count(pat) == before + 1
            assert sorted(first_ids + second_ids) == sorted(visits)
            assert "Next" not in second.text
            for bad in ({"page": "0"}, {"page": "501"}, {"page": "x"}, {"status": "nope"},
                        {"from": "2026-02-30"}, {"from": day, "to": "1990-01-01"},
                        {"doctor_id": "1'--"}):
                page = c.get("/my", params=bad)
                assert page.status_code == 200, bad
                assert "Traceback" not in page.text
            assert "were not valid" in c.get("/my", params={"status": "nope"}).text
            cancelled = c.get("/my", params={"status": "cancelled", "from": day, "to": day})
            assert "No appointments match these filters." in cancelled.text
            too_wide = c.get("/my", params={"status": "all", "from": "2025-01-01", "to": "2026-12-31"})
            assert "were not valid" in too_wide.text
    finally:
        _cleanup_slots(slots)


def test_my_filters_never_show_other_patients():
    pat2 = _user_id(PAT2)
    doctor2 = _doctor_id(DOC2)
    day = _free_days(1)[0]
    slot = _make_slot(doctor2, f"{day} 06:00")
    try:
        foreign = _book_sql(slot, pat2)
        with _client() as c, _client() as other:
            _login(c, PAT)
            _login(other, PAT2)
            for status in ("upcoming", "past", "cancelled", "all"):
                for extra in ({}, {"doctor_id": str(doctor2)}, {"from": day, "to": day}):
                    page = c.get("/my", params={"status": status, **extra})
                    assert page.status_code == 200
                    assert foreign not in _my_ids(page.text)
                    assert PAT2 not in page.text
            empty = c.get("/my", params={"status": "all", "doctor_id": str(doctor2),
                                         "from": day, "to": day})
            assert _my_ids(empty.text) == []
            assert foreign in _my_ids(other.get("/my", params={"from": day, "to": day}).text)
            confirmation = c.get("/my", params={"booked": "1", "appointment_id": str(foreign)})
            assert "Appointment confirmed" not in confirmation.text
            own = other.get("/my", params={"booked": "1", "appointment_id": str(foreign),
                                           "status": "past"})
            assert "Appointment confirmed" in own.text
    finally:
        _cleanup_slots([slot])


# --- 4. Audit log: filters and keyset pagination ------------------------------

def _audit_ids(html: str) -> list[int]:
    return [int(x) for x in re.findall(r'data-audit-id="(\d+)"', html)]


def _seed_audit_rows(count: int, target_id: int) -> None:
    admin = _user_id(ADMIN)
    _psql(
        "INSERT INTO audit_events (actor_user_id, actor_role, action, target_type, target_id) "
        f"SELECT {admin}, 'admin', 'clinic.settings.update', 'clinic', {target_id} "
        f"FROM generate_series(1, {count})"
    )


def _drop_audit_rows(target_id: int) -> None:
    _psql(
        "DELETE FROM audit_events WHERE action = 'clinic.settings.update' "
        f"AND target_type = 'clinic' AND target_id = {target_id}"
    )


def test_audit_log_is_admin_only_with_any_filter():
    with _client() as pat, _client() as doc, _client() as reg, _client() as guest:
        _login(pat, PAT)
        _login(doc, DOC)
        _login(reg, REG)
        for c in (pat, doc, reg):
            for params in ({}, {"action": "auth."}, {"before_id": "5"}, {"actor": ADMIN}):
                assert c.get("/admin/audit", params=params).status_code == 403
        assert guest.get("/admin/audit", params={"action": "auth."}).url.path == "/login"
    denied = _as_role("app_registrar", _user_id(REG), "SELECT count(*) FROM audit_events")
    assert denied.returncode != 0 and "permission denied" in denied.stderr


def test_audit_log_filters_narrow_and_reject_garbage():
    target = 900_000_000 + int(uuid.uuid4().int % 1_000_000)
    _seed_audit_rows(3, target)
    try:
        with _client() as admin:
            _login(admin, ADMIN)
            base = _audit_ids(admin.get("/admin/audit").text)
            assert base
            narrowed = admin.get("/admin/audit", params={"target_type": "clinic", "target_id": str(target)})
            assert len(_audit_ids(narrowed.text)) == 3
            by_action = admin.get("/admin/audit", params={"action": "auth.login.success"})
            assert by_action.status_code == 200
            assert "clinic.settings.update" not in by_action.text.split("<tbody>", 1)[1]
            group = admin.get("/admin/audit", params={"action": "auth."})
            body = group.text.split("<tbody>", 1)[1]
            assert re.findall(r"<code>([^<]+)</code>", body)
            assert all(a.startswith("auth.") for a in re.findall(r"<code>([^<]+)</code>", body))
            role = admin.get("/admin/audit", params={"actor_role": "anonymous"})
            assert all(r == "anonymous" for r in re.findall(
                r"<td>(admin|doctor|patient|registrar|anonymous)</td>", role.text.split("<tbody>", 1)[1]))
            for bad in ({"action": "x' OR 1=1 --"}, {"actor_role": "root"},
                        {"target_type": "users; DROP"}, {"target_id": "1 OR 1=1"},
                        {"before_id": "-1"}, {"from": "2026-99-01"},
                        {"from": "2020-01-01", "to": "2026-01-01"}):
                page = admin.get("/admin/audit", params=bad)
                assert page.status_code == 200, bad
                assert "were not valid" in page.text, bad
            sqli = admin.get("/admin/audit", params={"action": "x' OR 1=1 --", "target_id": str(target)})
            assert len(_audit_ids(sqli.text)) == 3
            # actor: exact normalized email only
            reg_email_part = REG.split("@")[0]
            for partial in (reg_email_part, REG[:-3], "%", "reg@%"):
                page = admin.get("/admin/audit", params={"actor": partial})
                assert _audit_ids(page.text) == [], partial
            exact = admin.get("/admin/audit", params={"actor": "  " + ADMIN.upper() + " "})
            exact_body = exact.text.split("<tbody>", 1)[1]
            assert _audit_ids(exact.text)
            assert set(re.findall(r"<td>([^<@]+@[^<]+)</td>", exact_body)) == {ADMIN}
            missing = admin.get("/admin/audit", params={"actor": f"nobody-{uuid.uuid4().hex}@example.com"})
            assert missing.status_code == 200 and _audit_ids(missing.text) == []
            today = _psql("SELECT CURRENT_DATE")[0]
            dated = admin.get("/admin/audit", params={"from": today, "to": today, "target_id": str(target)})
            assert len(_audit_ids(dated.text)) == 3
            old = admin.get("/admin/audit", params={"from": "2001-01-01", "to": "2001-12-31"})
            assert _audit_ids(old.text) == []
    finally:
        _drop_audit_rows(target)


def test_audit_log_keyset_pages_without_gaps_or_repeats():
    target = 800_000_000 + int(uuid.uuid4().int % 1_000_000)
    _seed_audit_rows(120, target)
    try:
        expected = [int(x) for x in _psql(
            "SELECT id FROM audit_events WHERE target_type = 'clinic' "
            f"AND target_id = {target} ORDER BY id DESC"
        )]
        before = int(_psql("SELECT count(*) FROM audit_events WHERE action LIKE 'audit.%'")[0])
        with _client() as admin:
            _login(admin, ADMIN)
            params = {"target_type": "clinic", "target_id": str(target)}
            first = admin.get("/admin/audit", params=params)
            page1 = _audit_ids(first.text)
            assert page1 == expected[:50]
            next_link = re.search(r'href="(/admin/audit\?[^"]*before_id=\d+[^"]*)"', first.text)
            assert next_link and "Newest" not in first.text
            # a row on the next page disappears between requests (S-01 style delete)
            _psql(f"DELETE FROM audit_events WHERE id = {expected[60]}")
            second = admin.get(next_link.group(1).replace("&amp;", "&"))
            page2 = _audit_ids(second.text)
            assert page2 == [i for i in expected[50:101] if i != expected[60]][:50]
            assert "Newest" in second.text and "target_id=" in second.text
            third_link = re.search(r'href="(/admin/audit\?[^"]*before_id=\d+[^"]*)"', second.text)
            third = admin.get(third_link.group(1).replace("&amp;", "&"))
            page3 = _audit_ids(third.text)
            remaining = [i for i in expected if i != expected[60]]
            assert page1 + page2 + page3 == remaining
            assert len(set(page1 + page2 + page3)) == len(remaining)
            assert not re.search(r'before_id=\d+', third.text.split("Newest", 1)[-1])
            newest = re.search(r'href="(/admin/audit\?[^"]*)">Newest', third.text)
            assert _audit_ids(admin.get(newest.group(1).replace("&amp;", "&")).text) == page1
            full = admin.get("/admin/audit").text
            assert PAT_NAME not in full and PAT_PHONE not in full
            patients = admin.get("/admin/audit", params={"target_type": "patient"}).text
            assert PAT_NAME not in patients and PAT_PHONE not in patients
        after = int(_psql("SELECT count(*) FROM audit_events WHERE action LIKE 'audit.%'")[0])
        assert before == after == 0
    finally:
        _drop_audit_rows(target)


# --- 5. Reschedule (5.9) ------------------------------------------------------

import threading  # noqa: E402

NO_SUCH_ID = 2_147_000_000


def _reschedule_events(*ids) -> list[str]:
    id_list = ",".join(str(int(i)) for i in ids)
    return _psql(
        "SELECT concat_ws('|', actor_role, action, target_type, target_id, old_value, new_value, "
        "coalesce(reason, ''), coalesce(source, '')) FROM audit_events "
        f"WHERE action LIKE 'appointment.%' AND (target_id IN ({id_list}) "
        f"OR old_value IN ({id_list})) ORDER BY id"
    )


def _scheduled_on(slot_id: int) -> list[str]:
    return _psql(
        f"SELECT id FROM appointments WHERE slot_id = {slot_id} AND status IN ('scheduled', 'completed')"
    )


def _new_visits_for(patient_id: int, after_id: int) -> list[int]:
    return [int(x) for x in _psql(
        f"SELECT id FROM appointments WHERE patient_user_id = {patient_id} AND id > {after_id}"
    )]


def _max_appointment_id() -> int:
    return int(_psql("SELECT coalesce(max(id), 0) FROM appointments")[0])


class _Setup:
    """Old visit of `patient` on DOC at 10:00 of a free far-future day plus target slots."""

    def __init__(self, patient=PAT, times=("10:00", "12:00", "13:00", "14:00")):
        self.patient = _user_id(patient)
        self.doctor = _doctor_id(DOC)
        self.day = _free_days(1)[0]
        self.slots = [_make_slot(self.doctor, f"{self.day} {t}") for t in times]
        self.old_slot, self.targets = self.slots[0], self.slots[1:]
        self.old = _book_sql(self.old_slot, self.patient)
        self.extra_slots = []

    def slot(self, doctor, when, service_id=1):
        slot_id = _make_slot(doctor, when, service_id)
        self.extra_slots.append(slot_id)
        return slot_id

    def cleanup(self):
        _cleanup_slots(self.slots + self.extra_slots)


def _post_reschedule(c, appointment_id, slot_id):
    return c.post(f"/appointments/{appointment_id}/reschedule", data={"slot_id": str(slot_id)})


def test_patient_reschedules_own_visit_and_old_slot_is_free_again():
    httpx.delete(f"{MAILPIT}/api/v1/messages", timeout=5)
    s = _Setup()
    target = s.targets[0]
    try:
        with _client() as pat, _client() as pat2:
            _login(pat, PAT)
            _login(pat2, PAT2)
            my = pat.get("/my", params={"from": s.day, "to": s.day})
            assert f'href="/appointments/{s.old}/reschedule"' in my.text
            form = pat.get(f"/appointments/{s.old}/reschedule", params={"day": s.day, "view": "day"})
            assert form.status_code == 200
            assert f'name="slot_id" value="{target}"' in form.text
            assert f'name="slot_id" value="{s.old_slot}"' not in form.text
            done = _post_reschedule(pat, s.old, target)
            assert done.url.path == "/my", done.url
            assert "rescheduled=1" in str(done.url)
            assert "Appointment rescheduled" in done.text
            new_ids = _new_visits_for(s.patient, s.old)
            assert len(new_ids) == 1
            new = new_ids[0]
            assert f"appointment_id={new}" in str(done.url)
            assert _status(s.old) == "cancelled" and _status(new) == "scheduled"
            assert _psql(f"SELECT slot_id FROM appointments WHERE id = {new}") == [str(target)]
            events = _reschedule_events(s.old, new)
            assert events == [f"patient|appointment.reschedule|appointment|{new}|{s.old}|{new}||"]
            # the old slot is bookable by someone else
            again = pat2.post(f"/slots/{s.old_slot}/book")
            assert "unavailable" not in str(again.url)
            assert len(_scheduled_on(s.old_slot)) == 1
            messages = httpx.get(f"{MAILPIT}/api/v1/search", params={"query": f"to:{PAT}"},
                                 timeout=5).json().get("messages") or []
            assert any(m.get("Subject") == "Appointment rescheduled" for m in messages)
    finally:
        s.cleanup()


def test_patient_gets_one_answer_for_foreign_missing_closed_or_garbage_visits():
    s = _Setup()
    other = _Setup(patient=PAT2)
    doctor = _doctor_id(DOC)
    past_slot = s.slot(doctor, _psql("SELECT (CURRENT_DATE - 2) + TIME '04:30'")[0])
    past_visit = _book_sql(past_slot, s.patient)
    cancelled = _book_sql(s.slot(doctor, f"{s.day} 15:00"), s.patient, "cancelled")
    completed_slot = s.slot(doctor, _psql("SELECT (CURRENT_DATE - 2) + TIME '05:30'")[0])
    completed = _book_sql(completed_slot, s.patient, "completed")
    try:
        before_max = _max_appointment_id()
        with _client() as pat:
            _login(pat, PAT)
            for bad in (other.old, NO_SUCH_ID, cancelled, completed, past_visit,
                        "abc", "1e3", "-1", "0", "\u00b2", "99999999999"):
                got = pat.get(f"/appointments/{bad}/reschedule")
                assert got.url.path == "/my" and "reschedule_error=1" in str(got.url), bad
                posted = _post_reschedule(pat, bad, s.targets[0])
                assert posted.url.path == "/my" and "reschedule_error=1" in str(posted.url), bad
                assert "could not be rescheduled" in posted.text
            garbage_slot = pat.post(f"/appointments/{s.old}/reschedule", data={"slot_id": "x"})
            assert "reschedule_error=1" in str(garbage_slot.url)
        assert _status(other.old) == "scheduled" and _status(s.old) == "scheduled"
        assert _max_appointment_id() == before_max
        assert _reschedule_events(other.old, s.old, cancelled, completed, past_visit) == []
    finally:
        s.cleanup()
        other.cleanup()


def test_patient_new_slot_must_match_and_be_free():
    s = _Setup()
    doc2 = _doctor_id(DOC2)
    service_name = f"UX service {uuid.uuid4().hex[:8]}"
    service = int(_psql(
        f"INSERT INTO services (name, duration_minutes, buffer_minutes) VALUES ('{service_name}', 30, 0) "
        "RETURNING id")[0])
    _psql(f"INSERT INTO doctor_services (doctor_id, service_id) VALUES ({s.doctor}, {service})")
    holiday = _free_days(1)[0]
    _psql(f"INSERT INTO holidays (day, name) VALUES ('{holiday}', 'UX closed day')")
    try:
        other_doctor = s.slot(doc2, f"{s.day} 12:00")
        other_service = s.slot(s.doctor, f"{s.day} 16:00", service)
        past = s.slot(s.doctor, _psql("SELECT (CURRENT_DATE - 1) + TIME '05:00'")[0])
        closed = s.slot(s.doctor, f"{holiday} 09:00")
        taken = s.targets[1]
        _book_sql(taken, _user_id(PAT2))
        before_max = _max_appointment_id()
        with _client() as pat:
            _login(pat, PAT)
            for slot_id, code in ((other_doctor, "slot_mismatch"), (other_service, "slot_mismatch"),
                                  (past, "unavailable"), (closed, "unavailable"),
                                  (taken, "unavailable"), (s.old_slot, "same_slot"),
                                  (NO_SUCH_ID, "unavailable")):
                page = _post_reschedule(pat, s.old, slot_id)
                assert page.url.path == f"/appointments/{s.old}/reschedule", (slot_id, page.url)
                assert f"error={code}" in str(page.url), (slot_id, code, page.url)
                assert "Reschedule failed." in page.text
                assert _status(s.old) == "scheduled"
        assert _max_appointment_id() == before_max
        assert _reschedule_events(s.old) == []
    finally:
        s.cleanup()
        _psql(f"DELETE FROM holidays WHERE day = '{holiday}'")
        _psql(f"DELETE FROM doctor_services WHERE service_id = {service}; "
              f"DELETE FROM services WHERE id = {service}")


def test_patient_overlap_with_other_visit_keeps_original():
    s = _Setup()
    try:
        own_other = s.slot(_doctor_id(DOC2), f"{s.day} 12:00")
        _book_sql(own_other, s.patient)
        with _client() as pat:
            _login(pat, PAT)
            page = _post_reschedule(pat, s.old, s.targets[0])
            assert "error=overlap" in str(page.url)
            query = str(page.url).split("?", 1)[1]
            assert query == "error=overlap"
            assert _status(s.old) == "scheduled"
            assert _scheduled_on(s.targets[0]) == []
    finally:
        s.cleanup()


def test_reschedule_to_slot_overlapping_old_reservation_succeeds():
    """Б1: the old visit is cancelled before the taken/overlap checks."""
    patient = _user_id(PAT)
    doctor = _doctor_id(DOC)
    day = _free_days(1)[0]
    old_slot = _make_slot(doctor, f"{day} 10:00")
    neighbour = _make_slot(doctor, f"{day} 10:30")
    # the old visit still reserves 10:00-11:00 (a buffer from before a service change)
    old = int(_psql(
        "INSERT INTO appointments (slot_id, patient_user_id, doctor_id, starts_at, ends_at, "
        f"reserved_ends_at) SELECT id, {patient}, doctor_id, starts_at, starts_at + INTERVAL '30 minutes', "
        f"starts_at + INTERVAL '60 minutes' FROM slots WHERE id = {old_slot} RETURNING id")[0])
    try:
        assert _psql(f"SELECT public.scheduled_slot_is_taken({neighbour})") == ["t"]
        with _client() as pat:
            _login(pat, PAT)
            form = pat.get(f"/appointments/{old}/reschedule", params={"day": day, "view": "day"})
            assert f'name="slot_id" value="{neighbour}"' in form.text
            done = _post_reschedule(pat, old, neighbour)
            assert "rescheduled=1" in str(done.url), done.url
        assert _status(old) == "cancelled"
        assert len(_scheduled_on(neighbour)) == 1
    finally:
        _cleanup_slots([old_slot, neighbour])


def _parallel(*calls):
    results = [None] * len(calls)
    barrier = threading.Barrier(len(calls))

    def run(index, fn):
        barrier.wait()
        try:
            results[index] = fn()
        except Exception as exc:  # pragma: no cover - reported below
            results[index] = exc

    threads = [threading.Thread(target=run, args=(i, fn)) for i, fn in enumerate(calls)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    for r in results:
        assert not isinstance(r, Exception), r
        assert r.status_code != 500, r.text[:300]
    return results


def test_race_reschedule_against_booking_of_the_same_slot():
    for _ in range(3):
        s = _Setup()
        target = s.targets[0]
        try:
            with _client() as pat, _client() as pat2:
                _login(pat, PAT)
                _login(pat2, PAT2)
                _parallel(lambda: _post_reschedule(pat, s.old, target),
                          lambda: pat2.post(f"/slots/{target}/book"))
            on_target = _scheduled_on(target)
            assert len(on_target) == 1
            winner = _psql(f"SELECT patient_user_id FROM appointments WHERE id = {on_target[0]}")[0]
            if int(winner) == s.patient:
                assert _status(s.old) == "cancelled"
                assert len(_reschedule_events(s.old)) == 1
            else:
                assert _status(s.old) == "scheduled"
                assert _reschedule_events(s.old) == []
        finally:
            s.cleanup()


def test_two_parallel_reschedules_of_one_visit_make_one_new_visit():
    s = _Setup()
    try:
        with _client() as a, _client() as b:
            _login(a, PAT)
            _login(b, PAT)
            _parallel(lambda: _post_reschedule(a, s.old, s.targets[0]),
                      lambda: _post_reschedule(b, s.old, s.targets[1]))
        new_ids = _new_visits_for(s.patient, s.old)
        assert len(new_ids) == 1
        assert _status(s.old) == "cancelled" and _status(new_ids[0]) == "scheduled"
        assert len(_reschedule_events(s.old)) == 1
    finally:
        s.cleanup()


class _Done:
    status_code = 200
    text = ""


def _block_patient(patient_id):
    def block():
        _psql(f"UPDATE users SET blocked = TRUE WHERE id = {patient_id}")
        return _Done()
    return block


def test_registrar_reschedules_and_blocked_patient_is_refused():
    s = _Setup(patient=PAT2)
    try:
        with _client() as reg:
            _login(reg, REG)
            form = reg.get(f"/appointments/{s.old}/reschedule", params={"day": s.day, "view": "day"})
            assert form.status_code == 200
            assert "Ani Sargsyan" in form.text and PAT2 in form.text
            assert "+374 10 654321" not in form.text
            slots_page = reg.get(f"/doctors/{s.doctor}/slots",
                                 params={"service_id": "1", "day": s.day, "view": "day"})
            assert f'href="/appointments/{s.old}/reschedule"' in slots_page.text
            _psql(f"UPDATE users SET blocked = TRUE WHERE id = {s.patient}")
            try:
                refused = _post_reschedule(reg, s.old, s.targets[0])
                assert "error=patient_blocked" in str(refused.url)
                assert _status(s.old) == "scheduled"
            finally:
                _psql(f"UPDATE users SET blocked = FALSE WHERE id = {s.patient}")
            done = _post_reschedule(reg, s.old, s.targets[0])
            url = str(done.url)
            assert done.url.path == f"/doctors/{s.doctor}/slots", url
            assert "rescheduled=1" in url and "service_id=1" in url
            assert "patient_email" not in url and "conflict" not in url
            assert f"patient={s.patient}" not in url
            assert "Appointment rescheduled" in done.text
            new = _new_visits_for(s.patient, s.old)[0]
            assert f"appointment_id={new}" in url
            assert _reschedule_events(s.old, new)[0].startswith("registrar|appointment.reschedule|")
            # move against blocking: refused or done before the block, never a 500
            current = new
            for target in (s.targets[1], s.targets[2], s.slot(s.doctor, f"{s.day} 17:00")):
                try:
                    _parallel(lambda: _post_reschedule(reg, current, target), _block_patient(s.patient))
                finally:
                    _psql(f"UPDATE users SET blocked = FALSE WHERE id = {s.patient}")
                moved = _new_visits_for(s.patient, current)
                if moved:
                    assert len(moved) == 1 and _status(current) == "cancelled"
                    current = moved[0]
                else:
                    assert _status(current) == "scheduled"
    finally:
        _psql(f"UPDATE users SET blocked = FALSE WHERE id = {_user_id(PAT2)}")
        s.cleanup()


def test_other_roles_and_missing_csrf_cannot_reschedule():
    s = _Setup()
    try:
        with _client() as doc, _client() as admin, _client() as guest, _client() as pat:
            _login(doc, DOC)
            _login(admin, ADMIN)
            _login(pat, PAT)
            for c in (doc, admin):
                assert c.get(f"/appointments/{s.old}/reschedule").status_code == 403
                assert _post_reschedule(c, s.old, s.targets[0]).status_code == 403
            assert guest.get(f"/appointments/{s.old}/reschedule").url.path == "/login"
            guest_post = guest.post(f"/appointments/{s.old}/reschedule",
                                    data={"slot_id": str(s.targets[0])})
            assert guest_post.url.path == "/login" or guest_post.status_code == 403
            no_csrf = pat.post(f"/appointments/{s.old}/reschedule",
                               data={"slot_id": str(s.targets[0])}, csrf=False)
            assert no_csrf.status_code == 403
            assert pat.request("PUT", f"/appointments/{s.old}/reschedule").status_code == 405
            assert pat.get(f"/appointments/{s.old}/cancel").status_code == 405
            admin_page = admin.get("/admin/schedule")
            assert f"/appointments/{s.old}/reschedule" not in admin_page.text
        assert _status(s.old) == "scheduled"
        assert _reschedule_events(s.old) == []
    finally:
        s.cleanup()


def test_visit_with_medical_records_is_not_moved():
    s = _Setup()
    other = _Setup(patient=PAT2)
    try:
        _psql(
            "INSERT INTO visit_notes (appointment_id, doctor_id, patient_user_id, body) "
            f"SELECT a.id, a.doctor_id, a.patient_user_id, {sql_packet('visit_notes', 'ux-has-records')} "
            f"FROM appointments a WHERE a.id IN ({s.old}, {other.old})"
        )
        seal_pending()
        with _client() as pat, _client() as reg:
            _login(pat, PAT)
            _login(reg, REG)
            page = _post_reschedule(pat, s.old, s.targets[0])
            assert "error=has_records" in str(page.url) and "contact the clinic" in page.text
            assert "ux-has-records" not in page.text
            by_registrar = _post_reschedule(reg, other.old, other.targets[0])
            assert "error=has_records" in str(by_registrar.url)
        assert _status(s.old) == "scheduled" and _status(other.old) == "scheduled"
        registrar = _as_role("app_registrar", _user_id(REG),
                             f"SELECT public.appointment_has_medical_records({other.old})")
        assert registrar.returncode == 0 and "t" in registrar.stdout.split()
        foreign = _as_role("app_patient", s.patient,
                           f"SELECT public.appointment_has_medical_records({other.old})")
        missing = _as_role("app_patient", s.patient,
                           f"SELECT public.appointment_has_medical_records({NO_SUCH_ID})")
        for result in (foreign, missing):
            assert result.returncode != 0 and "invalid context" in result.stderr
        assert _as_role("app_doctor", _user_id(DOC),
                        f"SELECT public.appointment_has_medical_records({s.old})").returncode != 0
    finally:
        s.cleanup()
        other.cleanup()


def test_reschedule_event_has_no_pii_and_cannot_be_forged():
    s = _Setup()
    other = _Setup(patient=PAT2)
    try:
        with _client() as pat:
            _login(pat, PAT)
            _post_reschedule(pat, s.old, s.targets[0])
        new = _new_visits_for(s.patient, s.old)[0]
        row = " ".join(_psql(f"SELECT e::text FROM audit_events e WHERE action = 'appointment.reschedule' "
                             f"AND target_id = {new}"))
        for pii in (PAT, PAT_NAME, PAT_PHONE, "Narek", "clinic.local"):
            assert pii not in row
        event_id = _psql(f"SELECT id FROM audit_events WHERE action = 'appointment.reschedule' "
                         f"AND target_id = {new}")[0]
        with _client() as admin:
            _login(admin, ADMIN)
            by_old = admin.get("/admin/audit", params={"target_id": str(s.old)})
            assert f'data-audit-id="{event_id}"' in by_old.text
            assert f"{s.old} → {new}" in by_old.text
            assert PAT_NAME not in by_old.text and PAT_PHONE not in by_old.text
        pat_id = s.patient
        # a valid pair of another patient, a reversed pair, a foreign mix, missing ids
        _psql(f"UPDATE appointments SET status = 'cancelled' WHERE id = {other.old}")
        other_new = _book_sql(other.targets[0], other.patient)
        forged = [
            (other.old, other_new),
            (new, s.old),
            (s.old, other_new),
            (NO_SUCH_ID, NO_SUCH_ID + 1),
        ]
        for old_id, new_id in forged:
            result = _as_role("app_patient", pat_id,
                              f"SELECT public.record_appointment_reschedule({old_id}, {new_id})")
            assert result.returncode != 0, (old_id, new_id)
            assert "42501" in result.stderr or "not allowed" in result.stderr \
                or "invalid reschedule context" in result.stderr, result.stderr
        assert _reschedule_events(other.old, other_new) == []
        for role in ("app_doctor", "app_admin", "app_guest"):
            denied = _as_role(role, _user_id(ADMIN if role == "app_admin" else DOC),
                              f"SELECT public.record_appointment_reschedule({s.old}, {new})")
            assert denied.returncode != 0 and "permission denied" in denied.stderr
        assert len(_reschedule_events(s.old)) == 1
    finally:
        s.cleanup()
        other.cleanup()


def test_no_role_may_move_an_appointment_by_update():
    """Б4: no new grants; slot_id, starts_at, doctor_id stay read-only."""
    s = _Setup()
    try:
        for role, user in (("app_patient", s.patient), ("app_registrar", _user_id(REG))):
            for column, value in (("slot_id", s.targets[0]), ("starts_at", "starts_at + INTERVAL '1 hour'"),
                                  ("doctor_id", _doctor_id(DOC2))):
                result = _as_role(role, user, f"UPDATE appointments SET {column} = {value} WHERE id = {s.old}")
                assert result.returncode != 0, (role, column)
                assert "permission denied" in result.stderr, (role, column, result.stderr)
        grants = _psql(
            "SELECT grantee || ':' || privilege_type || ':' || column_name "
            "FROM information_schema.column_privileges WHERE table_name = 'appointments' "
            "AND privilege_type = 'UPDATE' AND grantee LIKE 'app_%' ORDER BY 1"
        )
        assert all(g.endswith(":status") for g in grants), grants
    finally:
        s.cleanup()


def test_second_post_and_cancel_race_do_one_thing():
    s = _Setup()
    try:
        with _client() as pat:
            _login(pat, PAT)
            first = _post_reschedule(pat, s.old, s.targets[0])
            assert "rescheduled=1" in str(first.url)
            again = _post_reschedule(pat, s.old, s.targets[1])
            assert "reschedule_error=1" in str(again.url)
        assert len(_new_visits_for(s.patient, s.old)) == 1
        assert len(_reschedule_events(s.old)) == 1
    finally:
        s.cleanup()
    for _ in range(3):
        s = _Setup()
        try:
            with _client() as a, _client() as b:
                _login(a, PAT)
                _login(b, PAT)
                _parallel(lambda: _post_reschedule(a, s.old, s.targets[0]),
                          lambda: b.post(f"/appointments/{s.old}/cancel"))
            moved = _new_visits_for(s.patient, s.old)
            assert _status(s.old) == "cancelled"
            cancel_events = _psql(
                f"SELECT count(*) FROM audit_events WHERE action = 'appointment.cancel' AND target_id = {s.old}"
            )[0]
            if moved:
                assert len(moved) == 1 and cancel_events == "0"
                assert len(_reschedule_events(s.old)) == 1
            else:
                assert cancel_events == "1"
                assert [e for e in _reschedule_events(s.old) if "reschedule" in e] == []
        finally:
            s.cleanup()


def _run_migrate() -> None:
    completed = subprocess.run(
        ["docker", "compose", "run", "--rm", "--no-deps", "-T", "migrate"],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]


def _change_check() -> tuple[str, str]:
    row = _psql(
        "SELECT oid, pg_get_constraintdef(oid) FROM pg_constraint "
        "WHERE conname = 'audit_events_change_values_check'"
    )[0]
    oid, definition = row.split("|", 1)
    return oid, definition


def test_old_volume_check_is_upgraded_once_and_reschedule_works():
    """Б6: a volume whose CHECK lacks appointment.reschedule is fixed on start."""
    _psql(
        "ALTER TABLE audit_events DROP CONSTRAINT audit_events_change_values_check; "
        "DELETE FROM audit_events WHERE action IN ('appointment.reschedule', 'clinic.change_deadline.update'); "
        "ALTER TABLE audit_events ADD CONSTRAINT audit_events_change_values_check CHECK ("
        "(old_value IS NULL AND new_value IS NULL) OR action = 'clinic.session_idle.update')"
    )
    assert "appointment.reschedule" not in _change_check()[1]
    _run_migrate()
    oid, definition = _change_check()
    assert "appointment.reschedule" in definition
    assert "clinic.change_deadline.update" in definition
    s = _Setup()
    try:
        with _client() as pat:
            _login(pat, PAT)
            done = _post_reschedule(pat, s.old, s.targets[0])
            assert "rescheduled=1" in str(done.url), done.url
        assert len(_reschedule_events(s.old)) == 1
    finally:
        s.cleanup()
    # a second start leaves the extended CHECK alone (same constraint, no rebuild)
    _run_migrate()
    assert _change_check() == (oid, definition)


# --- 2. Registrar calendar and doctor appointment list ------------------------

def test_registrar_calendar_status_service_filters_and_actions():
    s = _Setup(times=("10:00", "11:00"))
    cancelled = _book_sql(s.targets[0], _user_id(PAT2), "cancelled")
    try:
        with _client() as reg, _client() as doc:
            _login(reg, REG)
            _login(doc, DOC)
            base = {"view": "day", "day": s.day, "doctor_id": str(s.doctor)}
            page = reg.get("/registrar/appointments", params=base)
            assert page.status_code == 200
            assert f'href="/appointments/{s.old}/reschedule"' in page.text
            assert f'action="/appointments/{s.old}/cancel"' in page.text
            assert f"/appointments/{cancelled}/reschedule" not in page.text
            assert "cancelled</span>" in page.text
            active = reg.get("/registrar/appointments", params={**base, "status": "active"})
            assert "cancelled</span>" not in active.text
            assert f'href="/appointments/{s.old}/reschedule"' in active.text
            assert "status=active" in active.text
            week = reg.get("/registrar/appointments", params={**base, "view": "week", "service_id": "1"})
            assert f'href="/appointments/{s.old}/reschedule"' in week.text
            assert "service_id=1" in week.text
            other_service = reg.get("/registrar/appointments", params={**base, "service_id": str(NO_SUCH_ID)})
            assert other_service.status_code == 200 and "Invalid service" in other_service.text
            for bad in ({"status": "x' OR 1=1"}, {"service_id": "1 OR 1=1"}):
                bad_page = reg.get("/registrar/appointments", params={**base, **bad})
                assert bad_page.status_code == 200 and "Traceback" not in bad_page.text
            doctor_view = doc.get("/doctor/calendar", params={"view": "day", "day": s.day})
            assert "/reschedule" not in doctor_view.text
            cancel = reg.post(f"/appointments/{s.old}/cancel")
            assert cancel.status_code == 200 and _status(s.old) == "cancelled"
    finally:
        s.cleanup()


def test_doctor_appointment_list_filters_and_pages():
    doctor = _doctor_id(DOC)
    pat = _user_id(PAT)
    day = _free_days(1)[0]
    slots = [_make_slot(doctor, f"{day} {hour:02d}:{minute:02d}")
             for hour in range(0, 13) for minute in (0, 30)][:25]
    try:
        visits = [_book_sql(slot, pat) for slot in slots]
        _psql(f"UPDATE appointments SET status = 'cancelled' WHERE id = {visits[-1]}")
        with _client() as doc, _client() as doc2:
            _login(doc, DOC)
            _login(doc2, DOC2)
            upcoming = doc.get("/doctor/appointments", params={"status": "upcoming"})
            ids1 = [int(x) for x in re.findall(r'href="/doctor/appointments/(\d+)/records"', upcoming.text)]
            assert len(ids1) == 20 and "page=2" in upcoming.text
            second = doc.get("/doctor/appointments", params={"status": "upcoming", "page": "2"})
            ids2 = [int(x) for x in re.findall(r'href="/doctor/appointments/(\d+)/records"', second.text)]
            assert not set(ids1) & set(ids2)
            assert set(visits[:-1]) <= set(ids1 + ids2)
            assert visits[-1] not in ids1 + ids2
            cancelled = doc.get("/doctor/appointments", params={"status": "cancelled"})
            assert f"/doctor/appointments/{visits[-1]}/records" in cancelled.text
            past = doc.get("/doctor/appointments", params={"status": "past"})
            assert not set(visits) & {int(x) for x in re.findall(
                r'href="/doctor/appointments/(\d+)/records"', past.text)}
            for bad in ({"status": "nope"}, {"page": "0"}, {"page": "abc"}, {"page": "501"}):
                page = doc.get("/doctor/appointments", params=bad)
                assert page.status_code == 200, bad
            other = doc2.get("/doctor/appointments", params={"status": "upcoming"})
            assert not set(visits) & {int(x) for x in re.findall(
                r'href="/doctor/appointments/(\d+)/records"', other.text)}
    finally:
        _cleanup_slots(slots)
