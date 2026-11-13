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
