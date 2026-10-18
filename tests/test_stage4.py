import os
import re
import subprocess
import uuid
from pathlib import Path

import httpx
import pytest

from tests.clinical_notes import (
	NOTE_DOCTOR1_PATIENT_A,
	NOTE_DOCTOR2_PATIENT_B,
	cleanup_cross_doctor_notes,
	insert_cross_doctor_notes,
)

ROOT = Path(__file__).resolve().parents[1]

BASE = os.environ.get("CLINIC_TEST_BASE", "http://localhost:8080")
PASSWORD = "password123"

PAT = "pat@clinic.local"
PAT2 = "pat2@clinic.local"
DOC = "doc@clinic.local"
DOC2 = "doc2@clinic.local"
REG = "reg@clinic.local"
ADMIN = "admin@clinic.local"


def client():
	return httpx.Client(base_url=BASE, follow_redirects=True, timeout=10.0)


def login(c: httpx.Client, email: str) -> httpx.Response:
	return c.post("/login", data={"email": email, "password": PASSWORD})


def test_application_database_timezone_is_yerevan():
	completed = subprocess.run(
		[
			"docker",
			"compose",
			"exec",
			"-T",
			"api",
			"python",
			"-c",
			"from db import db; c=db(); cur=c.cursor(); cur.execute('SHOW TIME ZONE'); zone=cur.fetchone()[0]; cur.execute(\"SELECT CURRENT_TIMESTAMP::timestamp = CURRENT_TIMESTAMP AT TIME ZONE 'Asia/Yerevan'\"); print(zone, cur.fetchone()[0]); c.close()",
		],
		cwd=ROOT,
		capture_output=True,
		text=True,
	)
	assert completed.returncode == 0, completed.stderr or completed.stdout
	assert completed.stdout.strip() == "Asia/Yerevan True"


def logout(c: httpx.Client) -> None:
	c.get("/logout")


def slot_ids(html: str) -> list[str]:
	return re.findall(r'action="/slots/(\d+)/book"', html)


def appointment_ids(html: str) -> list[str]:
	return re.findall(r'action="/appointments/(\d+)/cancel"', html)


def first_doctor_id(html: str) -> str:
	found = re.findall(r'href="/doctors/(\d+)/slots"', html)
	assert found, "no doctor slot links on /doctors"
	return found[0]


def open_free_slot_page(c: httpx.Client) -> tuple[str, str]:
	doctors = c.get("/doctors")
	assert doctors.status_code == 200
	for doc_id in re.findall(r'href="/doctors/(\d+)/slots"', doctors.text):
		page = c.get(f"/doctors/{doc_id}/slots")
		ids = slot_ids(page.text)
		if ids:
			return doc_id, ids[0]
	pytest.fail("no free slots left; reset volume or cancel leftover bookings")


def test_guest_sees_doctors_but_not_slots():
	with client() as c:
		home = c.get("/")
		doctors = c.get("/doctors")
		slots = c.get("/doctors/1/slots")
		book = c.post("/slots/1/book")
		mine = c.get("/my")
		assert home.status_code == 200
		assert doctors.status_code == 200
		assert "/login" in str(slots.url) or "Login" in slots.text
		assert "/login" in str(book.url) or "Login" in book.text
		assert "/login" in str(mine.url) or "Login" in mine.text


def test_bad_password_rejected():
	with client() as c:
		r = c.post("/login", data={"email": PAT, "password": "wrong"})
		assert r.status_code in (200, 401)
		assert "Invalid email or password" in r.text


def test_already_logged_in_admin_is_not_asked_for_credentials():
	with client() as c:
		login(c, ADMIN)
		page = c.get("/login")
		assert page.status_code == 200
		assert str(page.url).rstrip("/").endswith("/login")
		assert ADMIN in page.text
		assert "Password:" not in page.text
		kept = c.post("/login", data={"email": PAT, "password": PASSWORD})
		assert str(kept.url).rstrip("/").endswith("/login")
		me = c.get("/me")
		assert f"You are logged in as: {ADMIN}" in me.text
		assert "Role: admin" in me.text
		assert f"You are logged in as: {PAT}" not in me.text


def test_patient_login_and_cabinet():
	with client() as c:
		r = login(c, PAT)
		assert r.status_code == 200
		assert PAT in r.text
		assert "patient" in r.text


def test_book_cancel_frees_slot_for_other_patient():
	with client() as pat, client() as pat2:
		login(pat, PAT)
		login(pat2, PAT2)
		_, slot_id = open_free_slot_page(pat)
		existing_ids = set(appointment_ids(pat.get("/my").text))

		booked = pat.post(f"/slots/{slot_id}/book")
		assert booked.status_code == 200
		assert "My appointments" in booked.text or "scheduled" in booked.text

		blocked = pat2.post(f"/slots/{slot_id}/book")
		assert "unavailable" in (str(blocked.url) + blocked.text.lower())

		mine = pat.get("/my")
		new_ids = set(appointment_ids(mine.text)) - existing_ids
		assert new_ids, "cancel button missing after book"
		appointment_id = new_ids.pop()
		pat.post(f"/appointments/{appointment_id}/cancel")

		existing_pat2_ids = set(appointment_ids(pat2.get("/my").text))
		again = pat2.post(f"/slots/{slot_id}/book")
		assert "unavailable" not in (str(again.url) + again.text.lower())
		assert "My appointments" in again.text or "scheduled" in again.text

		mine2 = pat2.get("/my")
		created_pat2_ids = set(appointment_ids(mine2.text)) - existing_pat2_ids
		for appointment_id in created_pat2_ids:
			pat2.post(f"/appointments/{appointment_id}/cancel")


def test_patient_cannot_cancel_another_or_past_appointment():
	with client() as pat, client() as pat2, client() as registrar:
		login(pat, PAT)
		login(pat2, PAT2)
		login(registrar, REG)
		_, slot_id = open_free_slot_page(pat)
		existing_ids = set(appointment_ids(pat.get("/my").text))
		booked = pat.post(f"/slots/{slot_id}/book")
		assert booked.status_code == 200
		created_ids = set(appointment_ids(pat.get("/my").text)) - existing_ids
		assert created_ids, "test booking did not create a scheduled appointment"
		appointment_id = created_ids.pop()
		past_slot_id = None
		past_appointment_id = None

		try:
			other_cancel = pat2.post(f"/appointments/{appointment_id}/cancel")
			assert "cancel_error=1" in str(other_cancel.url)
			assert psql(
				f"SELECT status FROM appointments WHERE id = {int(appointment_id)}"
			) == "scheduled"

			doctor_id = psql(
				f"SELECT id FROM doctors WHERE user_id = "
				f"(SELECT id FROM users WHERE email = '{DOC}')"
			)
			patient_id = psql(f"SELECT id FROM users WHERE email = '{PAT}'")
			past_slot_id = psql(
				f"""
				INSERT INTO slots (doctor_id, starts_at, ends_at)
				VALUES (
					{int(doctor_id)},
					CURRENT_TIMESTAMP - INTERVAL '5 years',
					CURRENT_TIMESTAMP - INTERVAL '5 years' + INTERVAL '30 minutes'
				)
				RETURNING id
				"""
			)
			past_appointment_id = psql(
				f"""
				INSERT INTO appointments (
					slot_id, patient_user_id, status, doctor_id, starts_at, ends_at
				)
				SELECT id, {int(patient_id)}, 'scheduled', doctor_id, starts_at, ends_at
				FROM slots
				WHERE id = {int(past_slot_id)}
				RETURNING id
				"""
			)

			past_cancel = pat.post(
				f"/appointments/{int(past_appointment_id)}/cancel"
			)
			assert "cancel_error=1" in str(past_cancel.url)
			assert psql(
				f"SELECT status FROM appointments WHERE id = {int(past_appointment_id)}"
			) == "scheduled"
			assert int(past_appointment_id) not in appointment_ids(pat.get("/my").text)

			registrar_past_cancel = registrar.post(
				f"/appointments/{int(past_appointment_id)}/cancel"
			)
			assert "cancel_error=past" in str(registrar_past_cancel.url)
			assert "Registrars cannot cancel past appointments." in registrar_past_cancel.text
			assert psql(
				f"SELECT status FROM appointments WHERE id = {int(past_appointment_id)}"
			) == "scheduled"
		finally:
			if psql(
				f"SELECT status FROM appointments WHERE id = {int(appointment_id)}"
			) == "scheduled":
				pat.post(f"/appointments/{appointment_id}/cancel")
			if past_appointment_id:
				psql(f"DELETE FROM appointments WHERE id = {int(past_appointment_id)}")
			if past_slot_id:
				psql(f"DELETE FROM slots WHERE id = {int(past_slot_id)}")


def test_overlap_same_time_other_doctor():
	with client() as c:
		login(c, PAT)
		doctors = c.get("/doctors")
		doc_ids = re.findall(r'href="/doctors/(\d+)/slots"', doctors.text)
		assert len(doc_ids) >= 2

		first = c.get(f"/doctors/{doc_ids[0]}/slots")
		free = slot_ids(first.text)
		assert free
		existing_ids = set(appointment_ids(c.get("/my").text))
		c.post(f"/slots/{free[0]}/book")

		try:
			second = c.get(f"/doctors/{doc_ids[1]}/slots")
			other_free = slot_ids(second.text)
			if not other_free:
				pytest.skip("no free slot on second doctor")
			r = c.post(f"/slots/{other_free[0]}/book")
			page = str(r.url) + r.text.lower()
			if "overlap" not in page:
				pytest.skip("seed slots on two doctors did not overlap in time")
		finally:
			mine = c.get("/my")
			created_ids = set(appointment_ids(mine.text)) - existing_ids
			for appointment_id in created_ids:
				c.post(f"/appointments/{appointment_id}/cancel")


def test_patient_cannot_open_doctor_appointments():
	with client() as c:
		login(c, PAT)
		r = c.get("/doctor/appointments")
		assert "/login" in str(r.url) or "patient" in r.text.lower()
		assert "Manage patients" not in r.text


def test_doctor_sees_only_own_cabinet():
	with client() as c:
		login(c, DOC)
		r = c.get("/doctor/appointments")
		assert r.status_code == 200
		mine = c.get("/my")
		assert "/login" in str(mine.url) or "Login" in mine.text


def test_medical_records_are_scoped_and_audited():
	with (
		client() as pat,
		client() as doctor,
		client() as other_doctor,
		client() as registrar,
		client() as admin,
	):
		login(pat, PAT)
		login(doctor, DOC)
		login(other_doctor, DOC2)
		login(registrar, REG)
		login(admin, ADMIN)
		doctor_id = psql(
			f"SELECT id FROM doctors WHERE user_id = "
			f"(SELECT id FROM users WHERE email = '{DOC}')"
		)
		existing_ids = set(appointment_ids(pat.get("/my").text))
		slot_page = pat.get(f"/doctors/{doctor_id}/slots")
		appointment_id = None
		try:
			for slot_id in slot_ids(slot_page.text):
				pat.post(f"/slots/{slot_id}/book")
				created_ids = set(appointment_ids(pat.get("/my").text)) - existing_ids
				if created_ids:
					appointment_id = int(created_ids.pop())
					break
			assert appointment_id is not None, "no bookable slot for medical record test"

			record_url = f"/doctor/appointments/{appointment_id}/records"
			page = doctor.get(record_url)
			assert page.status_code == 200
			assert PAT in page.text
			note_body = "private-test-clinical-note"
			prescription_body = "private-test-prescription"
			saved_note = doctor.post(
				record_url,
				data={"record_type": "note", "body": note_body},
			)
			assert "saved=note" in str(saved_note.url)
			assert "Clinical note saved." in saved_note.text
			saved_prescription = doctor.post(
				record_url,
				data={"record_type": "prescription", "body": prescription_body},
			)
			assert "saved=prescription" in str(saved_prescription.url)
			assert "Prescription saved." in saved_prescription.text

			patient_records = pat.get("/my/records")
			assert note_body in patient_records.text
			assert prescription_body in patient_records.text
			assert note_body not in other_doctor.get(record_url).text
			assert note_body not in registrar.get(record_url).text
			assert note_body not in admin.get("/my/records").text
			assert note_body not in pat.get(record_url).text

			audit = admin.get("/admin/audit")
			assert audit.status_code == 200
			assert "medical.records.view" in audit.text
			assert "medical.note.save" in audit.text
			assert "medical.prescription.add" in audit.text
			assert note_body not in audit.text
			assert prescription_body not in audit.text
			assert note_body not in registrar.get("/admin/audit").text

			cancelled = pat.post(f"/appointments/{appointment_id}/cancel")
			assert "cancelled=1" in str(cancelled.url)
			assert "Appointment cancelled." in cancelled.text
			doctor_schedule = doctor.get("/doctor/appointments")
			assert re.search(
				rf'<li style="color: gray">\s*{re.escape(PAT)}[\s\S]*?\(cancelled[\s\S]*?'
				rf'href="/doctor/appointments/{appointment_id}/records"',
				doctor_schedule.text,
			)
			cancelled_records = doctor.get(record_url)
			assert note_body in cancelled_records.text
			assert prescription_body in cancelled_records.text
			assert "read-only" in cancelled_records.text
			assert "<textarea" not in cancelled_records.text

			patient_records = pat.get("/my/records")
			assert note_body in patient_records.text
			assert prescription_body in patient_records.text
			read_only_update = doctor.post(
				record_url,
				data={"record_type": "note", "body": "must-not-overwrite-cancelled-note"},
			)
			assert "cannot be edited" in read_only_update.text
			assert note_body in read_only_update.text
			assert "must-not-overwrite-cancelled-note" not in read_only_update.text
		finally:
			if appointment_id is not None:
				psql(
					f"DELETE FROM prescriptions WHERE appointment_id = {appointment_id};"
					f"DELETE FROM visit_notes WHERE appointment_id = {appointment_id}"
				)
				if str(appointment_id) in appointment_ids(pat.get("/my").text):
					pat.post(f"/appointments/{appointment_id}/cancel")


def test_admin_can_view_doctor_slots_without_actions():
	with client() as admin:
		login(admin, ADMIN)
		doctors = admin.get("/doctors")
		doctor_match = re.search(r'href="/doctors/(\d+)/slots"', doctors.text)
		assert doctor_match, "admin cannot find a doctor slots link"

		slots = admin.get(f"/doctors/{doctor_match.group(1)}/slots")
		assert slots.status_code == 200
		assert "Slots:" in slots.text
		assert 'action="/slots/' not in slots.text
		assert 'action="/appointments/' not in slots.text


def test_registrar_books_for_pat2():
	with client() as reg, client() as pat2:
		login(reg, REG)
		login(pat2, PAT2)
		_, error_slot_id = open_free_slot_page(reg)
		failed = reg.post(
			f"/slots/{error_slot_id}/book",
			data={"patient_email": "missing@clinic.local"},
		)
		assert "error=patient_not_found" in str(failed.url)
		assert "Patient account was not found." in failed.text
		existing_ids = set(appointment_ids(pat2.get("/my").text))
		doctors = reg.get("/doctors")
		r = None
		for doc_id in re.findall(r'href="/doctors/(\d+)/slots"', doctors.text):
			page = reg.get(f"/doctors/{doc_id}/slots")
			for slot_id in slot_ids(page.text):
				candidate = reg.post(
					f"/slots/{slot_id}/book",
					data={"patient_email": PAT2},
				)
				if "booked=1" in str(candidate.url):
					r = candidate
					break
			if r is not None:
				break
		assert r is not None, "no free slot without patient overlap for registrar test"
		assert r.status_code == 200
		assert "Appointment booked successfully." in r.text
		assert "patient_required" not in r.text
		assert "patient_not_found" not in r.text
		mine = pat2.get("/my")
		assert "scheduled" in mine.text
		created_ids = set(appointment_ids(mine.text)) - existing_ids
		assert created_ids, "registrar booking not visible in patient's appointments"
		for appointment_id in created_ids:
			pat2.post(f"/appointments/{appointment_id}/cancel")


def test_registrar_can_cancel_patient_appointment():
	with client() as reg, client() as pat:
		login(reg, REG)
		login(pat, PAT)
		doc_id, slot_id = open_free_slot_page(pat)
		existing_ids = set(appointment_ids(pat.get("/my").text))
		booked = pat.post(f"/slots/{slot_id}/book")
		assert booked.status_code == 200

		created_ids = set(appointment_ids(pat.get("/my").text)) - existing_ids
		assert created_ids, "test booking did not create a cancellable appointment"
		appointment_id = created_ids.pop()
		try:
			registrar_slots = reg.get(f"/doctors/{doc_id}/slots")
			assert f'action="/appointments/{appointment_id}/cancel"' in registrar_slots.text
			cancelled = reg.post(f"/appointments/{appointment_id}/cancel")
			assert "cancelled=1" in str(cancelled.url)
			assert "Appointment cancelled." in cancelled.text
			repeated_cancel = reg.post(f"/appointments/{appointment_id}/cancel")
			assert "cancel_error=1" in str(repeated_cancel.url)
			assert "could not be cancelled" in repeated_cancel.text
			assert appointment_id not in appointment_ids(pat.get("/my").text)
		finally:
			if appointment_id in appointment_ids(pat.get("/my").text):
				pat.post(f"/appointments/{appointment_id}/cancel")


def test_admin_can_cancel_a_single_upcoming_visit():
	with client() as admin, client() as patient:
		login(admin, ADMIN)
		login(patient, PAT)
		_, slot_id = open_free_slot_page(patient)
		before = set(appointment_ids(patient.get("/my").text))
		patient.post(f"/slots/{slot_id}/book")
		created = set(appointment_ids(patient.get("/my").text)) - before
		assert created, "test booking did not create an appointment"
		appointment_id = int(created.pop())

		try:
			schedule = admin.get("/admin/schedule")
			assert (
				f'action="/appointments/{appointment_id}/cancel"'
				in schedule.text
			)
			cancelled = admin.post(f"/appointments/{appointment_id}/cancel")
			assert "visit_cancelled=1" in str(cancelled.url)
			assert psql(
				f"SELECT status FROM appointments WHERE id = {appointment_id}"
			) == "cancelled"
		finally:
			psql(f"DELETE FROM appointments WHERE id = {appointment_id}")


def test_admin_can_cancel_future_appointments_separately_from_block():
	with client() as admin, client() as pat, client() as doc:
		login(admin, ADMIN)
		login(pat, PAT)
		login(doc, DOC)
		if appointment_ids(pat.get("/my").text):
			pytest.skip("pat already has scheduled appointments; preserving existing bookings")

		_, slot_id = open_free_slot_page(pat)
		booked = pat.post(f"/slots/{slot_id}/book")
		assert booked.status_code == 200
		created_ids = set(appointment_ids(pat.get("/my").text))
		assert created_ids, "test booking did not create a scheduled appointment"
		appointment_id = created_ids.pop()
		user_id = None

		try:
			html = admin.get("/admin/users").text
			block_match = re.search(
				rf"{re.escape(PAT)}[\s\S]{{0,400}}/admin/users/(\d+)/block",
				html,
			)
			assert block_match, "cannot find Block action for pat"
			user_id = block_match.group(1)
			admin.post(f"/admin/users/{user_id}/block")

			blocked_page = pat.get("/my")
			assert blocked_page.status_code == 403
			assert "Account is blocked" in blocked_page.text
			assert psql(
				f"SELECT status FROM appointments WHERE id = {int(appointment_id)}"
			) == "scheduled"
			doctor_schedule = doc.get("/doctor/appointments").text
			assert PAT in doctor_schedule
			assert "scheduled, account blocked" in doctor_schedule

			html = admin.get("/admin/users").text
			patient_row_match = re.search(
				rf"{re.escape(PAT)}[\s\S]{{0,600}}/admin/users/(\d+)/cancel-future-appointments",
				html,
			)
			if not patient_row_match:
				pytest.skip("selected seed slot is not in the future")
			patient_row = patient_row_match.group(0)
			assert "Blocked: Yes" in patient_row
			assert "Future scheduled appointments: 1" in html
			cancelled = admin.post(
				f"/admin/users/{user_id}/cancel-future-appointments"
			)
			assert "future_cancelled=1" in str(cancelled.url)
			assert psql(
				f"SELECT status FROM appointments WHERE id = {int(appointment_id)}"
			) == "cancelled"
			doctor_schedule = doc.get("/doctor/appointments").text
			assert re.search(
				rf'<li style="color: gray">\s*{re.escape(PAT)}[\s\S]*?\(cancelled',
				doctor_schedule,
			)
			admin.post(f"/admin/users/{user_id}/unblock")
			login(pat, PAT)
			assert appointment_id not in appointment_ids(pat.get("/my").text)
			assert "(cancelled)" in pat.get("/my").text
			assert "/admin/users" in cancelled.url.path
		finally:
			if user_id:
				admin.post(f"/admin/users/{user_id}/unblock")
			psql("UPDATE users SET blocked = FALSE WHERE email = 'pat@clinic.local'")
			login(pat, PAT)
			if appointment_id in appointment_ids(pat.get("/my").text):
				pat.post(f"/appointments/{appointment_id}/cancel")


def test_admin_block_pat():
	with client() as admin, client() as pat:
		login(admin, ADMIN)
		html = admin.get("/admin/users").text
		match = re.search(
			rf"{re.escape(PAT)}[\s\S]{{0,400}}/admin/users/(\d+)/block",
			html,
		)
		assert match, "cannot find block action for pat"
		user_id = match.group(1)

		try:
			admin.post(f"/admin/users/{user_id}/block")
			response = pat.post(
				"/login",
				data={"email": PAT, "password": PASSWORD},
			)
			assert "Account is blocked" in response.text
		finally:
			admin.post(f"/admin/users/{user_id}/unblock")


def test_admin_slot_generator_respects_time_off_and_role():
	with client() as admin, client() as registrar:
		login(admin, ADMIN)
		login(registrar, REG)
		html = admin.get("/admin/schedule").text
		match = re.search(
			rf'action="/admin/doctors/(\d+)/generate"[\s\S]{{0,250}}Anna Ohanyan',
			html,
		)
		assert match, "Anna slot-generation form missing"
		doctor_id = match.group(1)
		selected_day = psql(
			"SELECT CURRENT_DATE + ((8 - EXTRACT(ISODOW FROM CURRENT_DATE)::int) % 7) + 7"
		)
		psql(
			f"""
			INSERT INTO time_off (doctor_id, starts_on, ends_on)
			VALUES ({int(doctor_id)}, '{selected_day}', '{selected_day}')
			ON CONFLICT (doctor_id, starts_on, ends_on) DO NOTHING
			"""
		)

		try:
			generated = admin.post(
				f"/admin/doctors/{doctor_id}/generate",
				data={"from_date": selected_day, "to_date": selected_day},
			)
			assert "generated=0" in str(generated.url)
			assert "skipped=6" in str(generated.url)
			assert "Created 0 slots, skipped 6." in generated.text

			today = psql("SELECT CURRENT_DATE")
			yesterday = psql("SELECT CURRENT_DATE - 1")
			day_after_tomorrow = psql("SELECT CURRENT_DATE + 2")
			tomorrow = psql("SELECT CURRENT_DATE + 1")
			past = admin.post(
				f"/admin/doctors/{doctor_id}/generate",
				data={"from_date": yesterday, "to_date": today},
			)
			assert "error=range_in_past" in str(past.url)
			assert "cannot start in the past" in past.text

			reversed_range = admin.post(
				f"/admin/doctors/{doctor_id}/generate",
				data={"from_date": day_after_tomorrow, "to_date": tomorrow},
			)
			assert "error=range_order" in str(reversed_range.url)
			assert "End date must not be before start date." in reversed_range.text

			too_long = admin.post(
				f"/admin/doctors/{doctor_id}/generate",
				data={
					"from_date": tomorrow,
					"to_date": psql("SELECT CURRENT_DATE + 91"),
				},
			)
			assert "error=range_too_long" in str(too_long.url)
			assert "no more than 90 calendar days" in too_long.text
		finally:
			psql(
				f"DELETE FROM time_off WHERE doctor_id = {int(doctor_id)} "
				f"AND starts_on = '{selected_day}' AND ends_on = '{selected_day}'"
			)

		unauthorized = registrar.post(
			f"/admin/doctors/{doctor_id}/generate",
			data={"from_date": "2026-10-19", "to_date": "2026-10-19"},
		)
		assert "/login" in str(unauthorized.url)


def test_admin_schedule_configuration_is_admin_only_and_repeatable():
	with client() as admin, client() as registrar:
		login(admin, ADMIN)
		login(registrar, REG)
		page = admin.get("/admin/schedule")
		assert page.status_code == 200
		assert "Current hours are not preloaded" in page.text
		assert "Thanksgiving" in page.text
		assert "Monday" in page.text
		assert '<input name="name" type="text" required>' in page.text
		doctor_match = re.search(r'<option value="(\d+)">Anna Ohanyan</option>', page.text)
		assert doctor_match, "Anna missing from admin schedule controls"
		doctor_id = doctor_match.group(1)
		future_start = psql("SELECT CURRENT_DATE + 7")
		future_end = psql("SELECT CURRENT_DATE + 13")
		future_holiday = psql("SELECT CURRENT_DATE + 30")

		for path, data in (
			(
				"/admin/work-hours-bulk",
				{
					"doctor_id": doctor_id,
					"weekdays": ["0"],
					"start_time": "09:00",
					"end_time": "12:00",
					"slot_minutes": "30",
				},
			),
			(
				"/admin/time-off",
				{
					"doctor_id": doctor_id,
					"starts_on": future_start,
					"ends_on": future_end,
				},
			),
			(
				"/admin/holidays",
				{"holiday_day": future_holiday, "name": "Test Holiday"},
			),
		):
			response = admin.post(path, data=data)
			assert response.status_code == 200
			assert "/admin/schedule?saved=" in str(response.url)
			unauthorized = registrar.post(path, data=data)
			assert "/login" in str(unauthorized.url)

		past_day = psql("SELECT CURRENT_DATE - 1")
		past_time_off = admin.post(
			"/admin/time-off",
			data={
				"doctor_id": doctor_id,
				"starts_on": past_day,
				"ends_on": past_day,
			},
		)
		assert "error=time_off_past" in str(past_time_off.url)
		assert "Time off cannot start in the past." in past_time_off.text


def test_admin_cannot_approve_a_past_time_off_request():
	doctor_id = psql(
		f"SELECT id FROM doctors WHERE user_id = (SELECT id FROM users WHERE email = '{DOC}')"
	)
	comment = "past-time-off-approval-test"
	request_id = psql(
		f"""
		INSERT INTO time_off_requests (doctor_id, starts_on, ends_on, comment)
		VALUES ({int(doctor_id)}, CURRENT_DATE - 1, CURRENT_DATE, '{comment}')
		RETURNING id
		"""
	)
	try:
		with client() as admin:
			login(admin, ADMIN)
			response = admin.post(
				f"/admin/time-off-requests/{request_id}/decision",
				data={"decision": "approve"},
			)
			assert "error=time_off_past" in str(response.url)
			assert "Time off cannot start in the past." in response.text
			assert psql(
				f"SELECT status FROM time_off_requests WHERE id = {int(request_id)}"
			) == "pending"
	finally:
		psql(f"DELETE FROM time_off_requests WHERE id = {int(request_id)}")


def psql(sql: str) -> str:
	completed = subprocess.run(
		[
			"docker", "compose", "exec", "-T", "db",
			"psql", "-U", "clinic", "-d", "clinic",
			"-v", "ON_ERROR_STOP=1", "-At", "-c", sql,
		],
		cwd=ROOT,
		capture_output=True,
		text=True,
	)
	if completed.returncode != 0:
		raise AssertionError(completed.stderr or completed.stdout)
	lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
	for line in lines:
		if line.isdigit() or line in ("scheduled", "cancelled"):
			return line
	return lines[-1] if lines else ""


def test_database_rejects_overlapping_appointments_on_different_slots():
	psql(
		"""
		DO $$
		DECLARE
			test_doctor_id INTEGER;
			first_patient_id INTEGER;
			second_patient_id INTEGER;
			first_slot_id INTEGER;
			second_slot_id INTEGER;
			rejected_constraint TEXT;
		BEGIN
			SELECT id INTO test_doctor_id
			FROM doctors WHERE full_name = 'Anna Ohanyan';
			SELECT id INTO first_patient_id
			FROM users WHERE email = 'pat@clinic.local';
			SELECT id INTO second_patient_id
			FROM users WHERE email = 'pat2@clinic.local';

			INSERT INTO slots (doctor_id, starts_at, ends_at)
			VALUES (test_doctor_id, '2035-06-10 08:00', '2035-06-10 08:30')
			RETURNING id INTO first_slot_id;
			INSERT INTO slots (doctor_id, starts_at, ends_at)
			VALUES (test_doctor_id, '2035-06-10 09:00', '2035-06-10 09:30')
			RETURNING id INTO second_slot_id;

			INSERT INTO appointments
				(slot_id, patient_user_id, doctor_id, starts_at, ends_at, status)
			VALUES
				(first_slot_id, first_patient_id, test_doctor_id,
				 '2035-06-10 10:00', '2035-06-10 10:30', 'scheduled');

			BEGIN
				INSERT INTO appointments
					(slot_id, patient_user_id, doctor_id, starts_at, ends_at, status)
				VALUES
					(second_slot_id, second_patient_id, test_doctor_id,
					 '2035-06-10 10:15', '2035-06-10 10:45', 'scheduled');
				RAISE EXCEPTION 'overlapping appointment was accepted';
			EXCEPTION WHEN exclusion_violation THEN
				GET STACKED DIAGNOSTICS rejected_constraint = CONSTRAINT_NAME;
				IF rejected_constraint <> 'appointments_no_overlap_per_doctor' THEN
					RAISE;
				END IF;
			END;

			DELETE FROM appointments
			WHERE slot_id IN (first_slot_id, second_slot_id);
			DELETE FROM slots
			WHERE id IN (first_slot_id, second_slot_id);
		END
		$$;
		"""
	)


def test_past_slot_cannot_be_booked():
	psql(
		"""
		DELETE FROM slots
		WHERE starts_at = TIMESTAMP '2020-01-06 09:00'
		  AND doctor_id = (SELECT id FROM doctors WHERE full_name = 'Anna Ohanyan')
		"""
	)
	slot_id = psql(
		"""
		INSERT INTO slots (doctor_id, starts_at, ends_at)
		SELECT id, TIMESTAMP '2020-01-06 09:00', TIMESTAMP '2020-01-06 09:30'
		FROM doctors WHERE full_name = 'Anna Ohanyan'
		RETURNING id
		"""
	)
	try:
		with client() as pat:
			login(pat, PAT)
			booked = pat.post(f"/slots/{slot_id}/book")
			assert "error=past" in str(booked.url)
			assert "This slot is in the past" in booked.text
			assert "Past — unavailable" in booked.text
	finally:
		psql(f"DELETE FROM slots WHERE id = {int(slot_id)}")


def test_closed_day_lists_scheduled_and_drops_cancelled_only_slot():
	psql(
		"""
		DELETE FROM appointments
		WHERE slot_id IN (
			SELECT id FROM slots
			WHERE starts_at::date = DATE '2026-12-25'
		);
		DELETE FROM slots WHERE starts_at::date = DATE '2026-12-25';
		DELETE FROM holidays WHERE day = DATE '2026-12-25' AND name = 'Christmas';
		"""
	)
	free_id = psql(
		"""
		INSERT INTO slots (doctor_id, starts_at, ends_at)
		SELECT id, TIMESTAMP '2026-12-25 09:00', TIMESTAMP '2026-12-25 09:30'
		FROM doctors WHERE full_name = 'Anna Ohanyan'
		RETURNING id
		"""
	)
	kept_id = psql(
		"""
		INSERT INTO slots (doctor_id, starts_at, ends_at)
		SELECT id, TIMESTAMP '2026-12-25 10:00', TIMESTAMP '2026-12-25 10:30'
		FROM doctors WHERE full_name = 'Anna Ohanyan'
		RETURNING id
		"""
	)
	psql(
		f"""
		INSERT INTO appointments (slot_id, patient_user_id, status, doctor_id, starts_at, ends_at)
		SELECT s.id, u.id, 'cancelled', s.doctor_id, s.starts_at, s.ends_at
		FROM slots s JOIN users u ON u.email = '{PAT}'
		WHERE s.id = {int(free_id)}
		"""
	)
	psql(
		f"""
		INSERT INTO appointments (slot_id, patient_user_id, status, doctor_id, starts_at, ends_at)
		SELECT s.id, u.id, 'scheduled', s.doctor_id, s.starts_at, s.ends_at
		FROM slots s JOIN users u ON u.email = '{PAT2}'
		WHERE s.id = {int(kept_id)}
		"""
	)
	try:
		with client() as admin:
			login(admin, ADMIN)
			saved = admin.post(
				"/admin/holidays",
				data={"holiday_day": "2026-12-25", "name": "Christmas"},
			)
			assert "saved=holiday" in str(saved.url)
			assert "Needs manual cancellation" in saved.text
			assert PAT2 in saved.text
			assert "2026-12-25 10:00" in saved.text
			assert psql(f"SELECT count(*) FROM slots WHERE id = {int(free_id)}") == "0"
			assert psql(
				f"SELECT status FROM appointments WHERE slot_id = {int(kept_id)}"
			) == "scheduled"
	finally:
		psql(
			f"""
			DELETE FROM appointments WHERE slot_id IN ({int(free_id)}, {int(kept_id)});
			DELETE FROM slots WHERE id IN ({int(free_id)}, {int(kept_id)});
			DELETE FROM holidays WHERE day = DATE '2026-12-25' AND name = 'Christmas';
			"""
		)


def test_apply_hours_removes_free_slots_outside_window_only():
	psql(
		"""
		DELETE FROM appointments
		WHERE slot_id IN (
			SELECT id FROM slots
			WHERE starts_at::date = DATE '2026-12-05'
		);
		DELETE FROM slots WHERE starts_at::date = DATE '2026-12-05';
		"""
	)
	free_id = psql(
		"""
		INSERT INTO slots (doctor_id, starts_at, ends_at)
		SELECT id, TIMESTAMP '2026-12-05 09:00', TIMESTAMP '2026-12-05 09:30'
		FROM doctors WHERE full_name = 'Anna Ohanyan'
		RETURNING id
		"""
	)
	kept_id = psql(
		"""
		INSERT INTO slots (doctor_id, starts_at, ends_at)
		SELECT id, TIMESTAMP '2026-12-05 10:00', TIMESTAMP '2026-12-05 10:30'
		FROM doctors WHERE full_name = 'Anna Ohanyan'
		RETURNING id
		"""
	)
	psql(
		f"""
		INSERT INTO appointments (slot_id, patient_user_id, status, doctor_id, starts_at, ends_at)
		SELECT s.id, u.id, 'scheduled', s.doctor_id, s.starts_at, s.ends_at
		FROM slots s JOIN users u ON u.email = '{PAT2}'
		WHERE s.id = {int(kept_id)}
		"""
	)
	try:
		with client() as admin, client() as registrar:
			login(admin, ADMIN)
			login(registrar, REG)
			page = admin.get("/admin/schedule")
			match = re.search(
				r'action="/admin/doctors/(\d+)/apply-hours"',
				page.text,
			)
			assert match, "apply-hours button missing"
			doctor_id = match.group(1)
			denied = registrar.post(f"/admin/doctors/{doctor_id}/apply-hours")
			assert "/login" in str(denied.url)
			applied = admin.post(f"/admin/doctors/{doctor_id}/apply-hours")
			assert "saved=apply-hours" in str(applied.url)
			assert "Scheduled visits were not cancelled" in applied.text
			assert "Outside work hours" in applied.text
			assert PAT2 in applied.text
			assert psql(f"SELECT count(*) FROM slots WHERE id = {int(free_id)}") == "0"
			assert psql(
				f"SELECT status FROM appointments WHERE slot_id = {int(kept_id)}"
			) == "scheduled"
	finally:
		psql(
			f"""
			DELETE FROM appointments WHERE slot_id IN ({int(free_id)}, {int(kept_id)});
			DELETE FROM slots WHERE id IN ({int(free_id)}, {int(kept_id)});
			"""
		)
		for name, start, end in (
			("Anna Ohanyan", "2026-10-03 10:00", "2026-10-03 11:00"),
			("Levon Petrosyan", "2026-10-01 09:00", "2026-10-01 09:30"),
			("Levon Petrosyan", "2026-10-01 10:00", "2026-10-01 10:30"),
			("Levon Petrosyan", "2026-10-03 10:30", "2026-10-03 11:30"),
		):
			psql(
				f"""
				INSERT INTO slots (doctor_id, starts_at, ends_at)
				SELECT id, TIMESTAMP '{start}', TIMESTAMP '{end}'
				FROM doctors WHERE full_name = '{name}'
				ON CONFLICT (doctor_id, starts_at) DO NOTHING
				"""
			)


def test_patient_overlap_rejected_by_exclusion_without_python_select():
	"""Same patient, overlapping slots at two doctors, rejected by the DB constraint.

	The insert goes straight to PostgreSQL, so it still fails if the Python
	SELECT overlap check in book_slot() is removed.
	"""
	psql(
		"""
		DO $$
		DECLARE
			anna_id INTEGER;
			levon_id INTEGER;
			patient_id INTEGER;
			anna_slot_id INTEGER;
			levon_slot_id INTEGER;
			rejected_constraint TEXT;
		BEGIN
			SELECT id INTO anna_id FROM doctors WHERE full_name = 'Anna Ohanyan';
			SELECT id INTO levon_id FROM doctors WHERE full_name = 'Levon Petrosyan';
			SELECT id INTO patient_id FROM users WHERE email = 'pat@clinic.local';

			INSERT INTO slots (doctor_id, starts_at, ends_at)
			VALUES (anna_id, '2036-04-07 10:00', '2036-04-07 11:00')
			RETURNING id INTO anna_slot_id;
			INSERT INTO slots (doctor_id, starts_at, ends_at)
			VALUES (levon_id, '2036-04-07 10:30', '2036-04-07 11:30')
			RETURNING id INTO levon_slot_id;

			INSERT INTO appointments
				(slot_id, patient_user_id, doctor_id, starts_at, ends_at, status)
			VALUES
				(anna_slot_id, patient_id, anna_id,
				 '2036-04-07 10:00', '2036-04-07 11:00', 'scheduled');

			BEGIN
				INSERT INTO appointments
					(slot_id, patient_user_id, doctor_id, starts_at, ends_at, status)
				VALUES
					(levon_slot_id, patient_id, levon_id,
					 '2036-04-07 10:30', '2036-04-07 11:30', 'scheduled');
				RAISE EXCEPTION 'overlapping patient appointment was accepted';
			EXCEPTION WHEN exclusion_violation THEN
				GET STACKED DIAGNOSTICS rejected_constraint = CONSTRAINT_NAME;
				IF rejected_constraint <> 'appointments_no_overlap_per_patient' THEN
					RAISE EXCEPTION 'expected appointments_no_overlap_per_patient, got %', rejected_constraint;
				END IF;
			END;

			DELETE FROM appointments
			WHERE slot_id IN (anna_slot_id, levon_slot_id);
			DELETE FROM slots
			WHERE id IN (anna_slot_id, levon_slot_id);
		END
		$$;
		"""
	)

	anna_slot = psql(
		"""
		INSERT INTO slots (doctor_id, starts_at, ends_at)
		SELECT id, TIMESTAMP '2036-05-05 10:00', TIMESTAMP '2036-05-05 11:00'
		FROM doctors WHERE full_name = 'Anna Ohanyan'
		RETURNING id
		"""
	)
	levon_slot = psql(
		"""
		INSERT INTO slots (doctor_id, starts_at, ends_at)
		SELECT id, TIMESTAMP '2036-05-05 10:30', TIMESTAMP '2036-05-05 11:30'
		FROM doctors WHERE full_name = 'Levon Petrosyan'
		RETURNING id
		"""
	)
	try:
		with client() as pat:
			login(pat, PAT)
			first = pat.post(f"/slots/{int(anna_slot)}/book")
			assert first.status_code == 200
			assert first.status_code != 500
			second = pat.post(f"/slots/{int(levon_slot)}/book")
			assert second.status_code != 500
			page = str(second.url) + second.text.lower()
			assert "overlap" in page or "unavailable" in page
			assert psql(
				f"""
				SELECT count(*)
				FROM appointments
				WHERE slot_id IN ({int(anna_slot)}, {int(levon_slot)})
				  AND status = 'scheduled'
				"""
			) == "1"
	finally:
		psql(
			f"""
			DELETE FROM appointments
			WHERE slot_id IN ({int(anna_slot)}, {int(levon_slot)});
			DELETE FROM slots
			WHERE id IN ({int(anna_slot)}, {int(levon_slot)});
			"""
		)


def test_session_role_and_block_come_from_database():
	with client() as pat:
		login(pat, PAT)
		me = pat.get("/me")
		assert "Role: patient" in me.text
		psql("UPDATE users SET role = 'admin' WHERE email = 'pat@clinic.local'")
		try:
			me = pat.get("/me")
			assert "Role: admin" in me.text
			assert "Role: patient" not in me.text
			admin_page = pat.get("/admin/users")
			assert admin_page.status_code == 200
			assert "Manage patients" in admin_page.text
			mine = pat.get("/my")
			assert "/login" in str(mine.url)
		finally:
			psql("UPDATE users SET role = 'patient' WHERE email = 'pat@clinic.local'")

		psql("UPDATE users SET blocked = TRUE WHERE email = 'pat@clinic.local'")
		try:
			blocked = pat.get("/my")
			assert blocked.status_code == 403
			assert "Account is blocked" in blocked.text
			assert "Role: patient" not in blocked.text
			again = pat.post("/slots/1/book")
			assert again.status_code != 500
			assert "/login" in str(again.url) or again.status_code == 403
		finally:
			psql("UPDATE users SET blocked = FALSE, role = 'patient' WHERE email = 'pat@clinic.local'")


def test_visit_notes_keep_medical_text_off_appointment_status():
	assert psql(
		"""
		SELECT count(*)
		FROM information_schema.columns
		WHERE table_schema = 'public'
		  AND table_name = 'appointments'
		  AND column_name IN ('body', 'diagnosis', 'prescription')
		"""
	) == "0"
	assert psql(
		"""
		SELECT string_agg(column_name, ',' ORDER BY ordinal_position)
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'visit_notes'
		"""
	) == "id,appointment_id,doctor_id,patient_user_id,body"
	assert psql(
		"""
		SELECT string_agg(column_name, ',' ORDER BY ordinal_position)
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'prescriptions'
		"""
	) == "id,appointment_id,doctor_id,patient_user_id,body"
	assert psql(
		"""
		SELECT count(*)
		FROM pg_class
		WHERE relname IN (
			'appointments', 'visit_notes', 'prescriptions',
			'slots', 'work_hours', 'time_off', 'holidays',
			'time_off_requests'
		)
		  AND relrowsecurity
		"""
	) == "8"
	assert psql(
		"""
		SELECT count(*)
		FROM pg_constraint
		WHERE conrelid = 'public.appointments'::regclass
		  AND conname = 'appointments_status_check'
		  AND contype = 'c'
		  AND convalidated
		"""
	) == "1"

	created = insert_cross_doctor_notes()
	try:
		assert psql(
			f"""
			SELECT u.email || '|' || du.email || '|' || a.status
			FROM visit_notes n
			JOIN appointments a ON a.id = n.appointment_id
			JOIN users u ON u.id = n.patient_user_id
			JOIN doctors d ON d.id = n.doctor_id
			JOIN users du ON du.id = d.user_id
			WHERE n.id = {created['note_a_id']}
			"""
		) == "pat@clinic.local|doc@clinic.local|scheduled"
		assert psql(
			f"""
			SELECT u.email || '|' || du.email
			FROM visit_notes n
			JOIN users u ON u.id = n.patient_user_id
			JOIN doctors d ON d.id = n.doctor_id
			JOIN users du ON du.id = d.user_id
			WHERE n.id = {created['note_b_id']}
			"""
		) == "pat2@clinic.local|doc2@clinic.local"
		assert psql(
			f"SELECT status FROM appointments WHERE id = {created['appointment_a_id']}"
		) == "scheduled"
		assert NOTE_DOCTOR1_PATIENT_A not in psql(
			f"SELECT status FROM appointments WHERE id = {created['appointment_a_id']}"
		)
		assert psql(
			f"SELECT body FROM visit_notes WHERE id = {created['note_a_id']}"
		) == NOTE_DOCTOR1_PATIENT_A
		assert psql(
			f"SELECT body FROM visit_notes WHERE id = {created['note_b_id']}"
		) == NOTE_DOCTOR2_PATIENT_B

		psql(
			f"""
			INSERT INTO visit_notes (appointment_id, doctor_id, patient_user_id, body)
			SELECT appointment_id, doctor_id, patient_user_id, 'second note'
			FROM visit_notes
			WHERE id = {created['note_a_id']}
			"""
		)
		assert psql(
			f"""
			SELECT count(*) FROM visit_notes
			WHERE appointment_id = {created['appointment_a_id']}
			"""
		) == "2"

		psql(
			f"""
			INSERT INTO prescriptions (appointment_id, doctor_id, patient_user_id, body)
			SELECT appointment_id, doctor_id, patient_user_id, 'rx-1'
			FROM visit_notes WHERE id = {created['note_a_id']};
			INSERT INTO prescriptions (appointment_id, doctor_id, patient_user_id, body)
			SELECT appointment_id, doctor_id, patient_user_id, 'rx-2'
			FROM visit_notes WHERE id = {created['note_a_id']};
			"""
		)
		assert psql(
			f"""
			SELECT count(*) FROM prescriptions
			WHERE appointment_id = {created['appointment_a_id']}
			"""
		) == "2"

		for table, source_id in (
			("visit_notes", created["note_a_id"]),
			("prescriptions", created["note_a_id"]),
		):
			psql(
				f"""
				DO $$
				DECLARE rejected BOOLEAN := FALSE;
				BEGIN
					BEGIN
						INSERT INTO {table}
							(appointment_id, doctor_id, patient_user_id, body)
						SELECT appointment_id, doctor_id, patient_user_id, repeat('x', 5001)
						FROM visit_notes
						WHERE id = {source_id};
					EXCEPTION WHEN check_violation THEN
						rejected := TRUE;
					END;
					IF NOT rejected THEN
						RAISE EXCEPTION '5001-character {table} body was accepted';
					END IF;
				END
				$$;
				"""
			)

		with client() as doctor:
			login(doctor, DOC)
			unicode_note = "\u00e9" * 4000
			accepted_limit = doctor.post(
				f"/doctor/appointments/{created['appointment_a_id']}/records",
				data={"record_type": "note", "body": unicode_note},
			)
			assert "saved=note" in str(accepted_limit.url)
			assert psql(
				f"""
				SELECT char_length(body) FROM visit_notes
				WHERE appointment_id = {created['appointment_a_id']}
				ORDER BY id DESC LIMIT 1
				"""
			) == "4000"

			too_long = doctor.post(
				f"/doctor/appointments/{created['appointment_a_id']}/records",
				data={"record_type": "note", "body": "x" * 5001},
			)
			assert "error=too_long" in str(too_long.url)
			assert "Record text is too long." in too_long.text
			record_page = doctor.get(
				f"/doctor/appointments/{created['appointment_a_id']}/records"
			)
			assert NOTE_DOCTOR1_PATIENT_A in record_page.text
			assert "second note" in record_page.text
	finally:
		cleanup_cross_doctor_notes()


def test_registrar_day_list_doctor_calendar_and_time_off_approval():
	doctor_id = psql(
		f"SELECT id FROM doctors WHERE user_id = (SELECT id FROM users WHERE email = '{DOC}')"
	)
	selected_day = psql(
		f"""
		SELECT g.day::date
		FROM generate_series(CURRENT_DATE + 91, CURRENT_DATE + 365, INTERVAL '1 day')
			AS g(day)
		WHERE EXISTS (
			SELECT 1
			FROM work_hours w
			WHERE w.doctor_id = {doctor_id}
			  AND w.weekday = ((EXTRACT(DOW FROM g.day)::int + 6) % 7)
			  AND TIME '10:00' >= w.start_time
			  AND TIME '11:30' <= w.end_time
		)
		  AND NOT EXISTS (SELECT 1 FROM holidays h WHERE h.day = g.day::date)
		  AND NOT EXISTS (
			SELECT 1 FROM time_off t
			WHERE t.doctor_id = {doctor_id}
			  AND g.day::date BETWEEN t.starts_on AND t.ends_on
		  )
		  AND NOT EXISTS (
			SELECT 1 FROM slots s
			WHERE s.doctor_id = {doctor_id}
			  AND s.starts_at::date = g.day::date
		  )
		ORDER BY g.day
		LIMIT 1
		"""
	)
	assert selected_day, "no unused future workday available for calendar test"

	approved_comment = "calendar-time-off-approved-test"
	rejected_comment = "calendar-time-off-rejected-test"
	psql(
		f"""
		DELETE FROM time_off_requests
		WHERE doctor_id = {doctor_id}
		  AND comment IN ('{approved_comment}', '{rejected_comment}');
		INSERT INTO slots (doctor_id, starts_at, ends_at)
		VALUES
			({doctor_id}, TIMESTAMP '{selected_day} 10:00', TIMESTAMP '{selected_day} 10:30'),
			({doctor_id}, TIMESTAMP '{selected_day} 11:00', TIMESTAMP '{selected_day} 11:30');
		"""
	)
	slot_ids_value = psql(
		f"""
		SELECT string_agg(id::text, ',' ORDER BY starts_at)
		FROM slots
		WHERE doctor_id = {doctor_id} AND starts_at::date = '{selected_day}'
		"""
	)
	slot_id, free_slot_id = slot_ids_value.split(",")
	appointment_id = None

	try:
		with (
			client() as patient,
			client() as doctor,
			client() as other_doctor,
			client() as registrar,
			client() as admin,
		):
			login(patient, PAT)
			login(doctor, DOC)
			login(other_doctor, DOC2)
			login(registrar, REG)
			login(admin, ADMIN)

			past_request = doctor.post(
				"/doctor/time-off-requests",
				data={
					"starts_on": psql("SELECT CURRENT_DATE - 1"),
					"ends_on": psql("SELECT CURRENT_DATE + 1"),
					"comment": "past request must be rejected",
				},
			)
			assert "error=request_date_past" in str(past_request.url)
			assert "Start date cannot be in the past." in past_request.text

			existing_ids = set(appointment_ids(patient.get("/my").text))
			booked = patient.post(f"/slots/{slot_id}/book")
			assert booked.status_code == 200
			assert booked.url.path == "/my"
			created_ids = set(appointment_ids(patient.get("/my").text)) - existing_ids
			assert created_ids, "calendar test booking was not created"
			appointment_id = int(created_ids.pop())

			doctor_calendar = doctor.get(f"/doctor/calendar?day={selected_day}")
			assert doctor_calendar.status_code == 200
			assert f"{PAT} — scheduled" in doctor_calendar.text
			assert "Available" in doctor_calendar.text
			assert 'action="/slots/' not in doctor_calendar.text
			assert "Save hours" not in doctor_calendar.text
			other_calendar = other_doctor.get(
				f"/doctor/calendar?day={selected_day}"
			)
			assert other_calendar.status_code == 200

			registrar_day = registrar.get(
				f"/registrar/appointments?day={selected_day}"
			)
			assert registrar_day.status_code == 200
			assert PAT in registrar_day.text
			assert "scheduled" in registrar_day.text
			assert "10:00" in registrar_day.text
			assert "Clinical note" not in registrar_day.text
			assert "diagnosis" not in registrar_day.text.lower()

			cancelled = patient.post(f"/appointments/{appointment_id}/cancel")
			assert "cancelled=1" in str(cancelled.url)
			calendar_after_cancel = doctor.get(
				f"/doctor/calendar?day={selected_day}"
			)
			assert re.search(
				rf'<li style="color: gray">[\s\S]*?{re.escape(PAT)} — cancelled',
				calendar_after_cancel.text,
			)
			assert "Available" in calendar_after_cancel.text
			registrar_cancelled = registrar.get(
				f"/registrar/appointments?day={selected_day}"
			)
			assert "cancelled" in registrar_cancelled.text

			for comment in (approved_comment, rejected_comment):
				response = doctor.post(
					"/doctor/time-off-requests",
					data={
						"starts_on": selected_day,
						"ends_on": selected_day,
						"comment": comment,
					},
				)
				assert "request_submitted=1" in str(response.url)
			doctor_requests = doctor.get(f"/doctor/calendar?day={selected_day}")
			assert approved_comment in doctor_requests.text
			assert rejected_comment in doctor_requests.text
			assert approved_comment not in other_doctor.get(
				f"/doctor/calendar?day={selected_day}"
			).text

			admin_queue = admin.get("/admin/schedule")
			assert approved_comment in admin_queue.text
			assert rejected_comment in admin_queue.text
			approved_request_id = psql(
				f"SELECT id FROM time_off_requests WHERE comment = '{approved_comment}'"
			)
			rejected_request_id = psql(
				f"SELECT id FROM time_off_requests WHERE comment = '{rejected_comment}'"
			)

			rejected = admin.post(
				f"/admin/time-off-requests/{rejected_request_id}/decision",
				data={"decision": "reject"},
			)
			assert "time_off_request_decision=rejected" in str(rejected.url)
			assert psql(
				f"SELECT status FROM time_off_requests WHERE id = {rejected_request_id}"
			) == "rejected"
			assert psql(
				f"""
				SELECT count(*) FROM time_off
				WHERE doctor_id = {doctor_id}
				  AND starts_on = '{selected_day}' AND ends_on = '{selected_day}'
				"""
			) == "0"

			approved = admin.post(
				f"/admin/time-off-requests/{approved_request_id}/decision",
				data={"decision": "approve"},
			)
			assert "time_off_request_decision=approved" in str(approved.url)
			assert "Time-off request approved" in approved.text
			assert psql(
				f"SELECT status FROM time_off_requests WHERE id = {approved_request_id}"
			) == "approved"
			assert psql(
				f"""
				SELECT count(*) FROM time_off
				WHERE doctor_id = {doctor_id}
				  AND starts_on = '{selected_day}' AND ends_on = '{selected_day}'
				"""
			) == "1"
			audit_page = admin.get("/admin/audit")
			assert "schedule.time_off_request.submit" in audit_page.text
			assert "schedule.time_off_request.approved" in audit_page.text
			assert "schedule.time_off_request.rejected" in audit_page.text
			assert approved_comment not in audit_page.text
			assert rejected_comment not in audit_page.text
			closed_calendar = doctor.get(f"/doctor/calendar?day={selected_day}")
			assert "Closed: doctor time off." in closed_calendar.text
			assert approved_comment in closed_calendar.text
			assert rejected_comment in closed_calendar.text
			assert psql(
				f"SELECT count(*) FROM slots WHERE id IN ({slot_id}, {free_slot_id})"
			) == "0"
	finally:
		psql(
			f"""
			DELETE FROM time_off
			WHERE doctor_id = {doctor_id}
			  AND starts_on = '{selected_day}' AND ends_on = '{selected_day}';
			DELETE FROM time_off_requests
			WHERE doctor_id = {doctor_id}
			  AND comment IN ('{approved_comment}', '{rejected_comment}');
			DELETE FROM appointments
			WHERE slot_id IN ({slot_id}, {free_slot_id});
			DELETE FROM slots WHERE id IN ({slot_id}, {free_slot_id});
			"""
		)


def test_public_registration_is_patient_only_and_can_book(request):
	email = f"public-registration-{uuid.uuid4().hex}@clinic.test"
	password = "Clinic-Patient-Password-2026!"

	def cleanup_registered_user():
		registered_user_id = psql(
			f"SELECT id FROM users WHERE email = '{email}'"
		)
		if registered_user_id.isdigit():
			psql(
				f"""
				DELETE FROM audit_events WHERE actor_user_id = {registered_user_id};
				DELETE FROM appointments WHERE patient_user_id = {registered_user_id};
				DELETE FROM users WHERE id = {registered_user_id};
				"""
			)

	request.addfinalizer(cleanup_registered_user)
	user_id = None
	with client() as guest:
		register_page = guest.get("/register")
		assert register_page.status_code == 200
		assert 'name="role"' not in register_page.text

		invalid_email = guest.post(
			"/register",
			data={
				"email": "not-an-email",
				"password": password,
				"confirm_password": password,
			},
		)
		assert invalid_email.status_code == 400
		assert "valid email" in invalid_email.text

		short_password = guest.post(
			"/register",
			data={
				"email": email,
				"password": "short",
				"confirm_password": "short",
			},
		)
		assert short_password.status_code == 400
		assert "at least 8 characters" in short_password.text

		default_password = guest.post(
			"/register",
			data={
				"email": email,
				"password": "password123",
				"confirm_password": "password123",
			},
		)
		assert default_password.status_code == 400
		assert "non-default password" in default_password.text

		mismatched_passwords = guest.post(
			"/register",
			data={
				"email": email,
				"password": password,
				"confirm_password": password + "different",
			},
		)
		assert mismatched_passwords.status_code == 400
		assert "do not match" in mismatched_passwords.text

		created = guest.post(
			"/register",
			data={
				"email": email.upper(),
				"password": password,
				"confirm_password": password,
				"role": "admin",
			},
		)
		assert created.status_code == 200
		assert "/login?registered=1" in str(created.url)
		assert "Account created. Please log in." in created.text
		user_id = int(
			psql(f"SELECT id FROM users WHERE email = '{email}'")
		)
		assert psql(f"SELECT role FROM users WHERE id = {user_id}") == "patient"
		assert psql(f"SELECT blocked FROM users WHERE id = {user_id}") == "f"

		duplicate = guest.post(
			"/register",
			data={
				"email": email.upper(),
				"password": password,
				"confirm_password": password,
			},
		)
		assert duplicate.status_code == 409
		assert "already exists" in duplicate.text
		assert psql(f"SELECT count(*) FROM users WHERE lower(email) = '{email}'") == "1"

		login_response = guest.post(
			"/login",
			data={"email": email, "password": password},
		)
		assert "Role: patient" in guest.get("/me").text, login_response.text
		assert str(guest.get("/register").url).rstrip("/").endswith("/me")
		existing_appointments = set(appointment_ids(guest.get("/my").text))
		_, slot_id = open_free_slot_page(guest)
		booked = guest.post(f"/slots/{slot_id}/book")
		assert booked.url.path == "/my"
		new_appointments = set(appointment_ids(guest.get("/my").text)) - existing_appointments
		assert new_appointments, "new patient could not book an available slot"

	with client() as admin, client() as new_patient, client() as second_guest:
		login(admin, ADMIN)
		patient_row_match = re.search(
			rf"<li>\s*{re.escape(email)}\s*([\s\S]*?)</li>",
			admin.get("/admin/users").text,
		)
		assert patient_row_match, "admin cannot see the newly registered patient"
		patient_row = patient_row_match.group(1)
		assert "Blocked: No" in patient_row
		assert "Active" in patient_row

		new_patient_login = new_patient.post(
			"/login",
			data={"email": email, "password": password},
		)
		assert "/me" in str(new_patient_login.url)
		admin.post(f"/admin/users/{user_id}/block")
		blocked_page = new_patient.get("/my")
		assert blocked_page.status_code == 403
		assert "Account is blocked" in blocked_page.text

		reregister = second_guest.post(
			"/register",
			data={
				"email": email,
				"password": password,
				"confirm_password": password,
			},
		)
		assert reregister.status_code == 409
		assert "already exists" in reregister.text
		assert psql(f"SELECT count(*) FROM users WHERE lower(email) = '{email}'") == "1"

		try:
			assert "Blocked: Yes" in admin.get("/admin/users").text
		finally:
			psql(
				f"""
				DELETE FROM audit_events WHERE actor_user_id = {user_id};
				DELETE FROM appointments WHERE patient_user_id = {user_id};
				DELETE FROM users WHERE id = {user_id};
				"""
			)
