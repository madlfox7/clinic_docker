import os
import re
import statistics
import subprocess
import time
import uuid
from datetime import date, timedelta
from pathlib import Path

import httpx
import pytest

from tests.csrf_client import CsrfClient
from tests.clinical_notes import (
	NOTE_DOCTOR1_PATIENT_A,
	NOTE_DOCTOR2_PATIENT_B,
	cleanup_cross_doctor_notes,
	insert_cross_doctor_notes,
)

ROOT = Path(__file__).resolve().parents[1]

BASE = os.environ.get("CLINIC_TEST_BASE", "http://localhost:8080")
MAILPIT = os.environ.get("CLINIC_MAILPIT", "http://127.0.0.1:8025")
PASSWORD = "password123"

PAT = "pat@clinic.local"
PAT2 = "pat2@clinic.local"
DOC = "doc@clinic.local"
DOC2 = "doc2@clinic.local"
REG = "reg@clinic.local"
ADMIN = "admin@clinic.local"


def client():
	return CsrfClient(base_url=BASE, follow_redirects=True, timeout=10.0)


def login(c: httpx.Client, email: str) -> httpx.Response:
	return c.post("/login", data={"email": email, "password": PASSWORD})


def mailpit_messages(address: str) -> list[dict]:
	response = httpx.get(
		f"{MAILPIT}/api/v1/search",
		params={"query": f"to:{address}"},
		timeout=5,
	)
	response.raise_for_status()
	return response.json().get("messages") or []


def accept_setup_link(c: httpx.Client, email: str, password: str) -> httpx.Response:
	response = c.post(
		"/reset-password",
		data={
			"token": latest_reset_token(email),
			"new_password": password,
			"confirm_password": password,
		},
	)
	assert "Password updated." in response.text
	return response


def latest_reset_token(address: str) -> str:
	messages = mailpit_messages(address)
	assert messages, "reset email was not delivered"
	message_id = messages[0].get("ID") or messages[0].get("Id")
	message = httpx.get(f"{MAILPIT}/api/v1/message/{message_id}", timeout=5)
	message.raise_for_status()
	body = message.json().get("Text") or ""
	match = re.search(r"token=([0-9a-f]{64})", body)
	assert match, body
	return match.group(1)


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


def test_login_throttles_repeated_failed_attempts():
	email = f"throttle-{uuid.uuid4().hex}@clinic.local"
	password = "Throttle-Check-2026!"
	with client() as c:
		created = c.post(
			"/register",
			data={
				"email": email,
				"password": password,
				"confirm_password": password,
			},
		)
		assert "registered=1" in str(created.url)
		try:
			for _ in range(5):
				failed = c.post(
					"/login", data={"email": email, "password": "incorrect"}
				)
				assert failed.status_code == 401
			throttled = c.post(
				"/login", data={"email": email, "password": password}
			)
			assert throttled.status_code == 429
			assert throttled.headers["Retry-After"] == "900"
		finally:
			psql(
				f"""
				DELETE FROM login_attempts
				WHERE email_fingerprint = public.digest(lower('{email}'), 'sha256');
				DELETE FROM users WHERE email = '{email}'
				"""
			)


def test_nul_characters_are_rejected_before_database_use():
	nul = "\x00"
	with client() as guest, client() as admin, client() as doctor, client() as registrar:
		login(admin, ADMIN)
		login(doctor, DOC)
		login(registrar, REG)

		login_nul = guest.post(
			"/login", data={"email": PAT, "password": f"bad{nul}password"}
		)
		assert login_nul.status_code == 400
		assert "NUL characters are not allowed" in login_nul.text
		register_nul = guest.post(
			"/register",
			data={
				"email": f"bad{nul}@clinic.local",
				"password": "New-Password-2026!",
				"confirm_password": "New-Password-2026!",
			},
		)
		assert register_nul.status_code == 400

		service_nul = admin.post(
			"/admin/services",
			data={
				"name": f"bad{nul}service",
				"duration_minutes": "30",
				"buffer_minutes": "0",
			},
		)
		assert "error=invalid_service" in str(service_nul.url)
		holiday_nul = admin.post(
			"/admin/holidays",
			data={
				"holiday_day": psql("SELECT CURRENT_DATE + 30"),
				"name": f"bad{nul}holiday",
			},
		)
		assert "error=holiday_name_invalid" in str(holiday_nul.url)
		comment_nul = doctor.post(
			"/doctor/time-off-requests",
			data={
				"starts_on": psql("SELECT CURRENT_DATE + 30"),
				"ends_on": psql("SELECT CURRENT_DATE + 30"),
				"comment": f"bad{nul}comment",
			},
		)
		assert "error=request_comment_invalid" in str(comment_nul.url)
		record_nul = doctor.post(
			"/doctor/appointments/1/records",
			data={"record_type": "note", "body": f"bad{nul}note"},
		)
		assert record_nul.history
		assert "error=invalid_text" in record_nul.history[0].headers["location"]
		settings_nul = admin.post(
			"/admin/settings", data={"address": "address", "phone": f"bad{nul}phone"}
		)
		assert "error=invalid_text" in str(settings_nul.url)
		_, slot_id = open_free_slot_page(registrar)
		booking_nul = registrar.post(
			f"/slots/{slot_id}/book", data={"patient_email": f"bad{nul}@clinic.local"}
		)
		assert "error=patient_not_found" in str(booking_nul.url)
		search_nul = registrar.get(
			"/registrar/patients/search", params={"q": f"bad{nul}"}
		)
		assert search_nul.status_code == 400


def test_weak_passwords_are_rejected_without_creating_users():
	stamp = uuid.uuid4().hex
	email = f"weak-{stamp}@example.com"
	cases = (
		"11111111",
		"aaaaaaaa",
		email,
		f"xx{email.split('@')[0]}1",
		"abcabcab",
		"abcdabcd",
		"password",
		"12345678",
		"qwertyui",
		"letmein1",
	)
	with client() as guest, client() as admin, client() as patient:
		for password in ("        ", " Policy-Check-2026!", "Policy-Check-2026! "):
			rejected = guest.post(
				"/register",
				data={
					"email": email,
					"password": password,
					"confirm_password": password,
				},
			)
			assert rejected.status_code == 400
			assert "Password must not start or end with a space." in rejected.text
		spaced_email = guest.post(
			"/register",
			data={
				"email": f"bad {stamp}@example.com",
				"password": "Policy-Check-2026!",
				"confirm_password": "Policy-Check-2026!",
			},
		)
		assert spaced_email.status_code == 400
		assert "Enter a valid email address." in spaced_email.text
		for password in cases:
			rejected = guest.post(
				"/register",
				data={
					"email": email,
					"password": password,
					"confirm_password": password,
				},
			)
			assert rejected.status_code == 400
			assert "Choose a non-default password." in rejected.text
			assert psql(
				f"SELECT count(*) FROM users WHERE lower(email) = lower('{email}')"
			) == "0"
		login(admin, ADMIN)
		staff_page = admin.get("/admin/users")
		assert 'name="password"' not in staff_page.text
		assert 'name="new_password"' not in staff_page.text
		staff_email = f"weak-staff-{stamp}@example.com"
		staff = admin.post(
			"/admin/users",
			data={
				"email": staff_email,
				"role": "registrar",
				"password": "aaaaaaaa",
				"confirm_password": "aaaaaaaa",
			},
		)
		assert "Staff account created." in staff.text
		assert psql(
			f"SELECT count(*) FROM users WHERE email = '{staff_email}'"
		) == "1"
		with client() as stranger:
			denied_chosen = stranger.post(
				"/login",
				data={"email": staff_email, "password": "aaaaaaaa"},
			)
			assert "Invalid email or password" in denied_chosen.text
		psql(
			f"""
			DELETE FROM audit_events
			WHERE target_id = (SELECT id FROM users WHERE email = '{staff_email}');
			DELETE FROM password_reset_tokens
			WHERE user_id = (SELECT id FROM users WHERE email = '{staff_email}');
			DELETE FROM users WHERE email = '{staff_email}';
			"""
		)
		login(patient, PAT)
		changed = patient.post(
			"/me/password",
			data={
				"current_password": PASSWORD,
				"new_password": "        ",
				"confirm_password": "        ",
			},
		)
		assert "password_error=edge_space" in str(changed.url)
		assert "Password must not start or end with a space." in changed.text
		policy_email = f"policy-{stamp}@example.com"
		policy_password = "Policy-Check-2026!"
		created = guest.post(
			"/register",
			data={
				"email": policy_email,
				"password": policy_password,
				"confirm_password": policy_password,
			},
		)
		assert "registered=1" in str(created.url)
		login_policy = guest.post(
			"/login",
			data={"email": f"  {policy_email.upper()}  ", "password": policy_password},
		)
		assert "Role: patient" in login_policy.text
		same = guest.post(
			"/me/password",
			data={
				"current_password": policy_password,
				"new_password": policy_password,
				"confirm_password": policy_password,
			},
		)
		assert "password_error=same" in str(same.url)
		assert "different from your current one" in same.text
		guest.get("/logout")
		spaced_password = "Policy Check 2026"
		spaced = guest.post(
			"/register",
			data={
				"email": f"  Spaced-{stamp}@Example.COM  ",
				"password": spaced_password,
				"confirm_password": spaced_password,
			},
		)
		assert "registered=1" in str(spaced.url)
		stored_email = f"spaced-{stamp}@example.com"
		assert psql(f"SELECT email FROM users WHERE email = '{stored_email}'") == stored_email
		duplicate = guest.post(
			"/register",
			data={
				"email": stored_email,
				"password": spaced_password,
				"confirm_password": spaced_password,
			},
		)
		assert duplicate.status_code == 409
		spaced_login = guest.post(
			"/login",
			data={"email": stored_email, "password": spaced_password},
		)
		assert "Role: patient" in spaced_login.text
		guest.get("/logout")
		stripped_login = guest.post(
			"/login",
			data={"email": stored_email, "password": "PolicyCheck2026"},
		)
		assert "Invalid email or password" in stripped_login.text
		psql(
			f"""
			DELETE FROM audit_events
			WHERE target_id = (SELECT id FROM users WHERE email = '{policy_email}')
			   OR actor_user_id = (SELECT id FROM users WHERE email = '{policy_email}');
			DELETE FROM users WHERE email = '{policy_email}';
			DELETE FROM audit_events
			WHERE target_id = (SELECT id FROM users WHERE email = '{stored_email}')
			   OR actor_user_id = (SELECT id FROM users WHERE email = '{stored_email}');
			DELETE FROM users WHERE email = '{stored_email}';
			"""
		)
		with client() as registrar:
			login(registrar, REG)
			found = registrar.get(
				"/registrar/patients/search",
				params={"q": "  PAT@CLINIC.LOCAL  "},
			)
			assert found.status_code == 200
			assert "pat@clinic.local" in found.text
			rejected_query = registrar.get(
				"/registrar/patients/search",
				params={"q": "pat @clinic.local"},
			)
			assert rejected_query.status_code == 400
	with client() as patient:
		assert login(patient, PAT).status_code == 200


def test_login_timing_does_not_reveal_whether_email_exists():
	email = f"timing-{uuid.uuid4().hex}@example.com"
	password = "Timing-Equal-2026!"
	with client() as guest:
		created = guest.post(
			"/register",
			data={
				"email": email,
				"password": password,
				"confirm_password": password,
			},
		)
		assert "registered=1" in str(created.url)
	try:
		existing = []
		missing = []
		for index in range(3):
			with client() as existing_client:
				started = time.perf_counter()
				failed = existing_client.post(
					"/login", data={"email": email, "password": "wrong-password"}
				)
				existing.append(time.perf_counter() - started)
				assert failed.status_code == 401
			with client() as missing_client:
				started = time.perf_counter()
				failed = missing_client.post(
					"/login",
					data={
						"email": f"missing-{index}-{uuid.uuid4().hex}@example.com",
						"password": "wrong-password",
					},
				)
				missing.append(time.perf_counter() - started)
				assert failed.status_code == 401
		delta = abs(statistics.median(existing) - statistics.median(missing))
		assert delta < 0.15, (existing, missing, delta)
	finally:
		psql(
			f"""
			DELETE FROM login_attempts
			WHERE email_fingerprint = public.digest(lower('{email}'), 'sha256');
			DELETE FROM users WHERE email = '{email}'
			"""
		)


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
		assert "Appointment confirmed" in booked.text
		assert "Appointment booked successfully." in booked.text
		assert "Service duration" in booked.text
		assert re.search(r"\d+ min", booked.text)
		assert "My appointments" in booked.text or "scheduled" in booked.text

		blocked = pat2.post(f"/slots/{slot_id}/book")
		assert "unavailable" in (str(blocked.url) + blocked.text.lower())

		mine = pat.get("/my")
		new_ids = set(appointment_ids(mine.text)) - existing_ids
		assert new_ids, "cancel button missing after book"
		appointment_id = new_ids.pop()
		assert "min service" in mine.text
		assert "return confirm('Cancel this appointment?')" in mine.text
		other_confirmation = pat2.get(
			f"/my?booked=1&appointment_id={appointment_id}"
		)
		assert "Appointment confirmed" not in other_confirmation.text
		pat.post(f"/appointments/{appointment_id}/cancel")

		existing_pat2_ids = set(appointment_ids(pat2.get("/my").text))
		again = pat2.post(f"/slots/{slot_id}/book")
		assert "unavailable" not in (str(again.url) + again.text.lower())
		assert "My appointments" in again.text or "scheduled" in again.text

		mine2 = pat2.get("/my")
		created_pat2_ids = set(appointment_ids(mine2.text)) - existing_pat2_ids
		for appointment_id in created_pat2_ids:
			pat2.post(f"/appointments/{appointment_id}/cancel")


def latest_mail(address: str) -> dict:
	messages = mailpit_messages(address)
	assert messages, f"no mail for {address}"
	message_id = messages[0].get("ID") or messages[0].get("Id")
	message = httpx.get(f"{MAILPIT}/api/v1/message/{message_id}", timeout=5)
	message.raise_for_status()
	return message.json()


def test_appointment_emails_go_to_patient_and_doctor():
	with client() as pat:
		login(pat, PAT)
		doctors = pat.get("/doctors")
		page_text = ""
		slot_id = None
		for doc_id in re.findall(r'href="/doctors/(\d+)/slots"', doctors.text):
			page = pat.get(f"/doctors/{doc_id}/slots")
			ids = slot_ids(page.text)
			if ids:
				page_text = page.text
				slot_id = ids[0]
				break
		assert slot_id, "no free slots left"
		if "Anna Ohanyan" in page_text:
			doctor_name, doctor_email = "Anna Ohanyan", DOC
		else:
			assert "Levon Petrosyan" in page_text
			doctor_name, doctor_email = "Levon Petrosyan", DOC2
		before_patient = len(mailpit_messages(PAT))
		before_doctor = len(mailpit_messages(doctor_email))
		existing_ids = set(appointment_ids(pat.get("/my").text))
		booked = pat.post(f"/slots/{slot_id}/book")
		assert "Appointment booked successfully." in booked.text
		created_ids = set(appointment_ids(pat.get("/my").text)) - existing_ids
		assert created_ids
		appointment_id = created_ids.pop()
		try:
			assert len(mailpit_messages(PAT)) == before_patient + 1
			assert len(mailpit_messages(doctor_email)) == before_doctor + 1
			patient_mail = latest_mail(PAT)
			doctor_mail = latest_mail(doctor_email)
			patient_body = patient_mail.get("Text") or ""
			doctor_body = doctor_mail.get("Text") or ""
			when = re.compile(
				r"Date: \d{1,2} [A-Z][a-z]{2} \d{4}, \d{2}:\d{2}–\d{2}:\d{2}"
			)
			assert patient_mail.get("Subject") == "Appointment confirmed"
			assert doctor_mail.get("Subject") == "Appointment confirmed"
			assert "You have an appointment:" in patient_body
			assert "A patient booked an appointment:" in doctor_body
			assert f"Doctor: {doctor_name}" in patient_body
			assert f"Doctor: {doctor_name}" in doctor_body
			assert "Service: " in patient_body
			assert when.search(patient_body)
			assert when.search(doctor_body)
			assert "appointment id" not in patient_body.lower()
			assert "appointment id" not in doctor_body.lower()
			assert "token=" not in patient_body
			pat.post(f"/appointments/{appointment_id}/cancel")
			assert len(mailpit_messages(PAT)) == before_patient + 2
			assert len(mailpit_messages(doctor_email)) == before_doctor + 2
			cancelled_patient = latest_mail(PAT)
			cancelled_doctor = latest_mail(doctor_email)
			assert cancelled_patient.get("Subject") == "Appointment cancelled"
			assert cancelled_doctor.get("Subject") == "Appointment cancelled"
			assert "This appointment was cancelled:" in (cancelled_patient.get("Text") or "")
			assert "An appointment was cancelled:" in (cancelled_doctor.get("Text") or "")
			assert when.search(cancelled_patient.get("Text") or "")
		finally:
			if appointment_id in appointment_ids(pat.get("/my").text):
				pat.post(f"/appointments/{appointment_id}/cancel")


def test_appointment_emails_respect_notification_flag():
	with client() as pat, client() as doc:
		login(pat, PAT)
		login(doc, DOC)
		cabinet = pat.get("/me")
		assert "Receive appointment emails" in cabinet.text
		assert 'name="email_notifications" value="1" checked' in cabinet.text
		doctors = pat.get("/doctors")
		slot_id = None
		doctor_email = None
		for doc_id in re.findall(r'href="/doctors/(\d+)/slots"', doctors.text):
			page = pat.get(f"/doctors/{doc_id}/slots")
			ids = slot_ids(page.text)
			if not ids:
				continue
			slot_id = ids[0]
			doctor_email = DOC if "Anna Ohanyan" in page.text else DOC2
			break
		assert slot_id and doctor_email
		doctor_client = doc if doctor_email == DOC else None
		if doctor_client is None:
			doctor_client = client()
			login(doctor_client, doctor_email)
		existing_ids = set(appointment_ids(pat.get("/my").text))
		appointment_id = None
		try:
			disabled = pat.post("/me/notifications")
			assert "Email notification setting saved." in disabled.text
			assert 'name="email_notifications" value="1" checked' not in disabled.text
			before_patient = len(mailpit_messages(PAT))
			with client() as guest:
				reset = guest.post("/forgot-password", data={"email": PAT})
			assert "sent=1" in str(reset.url)
			assert len(mailpit_messages(PAT)) == before_patient + 1
			psql(
				"UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP "
				"WHERE used_at IS NULL"
			)
			before_doctor = len(mailpit_messages(doctor_email))
			booked = pat.post(f"/slots/{slot_id}/book")
			assert "Appointment booked successfully." in booked.text
			created_ids = set(appointment_ids(pat.get("/my").text)) - existing_ids
			assert created_ids
			appointment_id = created_ids.pop()
			assert len(mailpit_messages(PAT)) == before_patient + 1
			assert len(mailpit_messages(doctor_email)) == before_doctor + 1
			doctor_client.post("/me/notifications")
			pat.post(f"/appointments/{appointment_id}/cancel")
			assert len(mailpit_messages(PAT)) == before_patient + 1
			assert len(mailpit_messages(doctor_email)) == before_doctor + 1
			appointment_id = None
		finally:
			pat.post("/me/notifications", data={"email_notifications": "1"})
			doctor_client.post("/me/notifications", data={"email_notifications": "1"})
			if doctor_client is not doc:
				doctor_client.close()
			if appointment_id and appointment_id in appointment_ids(pat.get("/my").text):
				pat.post(f"/appointments/{appointment_id}/cancel")


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
			assert "Past appointments cannot be cancelled." in registrar_past_cancel.text
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
			assert "conflict_patient_id" not in str(r.url)
			assert "conflict_appointment_id" not in str(r.url)
			assert "conflict_patient_id" not in r.text
			assert "conflict_appointment_id" not in r.text
		finally:
			mine = c.get("/my")
			created_ids = set(appointment_ids(mine.text)) - existing_ids
			for appointment_id in created_ids:
				c.post(f"/appointments/{appointment_id}/cancel")


def test_overlap_redirect_hides_patient_and_appointment_ids():
	service_id = psql("SELECT id FROM services WHERE name = 'General consultation'")
	anna = psql("SELECT id FROM doctors WHERE full_name = 'Anna Ohanyan'")
	levon = psql("SELECT id FROM doctors WHERE full_name = 'Levon Petrosyan'")
	anna_slot = psql(
		f"""
		INSERT INTO slots (
			doctor_id, service_id, starts_at, ends_at, duration_minutes, buffer_minutes
		)
		VALUES (
			{int(anna)}, {int(service_id)},
			'2037-06-06 10:00', '2037-06-06 10:30', 30, 0
		)
		RETURNING id
		"""
	)
	levon_slot = psql(
		f"""
		INSERT INTO slots (
			doctor_id, service_id, starts_at, ends_at, duration_minutes, buffer_minutes
		)
		VALUES (
			{int(levon)}, {int(service_id)},
			'2037-06-06 10:15', '2037-06-06 10:45', 30, 0
		)
		RETURNING id
		"""
	)
	try:
		with client() as patient, client() as registrar:
			login(patient, PAT)
			login(registrar, REG)
			booked = patient.post(
				f"/slots/{int(anna_slot)}/book",
				data={"service_id": service_id},
			)
			assert booked.status_code == 200
			assert "booked" in str(booked.url)
			overlapped = patient.post(
				f"/slots/{int(levon_slot)}/book",
				data={"service_id": service_id},
			)
			assert "error=overlap" in str(overlapped.url)
			assert "conflict_patient_id" not in str(overlapped.url)
			assert "conflict_appointment_id" not in str(overlapped.url)
			assert "Anna Ohanyan" in overlapped.text
			registrar_overlap = registrar.post(
				f"/slots/{int(levon_slot)}/book",
				data={"service_id": service_id, "patient_email": PAT},
			)
			location = str(registrar_overlap.url)
			assert "error=overlap" in location
			assert "patient_email=" in location
			assert "conflict_patient_id" not in location
			assert "conflict_appointment_id" not in location
			assert "Anna Ohanyan" in registrar_overlap.text
			assert "conflict_patient_id" not in registrar_overlap.text
			assert "conflict_appointment_id" not in registrar_overlap.text
	finally:
		psql(
			f"""
			DELETE FROM appointments
			WHERE slot_id IN ({int(anna_slot)}, {int(levon_slot)});
			DELETE FROM slots
			WHERE id IN ({int(anna_slot)}, {int(levon_slot)});
			"""
		)


def test_patient_recovers_password_without_admin_reset():
	email = f"recover-patient-{uuid.uuid4().hex}@example.test"
	password = "Clinic-Patient-Recover-2026!"
	replacement = "Clinic-Patient-Recovered-2026!"
	user_id = None
	try:
		with (
			client() as guest,
			client() as other_session,
			client() as admin,
			client() as doctor,
		):
			registered = guest.post(
				"/register",
				data={
					"email": email,
					"password": password,
					"confirm_password": password,
				},
			)
			assert "Account created." in registered.text
			user_id = int(psql(f"SELECT id FROM users WHERE email = '{email}'"))
			login(admin, ADMIN)
			users_page = admin.get("/admin/users")
			assert "Forgot password?" not in users_page.text
			assert "new_password" not in users_page.text
			assert f'action="/admin/users/{user_id}/reset-link"' in users_page.text
			denied = admin.post(
				f"/admin/users/{user_id}/password",
				data={
					"new_password": replacement,
					"confirm_password": replacement,
				},
			)
			assert "password_reset_not_allowed" in str(denied.url)
			assert "Role: patient" in guest.post(
				"/login", data={"email": email, "password": password}
			).text
			other_session.post("/login", data={"email": email, "password": password})
			logout(guest)
			login_page = guest.get("/login")
			assert "Forgot password?" in login_page.text
			doctor_messages = len(mailpit_messages(DOC))
			doctor_reset = doctor.post(
				"/forgot-password", data={"email": DOC}
			)
			assert "sent=1" in str(doctor_reset.url)
			assert "token=" not in str(doctor_reset.url)
			assert "reset-password?token=" not in doctor_reset.text
			assert len(mailpit_messages(DOC)) == doctor_messages + 1
			psql(
				"UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP "
				"WHERE used_at IS NULL"
			)
			sent = guest.post("/forgot-password", data={"email": email})
			assert "sent=1" in str(sent.url)
			assert "token=" not in str(sent.url)
			assert "reset link has been sent" in sent.text
			assert "reset-password?token=" not in sent.text
			token = latest_reset_token(email)
			weak = guest.post(
				"/reset-password",
				data={
					"token": token,
					"new_password": "password123",
					"confirm_password": "password123",
				},
			)
			assert "Choose a non-default password." in weak.text
			changed = guest.post(
				"/reset-password",
				data={
					"token": token,
					"new_password": replacement,
					"confirm_password": replacement,
				},
			)
			assert "Password updated." in changed.text
			assert other_session.get("/me").url.path == "/login"
			assert "Invalid email or password" in guest.post(
				"/login", data={"email": email, "password": password}
			).text
			assert "Role: patient" in guest.post(
				"/login", data={"email": email, "password": replacement}
			).text
			logout(guest)
			reused = guest.post(
				"/reset-password",
				data={
					"token": token,
					"new_password": "Clinic-Patient-Again-2026!",
					"confirm_password": "Clinic-Patient-Again-2026!",
				},
			)
			assert "invalid or has expired" in reused.text
			opened_again = guest.get(f"/reset-password?token={token}")
			assert opened_again.status_code == 400
			assert "invalid or has expired" in opened_again.text
			assert 'name="new_password"' not in opened_again.text
			logout(guest)
			guest.post("/forgot-password", data={"email": email})
			same_reset = guest.post(
				"/reset-password",
				data={
					"token": latest_reset_token(email),
					"new_password": replacement,
					"confirm_password": replacement,
				},
			)
			assert "different from your current one" in same_reset.text
			assert "Role: patient" in guest.post(
				"/login", data={"email": email, "password": replacement}
			).text
	finally:
		if user_id:
			psql(
				f"""
				DELETE FROM audit_events
				WHERE actor_user_id = {user_id} OR target_id = {user_id};
				DELETE FROM users WHERE id = {user_id};
				"""
			)


def test_last_admin_reset_link_is_server_only():
	before = len(mailpit_messages(ADMIN))
	with client() as guest, client() as admin:
		sent = guest.post("/forgot-password", data={"email": ADMIN})
		assert "sent=1" in str(sent.url)
		assert len(mailpit_messages(ADMIN)) == before
		login(admin, ADMIN)
		own_admin_id = int(psql(f"SELECT id FROM users WHERE email = '{ADMIN}'"))
		denied = admin.post(f"/admin/users/{own_admin_id}/reset-link")
		assert "password_link_self" in str(denied.url)
		assert len(mailpit_messages(ADMIN)) == before
	refused = subprocess.run(
		[
			"docker", "compose", "exec", "-T", "api",
			"python", "send_reset_link.py", REG,
		],
		cwd=ROOT,
		capture_output=True,
		text=True,
	)
	assert refused.returncode != 0, refused.stdout
	assert "last remaining administrator" in refused.stderr
	issued = subprocess.run(
		[
			"docker", "compose", "exec", "-T", "api",
			"python", "send_reset_link.py", ADMIN,
		],
		cwd=ROOT,
		capture_output=True,
		text=True,
	)
	assert issued.returncode == 0, issued.stderr
	assert "Reset link sent." in issued.stdout
	assert "token=" not in issued.stdout
	assert "token=" not in issued.stderr
	assert len(mailpit_messages(ADMIN)) == before + 1
	psql(
		"UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP "
		"WHERE used_at IS NULL"
	)


def test_admin_cannot_set_email_or_open_medical_text():
	with client() as admin:
		login(admin, ADMIN)
		records = admin.get("/my/records")
		assert records.status_code == 403
		doctor_page = admin.get("/doctor/patients")
		assert doctor_page.status_code == 403
		users = admin.get("/admin/users")
		assert 'name="password"' not in users.text
		assert 'name="new_email"' not in users.text
	denied = subprocess.run(
		[
			"docker", "compose", "exec", "-T", "db",
			"psql", "-U", "clinic", "-d", "clinic",
			"-v", "ON_ERROR_STOP=1", "-c",
			"BEGIN; SET LOCAL ROLE app_admin; "
			"SELECT set_config('app.user_id', '1', true); "
			"UPDATE users SET email = 'stolen@example.test' WHERE role = 'patient';",
		],
		cwd=ROOT,
		capture_output=True,
		text=True,
	)
	assert denied.returncode != 0, denied.stdout
	assert (
		"email can only be changed" in denied.stderr
		or "permission denied for table users" in denied.stderr
	)


def test_owner_confirms_email_change_on_both_addresses():
	email = f"email-change-{uuid.uuid4().hex}@example.test"
	new_email = f"email-next-{uuid.uuid4().hex}@example.test"
	password = "Clinic-Email-Change-2026!"
	user_id = None
	try:
		with client() as owner, client() as other:
			registered = owner.post(
				"/register",
				data={
					"email": email,
					"password": password,
					"confirm_password": password,
				},
			)
			assert "Account created." in registered.text
			user_id = int(psql(f"SELECT id FROM users WHERE email = '{email}'"))
			assert "Role: patient" in owner.post(
				"/login", data={"email": email, "password": password}
			).text
			other.post("/login", data={"email": email, "password": password})
			requested = owner.post("/me/email", data={"new_email": new_email})
			assert "email_change=sent" in str(requested.url)
			assert new_email not in psql(f"SELECT email FROM users WHERE id = {user_id}")
			first = owner.post(
				"/confirm-email",
				data={"token": latest_reset_token(email)},
			)
			assert "still needs" in first.text
			second = owner.post(
				"/confirm-email",
				data={"token": latest_reset_token(new_email)},
			)
			assert "email_changed=1" in str(second.url) or second.url.path == "/login"
			assert other.get("/me").url.path == "/login"
			assert "Invalid email or password" in owner.post(
				"/login", data={"email": email, "password": password}
			).text
			assert "Role: patient" in owner.post(
				"/login", data={"email": new_email, "password": password}
			).text
	finally:
		psql(
			f"""
			DELETE FROM audit_events
			WHERE actor_user_id IN (
			  SELECT id FROM users WHERE email IN ('{email}', '{new_email}')
			) OR target_id IN (
			  SELECT id FROM users WHERE email IN ('{email}', '{new_email}')
			);
			DELETE FROM users WHERE email IN ('{email}', '{new_email}');
			"""
		)


def test_patient_cannot_open_doctor_appointments():
	with client() as c:
		login(c, PAT)
		r = c.get("/doctor/appointments")
		assert r.status_code == 403
		assert "Manage patients" not in r.text


def test_doctor_sees_only_own_cabinet():
	with client() as c:
		login(c, DOC)
		r = c.get("/doctor/appointments")
		assert r.status_code == 200
		mine = c.get("/my")
		assert mine.status_code == 403


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

			patient_id = psql(f"SELECT id FROM users WHERE email = '{PAT}'")
			patient_list = doctor.get("/doctor/patients")
			assert patient_list.status_code == 200
			assert PAT in patient_list.text
			assert "Next appointment" in patient_list.text
			patient_history = doctor.get(f"/doctor/patients/{patient_id}")
			assert patient_history.status_code == 200
			assert note_body in patient_history.text
			assert prescription_body in patient_history.text
			other_patient_history = other_doctor.get(
				f"/doctor/patients/{patient_id}"
			)
			assert note_body not in other_patient_history.text
			assert prescription_body not in other_patient_history.text

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
			assert "medical.patient_history.view" in audit.text
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
			appointment_day, appointment_start, appointment_end = psql(
				f"""
				SELECT to_char(starts_at, 'YYYY-MM-DD'),
				       to_char(starts_at, 'HH24:MI'),
				       to_char(ends_at, 'HH24:MI')
				FROM appointments WHERE id = {appointment_id}
				"""
			).split("|")
			doctor_calendar = doctor.get(
				f"/doctor/calendar?day={appointment_day}"
			)
			assert re.search(
				rf"{appointment_start}–{appointment_end}[\s\S]{{0,120}}Available",
				doctor_calendar.text,
			)
			cancelled_records = doctor.get(record_url)
			assert note_body in cancelled_records.text
			assert prescription_body in cancelled_records.text
			after_cancel_note = doctor.post(
				record_url,
				data={"record_type": "note", "body": "note-after-cancellation"},
			)
			assert "error=record_unavailable" in str(after_cancel_note.url)
			assert "note-after-cancellation" not in pat.get("/my/records").text
			assert "read-only" in cancelled_records.text
			assert "<textarea" not in cancelled_records.text
			cancelled_history = doctor.get(f"/doctor/patients/{patient_id}")
			still_own = psql(
				"SELECT count(*) FROM appointments a JOIN doctors d ON d.id = a.doctor_id "
				f"JOIN users u ON u.id = d.user_id AND u.email = '{DOC}' "
				f"WHERE a.patient_user_id = {patient_id} "
				"AND a.status IN ('scheduled', 'completed') "
				"AND a.starts_at > now() - interval '12 months'"
			)
			if still_own == "0":
				# only a cancelled visit left: no longer this doctor's patient
				assert "patient_unavailable" in str(cancelled_history.url)
			else:
				assert "cancelled" in cancelled_history.text
				assert note_body in cancelled_history.text

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


def _book_for_patient(pat, doctor_email):
	doctor_id = psql(
		f"SELECT id FROM doctors WHERE user_id = "
		f"(SELECT id FROM users WHERE email = '{doctor_email}')"
	)
	existing_ids = set(appointment_ids(pat.get("/my").text))
	for slot_id in slot_ids(pat.get(f"/doctors/{doctor_id}/slots").text):
		pat.post(f"/slots/{slot_id}/book")
		created_ids = set(appointment_ids(pat.get("/my").text)) - existing_ids
		if created_ids:
			return int(created_ids.pop())
	pytest.fail("no bookable slot for medical record test")


def test_medical_records_follow_visit_status_in_ui():
	with client() as pat, client() as doctor, client() as other_doctor:
		login(pat, PAT)
		login(doctor, DOC)
		login(other_doctor, DOC2)
		appointment_id = None
		marker = uuid.uuid4().hex[:8]
		diagnosis = f"diagnosis-{marker}"
		prescription = f"prescription-{marker}"
		late_note = f"late-note-{marker}"
		late_prescription = f"late-prescription-{marker}"
		try:
			appointment_id = _book_for_patient(pat, DOC)
			record_url = f"/doctor/appointments/{appointment_id}/records"
			page = doctor.get(record_url)
			assert "Report / diagnosis" in page.text
			assert "<label>Prescription" in page.text
			assert "<textarea" in page.text

			saved = doctor.post(record_url, data={"record_type": "note", "body": diagnosis})
			assert "saved=note" in str(saved.url)
			saved = doctor.post(
				record_url, data={"record_type": "prescription", "body": prescription}
			)
			assert "saved=prescription" in str(saved.url)

			foreign = other_doctor.post(
				record_url, data={"record_type": "note", "body": f"foreign-{marker}"}
			)
			assert "error=record_unavailable" in str(foreign.url)

			my = pat.get("/my").text
			assert "Report / diagnosis:" in my and diagnosis in my
			assert "Prescription:" in my and prescription in my
			assert f"foreign-{marker}" not in my

			cancelled = pat.post(f"/appointments/{appointment_id}/cancel")
			assert "cancelled=1" in str(cancelled.url)

			my = pat.get("/my").text
			assert diagnosis in my and prescription in my
			read_only = doctor.get(record_url)
			assert diagnosis in read_only.text and prescription in read_only.text
			assert "read-only" in read_only.text
			assert "<textarea" not in read_only.text
			for record_type, body in (("note", late_note), ("prescription", late_prescription)):
				blocked = doctor.post(record_url, data={"record_type": record_type, "body": body})
				assert "error=record_unavailable" in str(blocked.url)
			my = pat.get("/my").text
			assert late_note not in my and late_prescription not in my
			assert psql(
				f"SELECT count(*) FROM visit_notes WHERE appointment_id = {appointment_id}"
			) == "1"
			assert psql(
				f"SELECT count(*) FROM prescriptions WHERE appointment_id = {appointment_id}"
			) == "1"
		finally:
			if appointment_id is not None:
				psql(
					f"DELETE FROM prescriptions WHERE appointment_id = {appointment_id};"
					f"DELETE FROM visit_notes WHERE appointment_id = {appointment_id}"
				)
				if str(appointment_id) in appointment_ids(pat.get("/my").text):
					pat.post(f"/appointments/{appointment_id}/cancel")


def _doctor_insert_sql(table, appointment_sql, doctor_user_email, status):
	return f"""
		BEGIN;
		INSERT INTO appointments (slot_id, patient_user_id, doctor_id, starts_at, ends_at, reserved_ends_at, status)
		  SELECT id, (SELECT id FROM users WHERE email = '{PAT}'), doctor_id, starts_at,
		         starts_at + make_interval(mins => duration_minutes), ends_at, '{status}'
		  FROM ({appointment_sql}) AS slot
		  RETURNING id AS probe_id, doctor_id AS probe_doctor, patient_user_id AS probe_patient \\gset
		SELECT set_config('app.user_id',
		  (SELECT id FROM users WHERE email = '{doctor_user_email}')::text, true);
		SET LOCAL ROLE app_doctor;
		INSERT INTO {table} (appointment_id, doctor_id, patient_user_id, body)
		  VALUES (:probe_id, :probe_doctor, :probe_patient, 'probe');
		ROLLBACK;
	"""


def _run_psql_raw(sql):
	return subprocess.run(
		["docker", "compose", "exec", "-T", "db", "psql", "-X", "-U", "clinic",
		 "-d", "clinic", "-v", "ON_ERROR_STOP=1", "-At"],
		cwd=ROOT, input=sql, capture_output=True, text=True,
	)


@pytest.mark.parametrize("table", ["visit_notes", "prescriptions"])
def test_db_blocks_medical_writes_on_cancelled_or_foreign_visit(table):
	free_slot = (
		"SELECT s.* FROM slots s JOIN doctors d ON d.id = s.doctor_id "
		f"JOIN users u ON u.id = d.user_id AND u.email = '{DOC}' "
		"WHERE s.starts_at > now() + interval '1 hour' "
		"AND NOT EXISTS (SELECT 1 FROM appointments a WHERE a.slot_id = s.id) "
		"ORDER BY s.id LIMIT 1"
	)
	own_scheduled = _run_psql_raw(_doctor_insert_sql(table, free_slot, DOC, "scheduled"))
	assert own_scheduled.returncode == 0, own_scheduled.stderr
	assert own_scheduled.stdout.count("INSERT 0 1") == 2, own_scheduled.stdout

	own_cancelled = _run_psql_raw(_doctor_insert_sql(table, free_slot, DOC, "cancelled"))
	assert own_cancelled.returncode != 0
	assert "row-level security" in own_cancelled.stderr

	foreign = _run_psql_raw(_doctor_insert_sql(table, free_slot, DOC2, "scheduled"))
	assert foreign.returncode != 0
	assert "row-level security" in foreign.stderr

	for role in ("app_admin", "app_registrar"):
		denied = _run_psql_raw(
			f"BEGIN; SET LOCAL ROLE {role}; SELECT body FROM {table} LIMIT 1; ROLLBACK;"
		)
		assert denied.returncode != 0
		assert "permission denied" in denied.stderr


def _past_visit(doctor_email, patient_email=PAT, status="scheduled"):
	for _ in range(20):
		days = 20 + int(uuid.uuid4().int % 300)
		hours = int(uuid.uuid4().int % 10)
		result = _run_psql_raw(f"""
			INSERT INTO appointments
			  (slot_id, patient_user_id, doctor_id, starts_at, ends_at, reserved_ends_at, status)
			SELECT s.id, (SELECT id FROM users WHERE email = '{patient_email}'), s.doctor_id,
			       t.st, t.st + make_interval(mins => s.duration_minutes),
			       t.st + (s.ends_at - s.starts_at), '{status}'
			FROM slots s
			JOIN doctors d ON d.id = s.doctor_id
			JOIN users u ON u.id = d.user_id AND u.email = '{doctor_email}'
			CROSS JOIN LATERAL (
			  SELECT date_trunc('hour', now()::timestamp)
			         - interval '{days} days' - interval '{hours} hours' AS st
			) t
			ORDER BY s.id LIMIT 1
			RETURNING id;
		""")
		if result.returncode == 0:
			return int(result.stdout.split()[0])
	pytest.fail("could not create a past visit")


def _as_role(role, email, sql):
	return _run_psql_raw(
		"BEGIN;\n"
		f"SELECT set_config('app.user_id', (SELECT id FROM users WHERE email = '{email}')::text, true);\n"
		f"SET LOCAL ROLE {role};\n{sql}\nCOMMIT;\n"
	)


def _status(appointment_id):
	return psql(f"SELECT status FROM appointments WHERE id = {appointment_id}")


def _drop_visit(appointment_id):
	psql(
		f"DELETE FROM prescriptions WHERE appointment_id = {appointment_id};"
		f"DELETE FROM visit_notes WHERE appointment_id = {appointment_id};"
		f"DELETE FROM appointments WHERE id = {appointment_id}"
	)


def test_only_doctor_can_complete_own_started_visit():
	visit = _past_visit(DOC)
	try:
		complete = f"UPDATE appointments SET status = 'completed' WHERE id = {visit};"
		for role, email in (
			("app_patient", PAT),
			("app_registrar", REG),
			("app_admin", ADMIN),
			("app_doctor", DOC2),
		):
			_as_role(role, email, complete)
			assert _status(visit) == "scheduled", role

		done = _as_role("app_doctor", DOC, complete)
		assert done.returncode == 0, done.stderr
		assert "UPDATE 1" in done.stdout
		assert _status(visit) == "completed"

		# completed is final: nobody can cancel or reopen it
		for role, email in (
			("app_patient", PAT),
			("app_registrar", REG),
			("app_admin", ADMIN),
			("app_doctor", DOC),
		):
			for target in ("cancelled", "scheduled"):
				_as_role(
					role, email,
					f"UPDATE appointments SET status = '{target}' WHERE id = {visit};",
				)
				assert _status(visit) == "completed", (role, target)
	finally:
		_drop_visit(visit)


def test_doctor_cannot_complete_future_visit():
	with client() as pat:
		login(pat, PAT)
		visit = _book_for_patient(pat, DOC)
		try:
			_as_role(
				"app_doctor", DOC,
				f"UPDATE appointments SET status = 'completed' WHERE id = {visit};",
			)
			assert _status(visit) == "scheduled"
		finally:
			pat.post(f"/appointments/{visit}/cancel")


def test_records_on_completed_visit_and_survive_status_change():
	visit = _past_visit(DOC)
	cancelled_visit = _past_visit(DOC, status="cancelled")
	marker = uuid.uuid4().hex[:8]
	try:
		with client() as doctor, client() as pat:
			login(doctor, DOC)
			login(pat, PAT)
			record_url = f"/doctor/appointments/{visit}/records"
			page = doctor.get(record_url).text
			assert "Mark as completed" in page
			saved = doctor.post(
				record_url, data={"record_type": "note", "body": f"before-{marker}"}
			)
			assert "saved=note" in str(saved.url)

			done = doctor.post(f"/doctor/appointments/{visit}/complete")
			assert "completed=1" in str(done.url)
			assert _status(visit) == "completed"
			page = done.text
			assert "Mark as completed" not in page
			assert "<textarea" in page
			assert f"before-{marker}" in page

			for record_type in ("note", "prescription"):
				saved = doctor.post(
					record_url, data={"record_type": record_type, "body": f"after-{marker}"}
				)
				assert f"saved={record_type}" in str(saved.url)
			assert psql(
				f"SELECT count(*) FROM visit_notes WHERE appointment_id = {visit}"
			) == "2"

			my = pat.get("/my").text
			assert "(completed)" in my
			assert f"before-{marker}" in my and f"after-{marker}" in my

			again = doctor.post(f"/doctor/appointments/{visit}/complete")
			assert "error=complete_unavailable" in str(again.url)

			cancelled_url = f"/doctor/appointments/{cancelled_visit}/records"
			page = doctor.get(cancelled_url).text
			assert "<textarea" not in page and "Mark as completed" not in page
			blocked = doctor.post(
				cancelled_url, data={"record_type": "note", "body": f"late-{marker}"}
			)
			assert "error=record_unavailable" in str(blocked.url)
			blocked = doctor.post(f"/doctor/appointments/{cancelled_visit}/complete")
			assert "error=complete_unavailable" in str(blocked.url)

		for role in ("app_admin", "app_registrar"):
			denied = _as_role(role, ADMIN if role == "app_admin" else REG,
				f"SELECT body FROM visit_notes WHERE appointment_id = {visit};")
			assert denied.returncode != 0
			assert "permission denied" in denied.stderr
	finally:
		_drop_visit(visit)
		_drop_visit(cancelled_visit)


def test_notes_survive_cancel_of_scheduled_visit():
	visit = _past_visit(DOC)
	try:
		wrote = _as_role(
			"app_doctor", DOC,
			"INSERT INTO visit_notes (appointment_id, doctor_id, patient_user_id, body) "
			f"SELECT id, doctor_id, patient_user_id, 'kept' FROM appointments WHERE id = {visit};",
		)
		assert "INSERT 0 1" in wrote.stdout, wrote.stderr
		psql(f"UPDATE appointments SET status = 'cancelled' WHERE id = {visit}")
		assert psql(
			f"SELECT count(*) FROM visit_notes WHERE appointment_id = {visit}"
		) == "1"
		late = _as_role(
			"app_doctor", DOC,
			"INSERT INTO visit_notes (appointment_id, doctor_id, patient_user_id, body) "
			f"SELECT id, doctor_id, patient_user_id, 'late' FROM appointments WHERE id = {visit};",
		)
		assert late.returncode != 0 and "row-level security" in late.stderr
	finally:
		_drop_visit(visit)


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
		assert "Appointment confirmed" in r.text
		assert "Patient" in r.text
		assert "Service duration" in r.text
		assert "patient_required" not in r.text
		assert "patient_not_found" not in r.text
		mine = pat2.get("/my")
		assert "scheduled" in mine.text
		created_ids = set(appointment_ids(mine.text)) - existing_ids
		assert created_ids, "registrar booking not visible in patient's appointments"
		for appointment_id in created_ids:
			pat2.post(f"/appointments/{appointment_id}/cancel")


def test_registrar_patient_directory_search_and_booking_prefill():
	with client() as registrar, client() as patient:
		login(registrar, REG)
		login(patient, PAT)

		directory = registrar.get("/registrar/patients?q=pat@")
		assert directory.status_code == 200
		assert PAT in directory.text
		assert "Future appointments" in directory.text
		assert "password_hash" not in directory.text
		assert "medical records" in directory.text.lower()

		results = registrar.get(
			"/registrar/patients/search", params={"q": "pat@"}
		)
		assert results.status_code == 200
		found = results.json()
		assert len(found) <= 15
		assert any(item["email"] == PAT and item["blocked"] is False for item in found)

		patient_id = psql(f"SELECT id FROM users WHERE email = '{PAT}'")
		booking_start = registrar.get(
			f"/registrar/patients/{patient_id}/book"
		)
		assert "/doctors?patient_email=pat%40clinic.local" in str(booking_start.url)
		doctors_page = booking_start
		doctor_ids = re.findall(
			r'href="/doctors/(\d+)/slots\?patient_email=pat%40clinic\.local"',
			doctors_page.text,
		)
		assert doctor_ids, "selected patient was not carried to the doctor links"
		slots_page = None
		for doctor_id in doctor_ids:
			candidate = registrar.get(
				f"/doctors/{doctor_id}/slots?patient_email=pat%40clinic.local"
			)
			if slot_ids(candidate.text):
				slots_page = candidate
				break
		assert slots_page is not None, "no free slots were available for patient prefill"
		assert 'id="registrar-patient-search"' in slots_page.text
		assert f'value="{PAT}"' in slots_page.text
		assert f'name="patient_email"' in slots_page.text

		denied = patient.get("/registrar/patients/search?q=pat")
		assert denied.status_code == 403


def test_registrar_patient_directory_marks_blocked_accounts():
	with client() as registrar, client() as admin:
		login(registrar, REG)
		login(admin, ADMIN)
		patient_id = int(psql(f"SELECT id FROM users WHERE email = '{PAT2}'"))
		was_blocked = psql(
			f"SELECT blocked FROM users WHERE id = {patient_id}"
		) == "t"
		if not was_blocked:
			admin.post(f"/admin/users/{patient_id}/block")
		try:
			results = registrar.get(
				"/registrar/patients/search", params={"q": "pat2@"}
			)
			assert {"email": PAT2, "blocked": True} in results.json()
			directory = registrar.get("/registrar/patients?q=pat2@")
			assert "Blocked" in directory.text
			assert f"/registrar/patients/{patient_id}/book" not in directory.text
			blocked_booking = registrar.get(
				f"/registrar/patients/{patient_id}/book"
			)
			assert "error=patient_blocked" in str(blocked_booking.url)
		finally:
			if not was_blocked:
				admin.post(f"/admin/users/{patient_id}/unblock")


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
			rf'name="doctor_ids" value="(\d+)"[\s\S]{{0,120}}Anna Ohanyan',
			html,
		)
		assert match, "Anna checkbox missing from slot-generation form"
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
				"/admin/schedule/generate",
				data={
					"doctor_ids": [doctor_id],
					"from_date": selected_day,
					"to_date": selected_day,
				},
			)
			assert "generated=0" in str(generated.url)
			assert "skipped=6" in str(generated.url)
			assert "Created 0 slots, skipped 6." in generated.text

			today = psql("SELECT CURRENT_DATE")
			yesterday = psql("SELECT CURRENT_DATE - 1")
			day_after_tomorrow = psql("SELECT CURRENT_DATE + 2")
			tomorrow = psql("SELECT CURRENT_DATE + 1")
			past = admin.post(
				"/admin/schedule/generate",
				data={
					"doctor_ids": [doctor_id],
					"from_date": yesterday,
					"to_date": today,
				},
			)
			assert "error=range_in_past" in str(past.url)
			assert "cannot start in the past" in past.text

			reversed_range = admin.post(
				"/admin/schedule/generate",
				data={
					"doctor_ids": [doctor_id],
					"from_date": day_after_tomorrow,
					"to_date": tomorrow,
				},
			)
			assert "error=range_order" in str(reversed_range.url)
			assert "End date must not be before start date." in reversed_range.text

			too_long = admin.post(
				"/admin/schedule/generate",
				data={
					"doctor_ids": [doctor_id],
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
		assert unauthorized.status_code == 403


def test_slot_generator_advances_across_nonworking_dates():
	with client() as admin:
		login(admin, ADMIN)
		anna_id = int(psql("SELECT id FROM doctors WHERE full_name = 'Anna Ohanyan'"))
		levon_id = int(psql("SELECT id FROM doctors WHERE full_name = 'Levon Petrosyan'"))
		saturday = psql(
			f"""
			SELECT (CURRENT_DATE + candidate.day_offset)::date
			FROM generate_series(1, 14) AS candidate(day_offset)
			WHERE EXTRACT(ISODOW FROM CURRENT_DATE + candidate.day_offset)::int = 6
			  AND NOT EXISTS (
			        SELECT 1 FROM work_hours w
			        WHERE w.doctor_id = {anna_id} AND w.weekday = 5
			      )
			ORDER BY candidate.day_offset
			LIMIT 1
			"""
		)
		tuesday = psql(
			f"""
			SELECT (CURRENT_DATE + candidate.day_offset)::date
			FROM generate_series(1, 14) AS candidate(day_offset)
			WHERE EXTRACT(ISODOW FROM CURRENT_DATE + candidate.day_offset)::int = 2
			  AND NOT EXISTS (
			        SELECT 1 FROM work_hours w
			        WHERE w.doctor_id = {levon_id} AND w.weekday = 1
			      )
			ORDER BY candidate.day_offset
			LIMIT 1
			"""
		)
		anna_result = admin.post(
			f"/admin/doctors/{anna_id}/generate",
			data={"from_date": saturday, "to_date": saturday},
		)
		levon_result = admin.post(
			"/admin/schedule/generate",
			data={
				"doctor_ids": [str(levon_id)],
				"from_date": tuesday,
				"to_date": tuesday,
			},
		)
		assert "generated=0" in str(anna_result.url)
		assert "skipped=0" in str(anna_result.url)
		assert "generated=0" in str(levon_result.url)
		assert "skipped=0" in str(levon_result.url)


def test_admin_schedule_configuration_is_admin_only_and_repeatable():
	with client() as admin, client() as registrar:
		login(admin, ADMIN)
		login(registrar, REG)
		page = admin.get("/admin/schedule")
		assert page.status_code == 200
		assert 'action="/admin/schedule/generate"' in page.text
		assert 'action="/admin/schedule/apply-hours"' in page.text
		assert 'name="doctor_ids"' in page.text
		assert "Select all" in page.text
		assert "Clear selection" in page.text
		assert "Remove free slots outside working hours for selected doctors" in page.text
		assert "Current hours are not preloaded" in page.text
		assert 'data-weekday-preset="0,1,2,3,4"' in page.text
		assert 'data-weekday-preset="5,6"' in page.text
		assert 'data-weekday-preset="0,1,2,3,4,5,6"' in page.text
		assert "Thanksgiving" in page.text
		assert "Monday" in page.text
		assert 'name="name" type="text" minlength="2" maxlength="100" required' in page.text
		doctor_match = re.search(
			r'name="doctor_ids" value="(\d+)"[^>]*> Anna Ohanyan',
			page.text,
		)
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
			assert unauthorized.status_code == 403

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
				IF rejected_constraint <> 'appointments_no_overlap_per_doctor_reservation' THEN
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
			assert "Past — unavailable" not in booked.text
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
				r'action="/admin/schedule/apply-hours"',
				page.text,
			)
			assert match, "apply-hours form missing"
			doctor_id = re.search(
				r'name="doctor_ids" value="(\d+)"[^>]*> Anna Ohanyan',
				page.text,
			)
			assert doctor_id, "Anna missing from apply-hours form"
			doctor_id = doctor_id.group(1)
			denied = registrar.post(
				"/admin/schedule/apply-hours",
				data={"doctor_ids": doctor_id},
			)
			assert denied.status_code == 403
			applied = admin.post(
				"/admin/schedule/apply-hours",
				data={"doctor_ids": doctor_id},
			)
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
				ON CONFLICT (doctor_id, service_id, starts_at) DO NOTHING
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
			assert mine.status_code == 403
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
	other_doctor_id = psql(
		f"SELECT id FROM doctors WHERE user_id = (SELECT id FROM users WHERE email = '{DOC2}')"
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
			WHERE s.doctor_id IN ({doctor_id}, {other_doctor_id})
			  AND s.starts_at::date = g.day::date
		  )
		  AND NOT EXISTS (
			SELECT 1
			FROM appointments a
			JOIN users u ON u.id = a.patient_user_id
			WHERE u.email = '{PAT2}' AND a.starts_at::date = g.day::date
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
			({doctor_id}, TIMESTAMP '{selected_day} 11:00', TIMESTAMP '{selected_day} 11:30'),
			({other_doctor_id}, TIMESTAMP '{selected_day} 12:00', TIMESTAMP '{selected_day} 12:30');
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
	other_doctor_slot_id = psql(
		f"""
		SELECT id FROM slots
		WHERE doctor_id = {other_doctor_id}
		  AND starts_at = TIMESTAMP '{selected_day} 12:00'
		"""
	)
	psql(
		f"""
		INSERT INTO appointments
			(slot_id, patient_user_id, status, doctor_id, starts_at, ends_at)
		SELECT s.id, u.id, 'scheduled', s.doctor_id, s.starts_at, s.ends_at
		FROM slots s
		JOIN users u ON u.email = '{PAT2}'
		WHERE s.id = {other_doctor_slot_id}
		"""
	)
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
			week_start = date.fromisoformat(selected_day)
			week_start -= timedelta(days=week_start.weekday())
			doctor_week = doctor.get(
				f"/doctor/calendar?view=week&day={selected_day}"
			)
			assert doctor_week.status_code == 200
			assert f"Week of {week_start.isoformat()}" in doctor_week.text
			assert PAT in doctor_week.text
			assert "scheduled" in doctor_week.text
			invalid_calendar = doctor.get(
				"/doctor/calendar?view=invalid&day=not-a-date"
			)
			assert invalid_calendar.status_code == 200
			assert "Invalid date; showing today." in invalid_calendar.text
			assert "Invalid calendar view; showing day view." in invalid_calendar.text
			other_calendar = other_doctor.get(
				f"/doctor/calendar?day={selected_day}"
			)
			assert other_calendar.status_code == 200
			assert PAT not in other_calendar.text

			registrar_day = registrar.get(
				f"/registrar/appointments?day={selected_day}"
			)
			assert registrar_day.status_code == 200
			assert PAT in registrar_day.text
			assert PAT2 in registrar_day.text
			assert "scheduled" in registrar_day.text
			assert "10:00" in registrar_day.text
			assert "12:00" in registrar_day.text
			assert "Clinical note" not in registrar_day.text
			assert "diagnosis" not in registrar_day.text.lower()
			registrar_day_filtered = registrar.get(
				f"/registrar/appointments?day={selected_day}&doctor_id={other_doctor_id}"
			)
			assert PAT2 in registrar_day_filtered.text
			assert PAT not in registrar_day_filtered.text
			registrar_week_without_doctor = registrar.get(
				f"/registrar/appointments?view=week&day={selected_day}"
			)
			assert registrar_week_without_doctor.status_code == 200
			assert f"Week of {week_start.isoformat()}" in registrar_week_without_doctor.text
			assert PAT in registrar_week_without_doctor.text
			assert PAT2 in registrar_week_without_doctor.text
			registrar_week = registrar.get(
				f"/registrar/appointments?view=week&day={selected_day}&doctor_id={doctor_id}"
			)
			assert registrar_week.status_code == 200
			assert f"Week of {week_start.isoformat()}" in registrar_week.text
			assert PAT in registrar_week.text
			assert PAT2 not in registrar_week.text
			registrar_other_doctor_week = registrar.get(
				f"/registrar/appointments?view=week&day={selected_day}&doctor_id={other_doctor_id}"
			)
			assert PAT2 in registrar_other_doctor_week.text
			assert PAT not in registrar_other_doctor_week.text
			invalid_registrar_filter = registrar.get(
				f"/registrar/appointments?day={selected_day}&doctor_id=invalid"
			)
			assert invalid_registrar_filter.status_code == 200
			assert "Invalid doctor; showing all doctors." in invalid_registrar_filter.text

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
			closed_week = doctor.get(
				f"/doctor/calendar?view=week&day={selected_day}"
			)
			assert "doctor time off" in closed_week.text
			assert 'style="background: #ddd; color: #666"' in closed_week.text
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
			WHERE slot_id IN ({slot_id}, {free_slot_id}, {other_doctor_slot_id});
			DELETE FROM slots WHERE id IN ({slot_id}, {free_slot_id}, {other_doctor_slot_id});
			"""
		)


def test_field_limits_reject_invalid_values_and_keep_trimmed_text():
	service_name = f"  Limit {uuid.uuid4().hex[:8]}  "
	stored_name = service_name.strip()
	service_id = None
	old_settings = psql(
		"SELECT address || '|' || phone FROM clinic_settings WHERE id = 1"
	)
	old_address, old_phone = old_settings.split("|", 1)
	try:
		with client() as admin:
			login(admin, ADMIN)
			doctor_id = int(psql("SELECT id FROM doctors LIMIT 1"))
			for payload in (
				{"name": "A", "duration_minutes": "30", "buffer_minutes": "0"},
				{"name": stored_name, "duration_minutes": "4", "buffer_minutes": "0"},
				{"name": stored_name, "duration_minutes": "481", "buffer_minutes": "0"},
				{"name": stored_name, "duration_minutes": "30", "buffer_minutes": "121"},
				{"name": "Bad\nName", "duration_minutes": "30", "buffer_minutes": "0"},
			):
				rejected = admin.post("/admin/services", data=payload)
				assert "error=invalid_service" in str(rejected.url)
			created = admin.post(
				"/admin/services",
				data={
					"name": service_name,
					"duration_minutes": "30",
					"buffer_minutes": "10",
				},
			)
			assert "created=1" in str(created.url)
			service_id = int(
				psql(f"SELECT id FROM services WHERE name = '{stored_name}'")
			)
			experience = admin.post(
				f"/admin/doctors/{doctor_id}",
				data={
					"full_name": "A",
					"specialty": "Therapy",
					"experience_years": "71",
				},
			)
			assert "error=invalid_details" in str(experience.url)
			phone = admin.post(
				"/admin/settings",
				data={"address": "  12 Clinic Street  ", "phone": "call-me"},
			)
			assert "error=invalid_phone" in str(phone.url)
			empty_address = admin.post(
				"/admin/settings",
				data={"address": "   ", "phone": "+374 10 123456"},
			)
			assert "saved=1" in str(empty_address.url)
			assert psql("SELECT address FROM clinic_settings WHERE id = 1") == ""
			assert psql("SELECT phone FROM clinic_settings WHERE id = 1") == "+374 10 123456"
	finally:
		if service_id is not None:
			psql(
				f"""
				DELETE FROM doctor_services WHERE service_id = {service_id};
				DELETE FROM services WHERE id = {service_id};
				"""
			)
		psql(
			"UPDATE clinic_settings "
			f"SET address = '{old_address.replace(chr(39), chr(39)+chr(39))}', "
			f"phone = '{old_phone.replace(chr(39), chr(39)+chr(39))}' "
			"WHERE id = 1"
		)


def test_admin_service_duration_buffer_and_booking_overlap():
	service_name = f"Service test {uuid.uuid4().hex}"
	service_id = None
	with client() as admin, client() as patient:
		login(admin, ADMIN)
		login(patient, PAT)
		doctor_id = int(psql("SELECT id FROM doctors WHERE full_name = 'Anna Ohanyan'"))
		other_doctor_id = int(psql("SELECT id FROM doctors WHERE full_name = 'Levon Petrosyan'"))
		created = admin.post(
			"/admin/services",
			data={
				"name": service_name,
				"duration_minutes": "200",
				"buffer_minutes": "0",
				"doctor_ids": str(doctor_id),
			},
		)
		assert "created=1" in str(created.url)
		service_id = int(psql(f"SELECT id FROM services WHERE name = '{service_name}'"))
		try:
			warning_page = admin.get("/admin/schedule")
			assert service_name in warning_page.text
			assert "do not fit within the doctor's working window" in warning_page.text
			not_assigned = patient.get(
				f"/doctors/{other_doctor_id}/slots?service_id={service_id}"
			)
			assert "not currently available for this doctor" in not_assigned.text
			updated = admin.post(
				f"/admin/services/{service_id}",
				data={
					"name": service_name,
					"duration_minutes": "45",
					"buffer_minutes": "15",
					"doctor_ids": [str(doctor_id), str(other_doctor_id)],
				},
			)
			assert "updated=1" in str(updated.url)
			selected_day = psql(
				f"""
				SELECT (CURRENT_DATE + candidate.day_offset)::date
				FROM generate_series(1, 80) AS candidate(day_offset)
				JOIN work_hours w
				  ON w.doctor_id = {doctor_id}
				 AND w.weekday = EXTRACT(ISODOW FROM CURRENT_DATE + candidate.day_offset)::int - 1
				JOIN work_hours other_w
				  ON other_w.doctor_id = {other_doctor_id}
				 AND other_w.weekday = w.weekday
				 AND other_w.end_time - other_w.start_time >= INTERVAL '60 minutes'
				WHERE NOT EXISTS (
				        SELECT 1 FROM holidays h
				        WHERE h.day = CURRENT_DATE + candidate.day_offset
				      )
				  AND NOT EXISTS (
				        SELECT 1 FROM time_off t
				        WHERE t.doctor_id = {doctor_id}
				          AND CURRENT_DATE + candidate.day_offset BETWEEN t.starts_on AND t.ends_on
				      )
				  AND NOT EXISTS (
				        SELECT 1 FROM time_off t
				        WHERE t.doctor_id = {other_doctor_id}
				          AND CURRENT_DATE + candidate.day_offset BETWEEN t.starts_on AND t.ends_on
				      )
				ORDER BY candidate.day_offset
				LIMIT 1
				"""
			)
			generated = admin.post(
				"/admin/schedule/generate",
				data={
					"doctor_ids": [str(doctor_id), str(other_doctor_id)],
					"from_date": selected_day,
					"to_date": selected_day,
				},
			)
			assert "generated=" in str(generated.url)
			for selected_doctor in (doctor_id, other_doctor_id):
				assert psql(
					f"""
					SELECT count(*) FROM slots
					WHERE doctor_id = {selected_doctor} AND service_id = {service_id}
					  AND starts_at::date = '{selected_day}'
					  AND ends_at - starts_at = INTERVAL '60 minutes'
					"""
				) != "0"
			assert psql(
				f"""
				SELECT count(*) FROM slots
				WHERE doctor_id = {doctor_id} AND service_id = {service_id}
				  AND starts_at::date = '{selected_day}'
				  AND ends_at - starts_at = INTERVAL '60 minutes'
				  AND duration_minutes = 45 AND buffer_minutes = 15
				"""
			) != "0"
			default_service_id = int(
				psql("SELECT id FROM services WHERE name = 'General consultation'")
			)
			new_slot_id, old_slot_id = map(
				int,
				psql(
					f"""
					SELECT new_slot.id, old_slot.id
					FROM slots new_slot
					JOIN slots old_slot
					  ON old_slot.doctor_id = new_slot.doctor_id
					 AND old_slot.service_id = {default_service_id}
					 AND old_slot.starts_at < new_slot.ends_at
					 AND old_slot.ends_at > new_slot.starts_at
					WHERE new_slot.service_id = {service_id}
					  AND new_slot.starts_at::date = '{selected_day}'
					  AND NOT EXISTS (
					        SELECT 1 FROM appointments a
					        WHERE a.doctor_id = new_slot.doctor_id
					          AND a.status = 'scheduled'
					          AND a.starts_at < new_slot.ends_at
					          AND a.reserved_ends_at > new_slot.starts_at
					      )
					ORDER BY new_slot.starts_at
					LIMIT 1
					"""
				).split("|"),
			)
			slots_page = patient.get(
				f"/doctors/{doctor_id}/slots?service_id={service_id}"
			)
			assert service_name in slots_page.text
			assert "45 min + 15 min buffer" in slots_page.text
			before = set(appointment_ids(patient.get("/my").text))
			booked = patient.post(
				f"/slots/{new_slot_id}/book", data={"service_id": str(service_id)}
			)
			assert "My appointments" in booked.text
			assert service_name in patient.get("/my").text
			assert set(appointment_ids(patient.get("/my").text)) - before
			assert psql(
				f"""
				SELECT (EXTRACT(EPOCH FROM (a.ends_at - a.starts_at)) / 60)::int,
				       (EXTRACT(EPOCH FROM (a.reserved_ends_at - a.starts_at)) / 60)::int,
				       s.duration_minutes, s.buffer_minutes
				FROM appointments a JOIN slots s ON s.id = a.slot_id
				WHERE s.id = {new_slot_id}
				"""
			) == "45|60|45|15"
			remove_assignments = admin.post(
				f"/admin/services/{service_id}",
				data={
					"name": service_name,
					"duration_minutes": "45",
					"buffer_minutes": "15",
				},
			)
			assert "error=future_appointments" in str(remove_assignments.url)
			assert "future scheduled appointment(s)" in remove_assignments.text
			assert psql(
				f"SELECT count(*) FROM doctor_services WHERE service_id = {service_id}"
			) == "2"
			admin.post(
				f"/admin/services/{service_id}",
				data={
					"name": service_name,
					"duration_minutes": "25",
					"buffer_minutes": "5",
					"doctor_ids": str(doctor_id),
				},
			)
			assert psql(
				f"""
				SELECT s.duration_minutes, s.buffer_minutes,
				       (EXTRACT(EPOCH FROM (a.ends_at - a.starts_at)) / 60)::int
				FROM slots s JOIN appointments a ON a.slot_id = s.id
				WHERE s.id = {new_slot_id}
				"""
			) == "45|15|45"
			overlap = patient.post(
				f"/slots/{old_slot_id}/book",
				data={"service_id": str(default_service_id)},
			)
			assert "error=unavailable" in str(overlap.url)
			admin.post(f"/admin/services/{service_id}/deactivate")
			inactive_slots = patient.get(
				f"/doctors/{doctor_id}/slots?service_id={service_id}"
			)
			assert "not currently available for this doctor" in inactive_slots.text
			assert service_name in patient.get("/my").text
		finally:
			psql(
				f"""
				DELETE FROM appointments WHERE slot_id IN (
				  SELECT id FROM slots WHERE service_id = {service_id}
				);
				DELETE FROM slots WHERE service_id = {service_id};
				DELETE FROM services WHERE id = {service_id}
				"""
			)


def test_service_buffer_reserves_doctor_not_patient_across_doctors():
	service_name = f"Buffer boundary {uuid.uuid4().hex}"
	service_id = None
	slot_ids_created = []
	with client() as admin, client() as patient:
		login(admin, ADMIN)
		login(patient, PAT)
		doctor_a = int(psql("SELECT id FROM doctors WHERE full_name = 'Anna Ohanyan'"))
		doctor_b = int(psql("SELECT id FROM doctors WHERE full_name = 'Levon Petrosyan'"))
		created = admin.post(
			"/admin/services",
			data={
				"name": service_name,
				"duration_minutes": "30",
				"buffer_minutes": "30",
				"doctor_ids": [str(doctor_a), str(doctor_b)],
			},
		)
		assert "created=1" in str(created.url)
		service_id = int(psql(f"SELECT id FROM services WHERE name = '{service_name}'"))
		try:
			selected_day = psql(
				f"""
				SELECT CURRENT_DATE + candidate.day_offset
				FROM generate_series(100, 300) AS candidate(day_offset)
				WHERE NOT EXISTS (
				        SELECT 1 FROM holidays h
				        WHERE h.day = CURRENT_DATE + candidate.day_offset
				      )
				  AND NOT EXISTS (
				        SELECT 1 FROM time_off t
				        WHERE t.doctor_id IN ({doctor_a}, {doctor_b})
				          AND CURRENT_DATE + candidate.day_offset BETWEEN t.starts_on AND t.ends_on
				      )
				  AND NOT EXISTS (
				        SELECT 1 FROM appointments a
				        WHERE a.patient_user_id = (SELECT id FROM users WHERE email = '{PAT}')
				          AND a.status = 'scheduled'
				          AND a.starts_at < CURRENT_DATE + candidate.day_offset + TIME '11:00'
				          AND a.ends_at > CURRENT_DATE + candidate.day_offset + TIME '10:00'
				      )
				  AND NOT EXISTS (
				        SELECT 1 FROM slots s
				        WHERE (s.doctor_id = {doctor_a} AND s.starts_at = CURRENT_DATE + candidate.day_offset + TIME '10:00')
				           OR (s.doctor_id = {doctor_b} AND s.starts_at = CURRENT_DATE + candidate.day_offset + TIME '10:30')
				      )
				ORDER BY candidate.day_offset
				LIMIT 1
				"""
			)
			slot_ids_created = [
				int(slot_id)
				for slot_id in psql(
					f"""
					WITH inserted_slots AS (
					  INSERT INTO slots (
					  doctor_id, service_id, starts_at, ends_at,
					  duration_minutes, buffer_minutes
					  )
					  VALUES
					  ({doctor_a}, {service_id}, '{selected_day} 10:00', '{selected_day} 11:00', 30, 30),
					  ({doctor_b}, {service_id}, '{selected_day} 10:30', '{selected_day} 11:30', 30, 30)
					  RETURNING id
					)
					SELECT string_agg(id::text, ',') FROM inserted_slots
					"""
				).split(",")
			]
			assert len(slot_ids_created) == 2
			first = patient.post(
				f"/slots/{slot_ids_created[0]}/book",
				data={"service_id": str(service_id)},
			)
			assert "booked=1" in str(first.url)
			second = patient.post(
				f"/slots/{slot_ids_created[1]}/book",
				data={"service_id": str(service_id)},
			)
			assert second.url.path == "/my"
			assert "booked=1" in str(second.url)
			assert psql(
				f"""
				SELECT count(*) FROM appointments a
				WHERE a.slot_id IN ({', '.join(map(str, slot_ids_created))})
				  AND a.status = 'scheduled'
				  AND a.ends_at = a.starts_at + INTERVAL '30 minutes'
				  AND a.reserved_ends_at = a.starts_at + INTERVAL '60 minutes'
				"""
			) == "2"
		finally:
			if slot_ids_created:
				ids = ', '.join(map(str, slot_ids_created))
				psql(
					f"DELETE FROM appointments WHERE slot_id IN ({ids}); "
					f"DELETE FROM slots WHERE id IN ({ids})"
				)
			psql(f"DELETE FROM services WHERE id = {service_id}")

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
		dashboard = guest.get("/me")
		assert "Upcoming visits" in dashboard.text
		assert "General consultation" in dashboard.text
		assert "Change password" in dashboard.text

		wrong_current = guest.post(
			"/me/password",
			data={
				"current_password": "wrong-password",
				"new_password": "Clinic-Patient-Changed-2026!",
				"confirm_password": "Clinic-Patient-Changed-2026!",
			},
		)
		assert "password_error=current" in str(wrong_current.url)
		assert "Current password is incorrect." in wrong_current.text
		changed_password = "Clinic-Patient-Changed-2026!"
		changed = guest.post(
			"/me/password",
			data={
				"current_password": password,
				"new_password": changed_password,
				"confirm_password": changed_password,
			},
		)
		assert "password_changed=1" in str(changed.url)
		assert "Password changed successfully." in changed.text
		guest.get("/logout")
		old_password_login = guest.post(
			"/login", data={"email": email, "password": password}
		)
		assert "Invalid email or password" in old_password_login.text
		new_password_login = guest.post(
			"/login", data={"email": email, "password": changed_password}
		)
		assert "/me" in str(new_password_login.url)

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
			data={"email": email, "password": changed_password},
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


def test_admin_can_create_update_deactivate_and_reactivate_doctor():
	email = f"managed-doctor-{uuid.uuid4().hex}@example.test"
	initial_password = "DoctorInitial#417"
	reset_password = "DoctorReset#583"
	user_id = None
	doctor_id = None
	slot_id = None
	try:
		with client() as admin, client() as patient, client() as doctor:
			login(admin, ADMIN)
			created = admin.post(
				"/admin/doctors",
				data={
					"email": email,
					"full_name": "Dr. Initial Name",
					"specialty": "General Medicine",
					"experience_years": "7",
				},
			)
			assert created.url.path == "/admin/doctors"
			assert "setup link" in created.text
			accept_setup_link(doctor, email, initial_password)
			user_id = int(psql(f"SELECT id FROM users WHERE email = '{email}'"))
			doctor_id = int(psql(f"SELECT id FROM doctors WHERE user_id = {user_id}"))
			assert psql(f"SELECT role FROM users WHERE id = {user_id}") == "doctor"
			assert "Dr. Initial Name" in admin.get("/doctors").text
			assert (
				f'action="/admin/users/{user_id}/password"'
				not in admin.get("/admin/doctors").text
			)

			updated = admin.post(
				f"/admin/doctors/{doctor_id}",
				data={
					"full_name": "Dr. Updated Name",
					"specialty": "Cardiology",
					"experience_years": "9",
				},
			)
			assert "Doctor details updated." in updated.text
			assert psql(
				f"SELECT full_name || '|' || specialty || '|' || experience_years "
				f"FROM doctors WHERE id = {doctor_id}"
			) == "Dr. Updated Name|Cardiology|9"

			reset = admin.post(
				f"/admin/users/{user_id}/password",
				data={
					"new_password": reset_password,
					"confirm_password": reset_password,
				},
			)
			assert "password_reset_not_allowed" in str(reset.url)
			assert "cannot be set from this page" in reset.text
			linked = admin.post(
				f"/admin/users/{user_id}/reset-link",
				data={"next_page": "doctors"},
			)
			assert "Reset link sent." in linked.text
			assert "new_password" not in linked.text
			assert latest_reset_token(email)
			psql(
				"UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP "
				"WHERE used_at IS NULL"
			)
			denied_doctor_login = doctor.post(
				"/login", data={"email": email, "password": reset_password}
			)
			assert "Invalid email or password" in denied_doctor_login.text
			doctor_login = doctor.post(
				"/login", data={"email": email, "password": initial_password}
			)
			assert "Role: doctor" in doctor_login.text
			changed_doctor_password = "DoctorSelfChanged#902"
			changed = doctor.post(
				"/me/password",
				data={
					"current_password": initial_password,
					"new_password": changed_doctor_password,
					"confirm_password": changed_doctor_password,
				},
			)
			assert "password_changed=1" in str(changed.url)
			assert "Change password" in doctor.get("/me").text
			logout(doctor)
			assert "Invalid email or password" in doctor.post(
				"/login",
				data={"email": email, "password": initial_password},
			).text
			assert "Role: doctor" in doctor.post(
				"/login",
				data={"email": email, "password": changed_doctor_password},
			).text
			restored = doctor.post(
				"/me/password",
				data={
					"current_password": changed_doctor_password,
					"new_password": initial_password,
					"confirm_password": initial_password,
				},
			)
			assert "password_changed=1" in str(restored.url)

			slot_id = int(
				psql(
					f"""
					INSERT INTO slots (doctor_id, starts_at, ends_at)
					VALUES (
						{doctor_id},
						CURRENT_TIMESTAMP + INTERVAL '100 days',
						CURRENT_TIMESTAMP + INTERVAL '100 days 30 minutes'
					)
					RETURNING id
					"""
				)
			)
			psql(
				f"""
				INSERT INTO appointments (
					slot_id, patient_user_id, status, doctor_id, starts_at, ends_at
				)
				SELECT s.id, u.id, 'scheduled', s.doctor_id, s.starts_at,
				       s.starts_at + make_interval(mins => s.duration_minutes)
				FROM slots s
				JOIN users u ON u.email = '{PAT}'
				WHERE s.id = {slot_id}
				"""
			)
			deactivated = admin.post(f"/admin/doctors/{doctor_id}/deactivate")
			assert "1 future scheduled appointment(s) remain" in deactivated.text
			assert psql(
				f"SELECT status FROM appointments WHERE slot_id = {slot_id}"
			) == "scheduled"
			assert "Inactive" in admin.get("/admin/doctors").text
			assert "Dr. Updated Name" not in admin.get("/doctors").text
			blocked_doctor = doctor.get("/me")
			assert blocked_doctor.status_code == 403
			assert "Account is blocked" in blocked_doctor.text

			login(patient, PAT)
			patient_id = int(psql(f"SELECT id FROM users WHERE email = '{PAT}'"))
			assert psql(
				f"""
				BEGIN;
				SET LOCAL ROLE app_patient;
				SELECT set_config('app.user_id', '{patient_id}', true) IS NOT NULL;
				SELECT CASE WHEN public.is_valid_free_slot(
					{slot_id},
					{doctor_id},
					(SELECT starts_at FROM slots WHERE id = {slot_id}),
					(SELECT starts_at + make_interval(mins => duration_minutes)
					 FROM slots WHERE id = {slot_id}),
					(SELECT ends_at FROM slots WHERE id = {slot_id})
				) THEN 'allowed' ELSE 'denied' END;
				"""
			) == "denied"
			patient.post(f"/slots/{slot_id}/book")
			assert psql(
				f"SELECT count(*) FROM appointments WHERE slot_id = {slot_id}"
			) == "1"

			reactivated = admin.post(f"/admin/doctors/{doctor_id}/activate")
			assert "Doctor reactivated." in reactivated.text
			assert "Dr. Updated Name" in admin.get("/doctors").text
			doctor_login = doctor.post(
				"/login", data={"email": email, "password": initial_password}
			)
			assert "Role: doctor" in doctor_login.text
	finally:
		if doctor_id is not None:
			psql(
				f"""
				DELETE FROM audit_events
				WHERE target_type = 'doctor'
				  AND target_id IN ({doctor_id}, COALESCE({user_id}, 0));
				DELETE FROM appointments
				WHERE slot_id IN (SELECT id FROM slots WHERE doctor_id = {doctor_id});
				DELETE FROM slots WHERE doctor_id = {doctor_id};
				DELETE FROM doctors WHERE id = {doctor_id};
				"""
			)
		if user_id is not None:
			psql(
				f"""
				DELETE FROM audit_events
				WHERE actor_user_id = {user_id}
				   OR (target_id = {user_id} AND target_type IN ('doctor', 'user'));
				DELETE FROM users WHERE id = {user_id};
				"""
			)


def test_admin_can_create_staff_and_reset_password():
	email = f"managed-registrar-{uuid.uuid4().hex}@example.test"
	admin_email = f"managed-admin-{uuid.uuid4().hex}@example.test"
	initial_password = "RegistrarInitial#417"
	reset_password = "RegistrarReset#583"
	user_id = None
	other_admin_id = None
	try:
		with (
			client() as admin,
			client() as registrar,
			client() as other_registrar,
			client() as managed_admin,
			client() as stale_admin,
		):
			login(admin, ADMIN)
			invalid_role = admin.post(
				"/admin/users",
				data={
					"email": email,
					"role": "patient",
					"password": initial_password,
					"confirm_password": initial_password,
				},
			)
			assert "Choose registrar or admin." in invalid_role.text
			missing_password = admin.post(
				"/admin/users",
				data={"email": admin_email, "role": "admin"},
			)
			assert "password_required" in str(missing_password.url)
			assert "No account was created and no email was sent." in missing_password.text
			assert "Staff account created." not in missing_password.text
			wrong_password = admin.post(
				"/admin/users",
				data={
					"email": admin_email,
					"role": "admin",
					"current_password": "not-the-admin-password",
				},
			)
			assert "password_denied" in str(wrong_password.url)
			assert "Current password is incorrect." in wrong_password.text
			assert "Nothing was created and no email was sent." in wrong_password.text
			assert "Staff account created." not in wrong_password.text
			assert psql(
				f"SELECT count(*) FROM users WHERE email = '{admin_email}'"
			) == "0"
			assert psql(
				"SELECT count(*) FROM audit_events "
				"WHERE action = 'admin.create_denied' AND actor_role = 'admin'"
			) != "0"
			created_admin = admin.post(
				"/admin/users",
				data={
					"email": admin_email,
					"role": "admin",
					"current_password": PASSWORD,
				},
			)
			assert "Staff account created." in created_admin.text
			assert psql(
				"SELECT actor_user_id::text || ' ' || action "
				"FROM audit_events "
				f"WHERE action = 'admin.create' AND target_id = ("
				f"SELECT id FROM users WHERE email = '{admin_email}')"
			) == psql(
				f"SELECT id::text FROM users WHERE email = '{ADMIN}'"
			) + " admin.create"
			accept_setup_link(managed_admin, admin_email, initial_password)
			other_admin_id = int(
				psql(f"SELECT id FROM users WHERE email = '{admin_email}'")
			)
			staff_page = admin.get("/admin/users")
			assert "new_password" not in staff_page.text
			assert (
				f'action="/admin/users/{other_admin_id}/reset-link"'
				in staff_page.text
			)
			assert f'action="/admin/users/{other_admin_id}/password"' not in staff_page.text
			managed_admin_login = managed_admin.post(
				"/login",
				data={"email": admin_email, "password": initial_password},
			)
			assert "Role: admin" in managed_admin_login.text
			stale_admin.post(
				"/login",
				data={"email": admin_email, "password": initial_password},
			)
			changed_admin_password = "AdminSelfChanged#781"
			changed_admin = managed_admin.post(
				"/me/password",
				data={
					"current_password": initial_password,
					"new_password": changed_admin_password,
					"confirm_password": changed_admin_password,
				},
			)
			assert "password_changed=1" in str(changed_admin.url)
			assert stale_admin.get("/me").url.path == "/login"
			logout(managed_admin)
			assert "Invalid email or password" in managed_admin.post(
				"/login",
				data={"email": admin_email, "password": initial_password},
			).text
			assert "Role: admin" in managed_admin.post(
				"/login",
				data={"email": admin_email, "password": changed_admin_password},
			).text
			restored_admin_password = managed_admin.post(
				"/me/password",
				data={
					"current_password": changed_admin_password,
					"new_password": initial_password,
					"confirm_password": initial_password,
				},
			)
			assert "password_changed=1" in str(restored_admin_password.url)

			own_admin_id = int(
				psql(f"SELECT id FROM users WHERE email = '{ADMIN}'")
			)
			self_block = admin.post(f"/admin/users/{own_admin_id}/block")
			assert "error=self_block" in str(self_block.url)
			assert psql(
				f"SELECT blocked FROM users WHERE id = {own_admin_id}"
			) == "f"
			admin.post(f"/admin/users/{other_admin_id}/block")
			assert psql(
				f"SELECT blocked FROM users WHERE id = {other_admin_id}"
			) == "t"
			assert managed_admin.get("/me").status_code == 403
			admin.post(f"/admin/users/{other_admin_id}/unblock")
			assert "Role: admin" in managed_admin.post(
				"/login",
				data={"email": admin_email, "password": initial_password},
			).text
			own_admin_id = int(psql(f"SELECT id FROM users WHERE email = '{ADMIN}'"))
			denied_self_reset = admin.post(
				f"/admin/users/{own_admin_id}/password",
				data={
					"new_password": reset_password,
					"confirm_password": reset_password,
				},
			)
			assert "password_reset_not_allowed" in str(denied_self_reset.url)
			denied_self_link = admin.post(f"/admin/users/{own_admin_id}/reset-link")
			assert "password_link_self" in str(denied_self_link.url)
			direct_reset = admin.post(
				f"/admin/users/{other_admin_id}/password",
				data={
					"new_password": reset_password,
					"confirm_password": reset_password,
				},
			)
			assert "password_reset_not_allowed" in str(direct_reset.url)
			admin_reset = admin.post(f"/admin/users/{other_admin_id}/reset-link")
			assert "Reset link sent." in admin_reset.text
			assert "new_password" not in admin_reset.text
			logout(registrar)
			consumed_admin_link = registrar.post(
				"/reset-password",
				data={
					"token": latest_reset_token(admin_email),
					"new_password": reset_password,
					"confirm_password": reset_password,
				},
			)
			assert "Password updated." in consumed_admin_link.text
			assert managed_admin.get("/me").url.path == "/login"
			assert "Invalid email or password" in managed_admin.post(
				"/login",
				data={"email": admin_email, "password": initial_password},
			).text
			assert "Role: admin" in managed_admin.post(
				"/login",
				data={"email": admin_email, "password": reset_password},
			).text

			created = admin.post(
				"/admin/users",
				data={
					"email": email,
					"role": "registrar",
					"password": initial_password,
					"confirm_password": initial_password,
				},
			)
			assert "Staff account created." in created.text
			accept_setup_link(other_registrar, email, initial_password)
			user_id = int(psql(f"SELECT id FROM users WHERE email = '{email}'"))
			assert psql(f"SELECT role FROM users WHERE id = {user_id}") == "registrar"
			for registrar_client in (registrar, other_registrar):
				initial_login = registrar_client.post(
					"/login",
					data={"email": email, "password": initial_password},
				)
				assert "Role: registrar" in initial_login.text
			reset = admin.post(f"/admin/users/{user_id}/reset-link")
			assert "Reset link sent." in reset.text
			logout(other_registrar)
			consumed_registrar_link = other_registrar.post(
				"/reset-password",
				data={
					"token": latest_reset_token(email),
					"new_password": reset_password,
					"confirm_password": reset_password,
				},
			)
			assert "Password updated." in consumed_registrar_link.text
			for registrar_client in (registrar, other_registrar):
				stale_session = registrar_client.get("/me")
				assert stale_session.url.path == "/login"
			old_password_login = registrar.post(
				"/login", data={"email": email, "password": initial_password}
			)
			assert "Invalid email or password" in old_password_login.text
			registrar_login = registrar.post(
				"/login", data={"email": email, "password": reset_password}
			)
			assert "Role: registrar" in registrar_login.text
			stale_registrar_login = other_registrar.post(
				"/login",
				data={"email": email, "password": reset_password},
			)
			assert "Role: registrar" in stale_registrar_login.text
			changed_registrar_password = "RegistrarSelfChanged#644"
			changed_registrar = registrar.post(
				"/me/password",
				data={
					"current_password": reset_password,
					"new_password": changed_registrar_password,
					"confirm_password": changed_registrar_password,
				},
			)
			assert "password_changed=1" in str(changed_registrar.url)
			assert other_registrar.get("/me").url.path == "/login"
			logout(registrar)
			assert "Invalid email or password" in registrar.post(
				"/login",
				data={"email": email, "password": reset_password},
			).text
			assert "Role: registrar" in registrar.post(
				"/login",
				data={"email": email, "password": changed_registrar_password},
			).text
	finally:
		target_ids = [target_id for target_id in (user_id, other_admin_id) if target_id]
		if target_ids:
			ids_csv = ", ".join(str(target_id) for target_id in target_ids)
			psql(
				f"""
				DELETE FROM audit_events
				WHERE target_id IN ({ids_csv});
				DELETE FROM users WHERE id IN ({ids_csv});
				"""
			)


def test_admin_clinic_settings_are_visible_and_admin_only():
	old_settings = psql(
		"SELECT address || '|' || phone FROM clinic_settings WHERE id = 1"
	)
	old_address, old_phone = old_settings.split("|", 1)
	try:
		with client() as admin, client() as doctor, client() as guest:
			login(admin, ADMIN)
			saved = admin.post(
				"/admin/settings",
				data={"address": "42 Test Street", "phone": "+374 00 123456"},
			)
			assert "Clinic settings saved." in saved.text
			home = guest.get("/")
			assert "42 Test Street" in home.text
			assert "+374 00 123456" in home.text

			login(doctor, DOC)
			forbidden = doctor.get("/admin/settings")
			assert forbidden.status_code == 403

	finally:
		psql(
			"UPDATE clinic_settings "
			"SET address = "
			+ "'" + old_address.replace("'", "''") + "', phone = '"
			+ old_phone.replace("'", "''")
			+ "' WHERE id = 1"
		)


def test_cancel_requires_csrf_token():
	with client() as pat:
		login(pat, PAT)
		_, slot_id = open_free_slot_page(pat)
		existing_ids = set(appointment_ids(pat.get("/my").text))
		pat.post(f"/slots/{slot_id}/book")
		mine = pat.get("/my")
		new_ids = set(appointment_ids(mine.text)) - existing_ids
		assert new_ids
		appointment_id = new_ids.pop()

		missing = pat.post(f"/appointments/{appointment_id}/cancel", data={}, csrf=False)
		assert missing.status_code == 403
		wrong = pat.post(
			f"/appointments/{appointment_id}/cancel",
			data={"csrf_token": "wrong-token"},
			csrf=False,
		)
		assert wrong.status_code == 403
		assert appointment_id in appointment_ids(pat.get("/my").text)

		form = re.search(
			rf'action="/appointments/{appointment_id}/cancel".*?name="csrf_token" value="([^"]+)"',
			pat.get("/my").text,
			re.S,
		)
		assert form, "cancel form has no CSRF token"
		cancelled = pat.post(
			f"/appointments/{appointment_id}/cancel",
			data={"csrf_token": form.group(1)},
			csrf=False,
		)
		assert cancelled.status_code == 200
		assert appointment_id not in appointment_ids(pat.get("/my").text)


def test_doctor_calendar_shows_cancelled_visit_and_slot_stays_bookable():
	with client() as pat, client() as pat2, client() as doctor:
		login(pat, PAT)
		login(pat2, PAT2)
		login(doctor, DOC)
		appointment_id = _book_for_patient(pat, DOC)
		slot_id, day, start = psql(
			f"SELECT slot_id, starts_at::date, to_char(starts_at, 'HH24:MI') "
			f"FROM appointments WHERE id = {appointment_id}"
		).split("|")
		pat.post(f"/appointments/{appointment_id}/cancel")
		assert _status(appointment_id) == "cancelled"

		calendar = doctor.get(f"/doctor/calendar?day={day}").text
		assert re.search(
			rf'<li style="color: gray">\s*{start}[\s\S]*?{re.escape(PAT)} — cancelled',
			calendar,
		)
		assert re.search(rf"<li>\s*{start}[\s\S]*?Available", calendar)

		existing_ids = set(appointment_ids(pat2.get("/my").text))
		pat2.post(f"/slots/{slot_id}/book")
		created = set(appointment_ids(pat2.get("/my").text)) - existing_ids
		assert created, "cancelled slot was not bookable again"
		new_id = created.pop()
		assert psql(f"SELECT slot_id FROM appointments WHERE id = {new_id}") == slot_id
		pat2.post(f"/appointments/{new_id}/cancel")


def test_wrong_role_gets_403_and_guest_goes_to_login():
	with client() as guest:
		page = guest.get("/admin/users")
		assert page.url.path == "/login"
	with client() as pat, client() as doctor, client() as registrar:
		login(pat, PAT)
		login(doctor, DOC)
		login(registrar, REG)
		for c, path in (
			(pat, "/admin/users"),
			(pat, "/doctor/patients"),
			(doctor, "/registrar/patients"),
			(registrar, "/my"),
		):
			denied = c.get(path)
			assert denied.status_code == 403
			assert denied.url.path == path
			assert "Нет доступа" in denied.text
		post = pat.post("/admin/holidays", data={"holiday_day": "2030-01-01", "name": "x"})
		assert post.status_code == 403
		assert "Нет доступа" in post.text


def test_logout_revokes_copied_session_cookie():
	with client() as c:
		login(c, PAT2)
		assert c.get("/my").url.path == "/my"
		copied = dict(c.cookies)
		logout(c)
	with CsrfClient(base_url=BASE, follow_redirects=False, timeout=10.0, cookies=copied) as replay:
		page = replay.get("/my")
		assert page.status_code == 303
		assert page.headers["location"].endswith("/login")


def test_patient_cannot_forge_audit_events():
	for action, target_type, target in (
		("admin.user_delete", "user", "1"),
		("service.delete", "service", "1"),
		("appointment.cancel", "appointment", "(SELECT max(id) FROM appointments WHERE patient_user_id <> current_setting('app.user_id')::int)"),
		("user.email_notifications", "user", "1"),
	):
		forged = _as_role(
			"app_patient", PAT,
			f"SELECT public.record_audit_event('{action}', '{target_type}', {target});",
		)
		assert forged.returncode != 0, (action, forged.stdout)
		assert "not allowed" in forged.stderr or "permission denied" in forged.stderr
	direct = _as_role(
		"app_patient", PAT,
		"INSERT INTO audit_events (actor_user_id, actor_role, action, target_type) "
		"VALUES (1, 'admin', 'x', 'y');",
	)
	assert direct.returncode != 0
	assert "permission denied" in direct.stderr
	own = _as_role(
		"app_patient", PAT,
		"SELECT public.record_audit_event('user.email_notifications', 'user', "
		"current_setting('app.user_id')::int);",
	)
	assert own.returncode == 0, own.stderr


def test_cancelled_only_patient_is_not_own_patient_of_doctor():
	email = f"cancelled-only-{uuid.uuid4().hex[:10]}@example.test"
	psql(
		"INSERT INTO users (email, password_hash, role, blocked) "
		f"VALUES ('{email}', (SELECT password_hash FROM users WHERE email = '{PAT}'), 'patient', false)"
	)
	patient_id = int(psql(f"SELECT id FROM users WHERE email = '{email}'"))
	visit = _past_visit(DOC, patient_email=email, status="cancelled")
	try:
		listed = _as_role("app_doctor", DOC, f"SELECT count(*) FROM public.doctor_patients(current_setting('app.user_id')::int) WHERE id = {patient_id};")
		assert listed.returncode == 0, listed.stderr
		assert listed.stdout.split()[-2] == "0", listed.stdout
		with client() as doctor:
			login(doctor, DOC)
			assert email not in doctor.get("/doctor/patients").text
			page = doctor.get(f"/doctor/patients/{patient_id}")
			assert "patient_unavailable" in str(page.url)
		psql(f"UPDATE appointments SET status = 'completed' WHERE id = {visit}")
		listed = _as_role("app_doctor", DOC, f"SELECT count(*) FROM public.doctor_patients(current_setting('app.user_id')::int) WHERE id = {patient_id};")
		assert listed.stdout.split()[-2] == "1", listed.stdout
	finally:
		_drop_visit(visit)
		psql(f"DELETE FROM users WHERE id = {patient_id}")


def test_admin_cannot_cancel_started_visit():
	visit = _past_visit(DOC, patient_email=PAT2)
	try:
		with client() as admin:
			login(admin, ADMIN)
			admin.post(f"/appointments/{visit}/cancel")
			assert _status(visit) == "scheduled"
			admin.post(f"/admin/users/{psql(f'SELECT id FROM users WHERE email = {chr(39)}{PAT2}{chr(39)}')}/cancel-future-appointments")
			assert _status(visit) == "scheduled"
		direct = _as_role(
			"app_admin", ADMIN,
			f"UPDATE appointments SET status = 'cancelled' WHERE id = {visit};",
		)
		assert direct.returncode == 0, direct.stderr
		assert "UPDATE 0" in direct.stdout
		assert _status(visit) == "scheduled"
	finally:
		_drop_visit(visit)


def test_unicode_digits_in_ids_are_rejected_without_500():
	with client() as doctor, client() as admin:
		login(doctor, DOC)
		login(admin, ADMIN)
		for c, method, path in (
			(doctor, "post", "/doctor/appointments/²/complete"),
			(doctor, "get", "/doctor/appointments/²/records"),
			(doctor, "get", "/doctor/patients/٣"),
			(admin, "get", "/doctors/²/slots"),
			(admin, "post", "/admin/users/²/block"),
			(admin, "post", "/admin/services/¹/deactivate"),
		):
			response = getattr(c, method)(path)
			assert response.status_code < 500, (path, response.status_code)
		admin.post("/admin/users/ ² /block")
		padded = admin.get("/doctors/ 1 /slots")
		assert padded.status_code == 200


def test_calendar_day_outside_supported_years_shows_error():
	with client() as doctor, client() as registrar:
		login(doctor, DOC)
		login(registrar, REG)
		for c, path in ((doctor, "/doctor/calendar"), (registrar, "/registrar/appointments")):
			for day in ("0001-01-01", "9999-12-31", "1899-12-31", "2101-01-01"):
				for view in ("day", "week"):
					page = c.get(path, params={"day": day, "view": view})
					assert page.status_code == 200, (path, day, view, page.status_code)
					assert "between years 1900 and 2100" in page.text
			edge = c.get(path, params={"day": "2100-12-31"})
			assert edge.status_code == 200
			assert "between years 1900 and 2100" not in edge.text


def test_slot_generation_respects_max_future_days():
	far = date.today() + timedelta(days=366 * 2 + 10)
	before = psql(f"SELECT count(*) FROM slots WHERE starts_at::date >= '{far.isoformat()}'")
	with client() as admin:
		login(admin, ADMIN)
		page = admin.post(
			"/admin/schedule/generate",
			data={"doctor_ids": ["1"], "from_date": far.isoformat(), "to_date": (far + timedelta(days=3)).isoformat()},
		)
		assert "error=range_too_far" in str(page.url)
		assert "more than two years ahead" in page.text
	assert psql(f"SELECT count(*) FROM slots WHERE starts_at::date >= '{far.isoformat()}'") == before
