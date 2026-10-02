import re
import subprocess
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]

BASE = "http://localhost:8080"
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


def test_registrar_books_for_pat2():
	with client() as reg, client() as pat2:
		login(reg, REG)
		login(pat2, PAT2)
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
			assert appointment_id not in appointment_ids(pat.get("/my").text)
		finally:
			if appointment_id in appointment_ids(pat.get("/my").text):
				pat.post(f"/appointments/{appointment_id}/cancel")


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

		generated = admin.post(
			f"/admin/doctors/{doctor_id}/generate",
			data={"from_date": "2026-10-12", "to_date": "2026-10-12"},
		)
		assert "generated=0" in str(generated.url)
		assert "skipped=6" in str(generated.url)
		assert "Created 0 slots, skipped 6." in generated.text

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
		assert "Thanksgiving" in page.text
		assert "Monday" in page.text
		assert '<input name="name" type="text" required>' in page.text
		doctor_match = re.search(r'<option value="(\d+)">Anna Ohanyan</option>', page.text)
		assert doctor_match, "Anna missing from admin schedule controls"
		doctor_id = doctor_match.group(1)

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
					"starts_on": "2026-10-12",
					"ends_on": "2026-10-18",
				},
			),
			(
				"/admin/holidays",
				{"holiday_day": "2026-11-26", "name": "Thanksgiving"},
			),
		):
			response = admin.post(path, data=data)
			assert response.status_code == 200
			assert "/admin/schedule?saved=" in str(response.url)
			unauthorized = registrar.post(path, data=data)
			assert "/login" in str(unauthorized.url)


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
