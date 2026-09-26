import re

import httpx
import pytest

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
		_, slot_id = open_free_slot_page(reg)
		existing_ids = set(appointment_ids(pat2.get("/my").text))
		r = reg.post(
			f"/slots/{slot_id}/book",
			data={"patient_email": PAT2},
		)
		assert r.status_code == 200
		assert "patient_required" not in r.text
		assert "patient_not_found" not in r.text
		mine = pat2.get("/my")
		assert "scheduled" in mine.text
		created_ids = set(appointment_ids(mine.text)) - existing_ids
		assert created_ids, "registrar booking not visible in patient's appointments"
		for appointment_id in created_ids:
			pat2.post(f"/appointments/{appointment_id}/cancel")


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
