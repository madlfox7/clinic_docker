"""AUDIT_ROLES_2 fixes: neutral answer for a blocked account at sign-in,
patient name and phone (patient_profiles)."""
import os
import subprocess
import uuid
from pathlib import Path

from tests.clinical_notes import cleanup_cross_doctor_notes, insert_cross_doctor_notes
from tests.csrf_client import CsrfClient
from tests.demo_secret import demo_password
from tests.registration import registration_form

ROOT = Path(__file__).resolve().parents[1]
BASE = os.environ.get("CLINIC_TEST_BASE", "http://localhost:8080")
PASSWORD = demo_password()
PAT = "pat@clinic.local"
PAT2 = "pat2@clinic.local"
DOC = "doc@clinic.local"
REG = "reg@clinic.local"
ADMIN = "admin@clinic.local"
PAT_NAME, PAT_PHONE = "Narek Hakobyan", "+374 10 123456"
PAT2_NAME, PAT2_PHONE = "Ani Sargsyan", "+374 10 654321"
INVALID = "Invalid email or password"


def _client(**kwargs):
    return CsrfClient(base_url=BASE, follow_redirects=True, timeout=10.0, **kwargs)


def _psql(sql: str) -> list[str]:
    completed = subprocess.run(
        ["docker", "compose", "exec", "-T", "db", "psql", "-X", "-U", "clinic", "-d", "clinic",
         "-v", "ON_ERROR_STOP=1", "-At", "-F", "|", "-c", sql],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    return [line for line in completed.stdout.splitlines() if line.strip()]


def _psql_try(sql: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "exec", "-T", "db", "psql", "-X", "-U", "clinic", "-d", "clinic",
         "-v", "ON_ERROR_STOP=1", "-At", "-F", "|", "-c", sql],
        cwd=ROOT, capture_output=True, text=True,
    )


def _as_role(role: str, user_id: int, sql: str) -> subprocess.CompletedProcess:
    """Run sql inside a rolled-back transaction as an application role."""
    return _psql_try(
        f"BEGIN; SET LOCAL ROLE {role}; "
        f"SELECT set_config('app.user_id', '{user_id}', true); {sql}; ROLLBACK;"
    )


def _user_id(email: str) -> int:
    return int(_psql(f"SELECT id FROM users WHERE email = '{email}'")[0])


def _login(c, email, password=PASSWORD):
    page = c.post("/login", data={"email": email, "password": password})
    assert page.status_code == 200 and page.url.path == "/me", (email, page.status_code)
    return page


def _audit_rows_for(target_id: int, action: str) -> list[str]:
    return _psql(
        "SELECT concat_ws('|', actor_user_id, actor_role, action, target_type, target_id, "
        "reason, source, old_value, new_value) FROM audit_events "
        f"WHERE action = '{action}' AND target_id = {target_id} ORDER BY id"
    )


def _restore_demo_profiles() -> None:
    _psql(
        f"UPDATE patient_profiles SET full_name = '{PAT_NAME}', phone = '{PAT_PHONE}' "
        f"WHERE user_id = (SELECT id FROM users WHERE email = '{PAT}'); "
        f"UPDATE patient_profiles SET full_name = '{PAT2_NAME}', phone = '{PAT2_PHONE}' "
        f"WHERE user_id = (SELECT id FROM users WHERE email = '{PAT2}')"
    )


def _delete_user(email: str) -> None:
    _psql(
        f"DELETE FROM audit_events WHERE actor_user_id = (SELECT id FROM users WHERE email = '{email}') "
        f"OR (target_type IN ('user', 'patient') AND target_id = (SELECT id FROM users WHERE email = '{email}')); "
        f"DELETE FROM login_attempts WHERE email_fingerprint = public.digest('{email}', 'sha256'); "
        f"DELETE FROM users WHERE email = '{email}'"
    )


def _clear_login_attempts(email: str) -> None:
    _psql(f"DELETE FROM login_attempts WHERE email_fingerprint = public.digest('{email}', 'sha256')")


# --- R2-C-enum-blocked-msg ---------------------------------------------------

def test_blocked_account_answers_like_unknown_email():
    unknown = f"nobody-{uuid.uuid4().hex}@example.com"
    _clear_login_attempts(PAT2)
    _psql(f"UPDATE users SET blocked = TRUE WHERE email = '{PAT2}'")
    try:
        with _client() as c:
            blocked = c.post("/login", data={"email": PAT2, "password": PASSWORD})
        with _client() as c:
            missing = c.post("/login", data={"email": unknown, "password": PASSWORD})
        assert blocked.status_code == missing.status_code == 401
        assert INVALID in blocked.text and INVALID in missing.text
        assert "Account is blocked" not in blocked.text
        assert "blocked" not in blocked.text.lower()
    finally:
        _psql(f"UPDATE users SET blocked = FALSE WHERE email = '{PAT2}'")
        _clear_login_attempts(PAT2)
        _clear_login_attempts(unknown)


def test_blocked_right_password_counts_toward_rate_limit():
    _clear_login_attempts(PAT2)
    _psql(f"UPDATE users SET blocked = TRUE WHERE email = '{PAT2}'")
    try:
        with _client() as c:
            for _ in range(5):
                page = c.post("/login", data={"email": PAT2, "password": PASSWORD})
                assert page.status_code == 401 and INVALID in page.text
            sixth = c.post("/login", data={"email": PAT2, "password": PASSWORD})
            assert sixth.status_code == 429
    finally:
        _psql(f"UPDATE users SET blocked = FALSE WHERE email = '{PAT2}'")
        _clear_login_attempts(PAT2)


def test_session_revoked_by_block_still_says_blocked():
    _clear_login_attempts(PAT2)
    with _client() as c:
        page = c.post("/login", data={"email": PAT2, "password": PASSWORD})
        assert page.status_code == 200 and page.url.path == "/me"
        _psql(f"UPDATE users SET blocked = TRUE WHERE email = '{PAT2}'")
        try:
            revoked = c.get("/me")
            assert revoked.status_code == 403
            assert "Account is blocked" in revoked.text
        finally:
            _psql(f"UPDATE users SET blocked = FALSE WHERE email = '{PAT2}'")


# --- R2-A-no-patient-name ----------------------------------------------------

def test_demo_patients_have_their_names():
    for email, name, phone in ((PAT, PAT_NAME, PAT_PHONE), (PAT2, PAT2_NAME, PAT2_PHONE)):
        with _client() as c:
            me = _login(c, email)
            assert name in me.text and phone in me.text and email in me.text


def test_registration_requires_a_valid_name_and_phone():
    email = f"profile-bad-{uuid.uuid4().hex}@example.com"
    password = "Profile-Check-2026!"
    cases = [
        {"full_name": ""},
        {"phone": ""},
        {"full_name": "A"},
        {"full_name": "x" * 101},
        {"full_name": "Bad\x07Name"},
        {"full_name": "Bad\x85Name"},
        {"phone": "abc-def"},
        {"phone": "12-34"},
        {"phone": "1" * 41},
    ]
    with _client() as guest:
        for fields in cases:
            page = guest.post("/register", data=registration_form(email, password, **fields))
            assert page.status_code == 400, fields
        missing = {"email": email, "password": password, "confirm_password": password}
        assert guest.post("/register", data=missing).status_code == 400
    assert _psql(f"SELECT count(*) FROM users WHERE email = '{email}'") == ["0"]


def test_registration_stores_profile_for_registrar_and_journal_has_no_pii():
    stamp = uuid.uuid4().hex[:10]
    email = f"profile-{stamp}@example.com"
    name = f"Profile Person {stamp}"
    phone = "+374 (55) 12-34-56"
    new_phone = "+374 77 000222"
    try:
        with _client() as guest:
            created = guest.post(
                "/register",
                data=registration_form(email, "Profile-Check-2026!", full_name=f"  {name}  ", phone=phone),
            )
            assert "registered=1" in str(created.url)
        patient_id = _user_id(email)
        assert _psql(f"SELECT full_name, phone FROM patient_profiles WHERE user_id = {patient_id}") == [
            f"{name}|{phone}"
        ]
        with _client() as registrar:
            _login(registrar, REG)
            found = registrar.get("/registrar/patients", params={"q": f"person  {stamp.upper()}"})
            assert found.status_code == 200
            assert name in found.text and phone in found.text and email in found.text
            assert f"/registrar/patients/{patient_id}/profile" in found.text
            saved = registrar.post(
                f"/registrar/patients/{patient_id}/profile",
                data={"full_name": name, "phone": new_phone},
            )
            assert saved.status_code == 200 and "Profile saved." in saved.text
            rejected = registrar.post(
                f"/registrar/patients/{patient_id}/profile",
                data={"full_name": name, "phone": "call me"},
            )
            assert rejected.status_code == 400
        assert _psql(f"SELECT phone FROM patient_profiles WHERE user_id = {patient_id}") == [new_phone]
        reg_id = _user_id(REG)
        events = _audit_rows_for(patient_id, "patient.profile.update")
        assert events == [f"{reg_id}|registrar|patient.profile.update|patient|{patient_id}"]
        journal = "\n".join(_psql(
            "SELECT concat_ws('|', action, target_type, target_id, reason, source) FROM audit_events "
            f"WHERE target_id = {patient_id} OR actor_user_id = {patient_id}"
        ))
        assert stamp not in journal and "374" not in journal
    finally:
        _delete_user(email)


def test_patient_edits_own_profile_escaped_and_journaled_without_pii():
    pat2_id = _user_id(PAT2)
    hostile = '<script>alert("x")</script> Ani'
    try:
        with _client() as c:
            _login(c, PAT2)
            saved = c.post("/me/profile", data={"full_name": hostile, "phone": "+374 10 999999"})
            assert saved.status_code == 200 and "Profile saved." in saved.text
            assert hostile not in saved.text
            assert "&lt;script&gt;" in saved.text
            bad = c.post("/me/profile", data={"full_name": hostile, "phone": "nope"})
            assert "profile_error=phone" in str(bad.url)
        with _client() as registrar:
            _login(registrar, REG)
            page = registrar.get("/registrar/patients", params={"q": PAT2})
            assert hostile not in page.text and "&lt;script&gt;" in page.text
        events = _audit_rows_for(pat2_id, "patient.profile.update")
        assert events and events[-1] == f"{pat2_id}|patient|patient.profile.update|patient|{pat2_id}"
        journal = "\n".join(events)
        assert "script" not in journal and "999999" not in journal
    finally:
        _restore_demo_profiles()


def test_doctor_sees_name_and_phone_of_own_patient_only_through_definer():
    cleanup_cross_doctor_notes()
    pat_id, pat2_id, doc_id = _user_id(PAT), _user_id(PAT2), _user_id(DOC)
    try:
        insert_cross_doctor_notes()
        with _client() as doctor:
            _login(doctor, DOC)
            appointments = doctor.get("/doctor/appointments").text
            assert f"{PAT_NAME} — {PAT}" in appointments
            history = doctor.get(f"/doctor/patients/{pat_id}").text
            assert PAT_NAME in history and PAT_PHONE in history
        direct = _as_role("app_doctor", doc_id, "SELECT full_name FROM patient_profiles")
        assert direct.returncode != 0 and "permission denied" in direct.stderr
        stranger = f"profile-nobody-{uuid.uuid4().hex}@example.com"
        with _client() as guest:
            guest.post("/register", data=registration_form(stranger, "Profile-Check-2026!", full_name="Never Seen"))
        try:
            visible = _as_role(
                "app_doctor", doc_id,
                f"SELECT count(*) FROM doctor_visit_patients({doc_id}) WHERE full_name = 'Never Seen'",
            )
            assert visible.returncode == 0 and visible.stdout.splitlines()[-2] == "0"
        finally:
            _delete_user(stranger)
        assert pat2_id != pat_id
    finally:
        cleanup_cross_doctor_notes()


def test_patient_cannot_read_or_change_another_profile():
    pat_id, pat2_id = _user_id(PAT), _user_id(PAT2)
    own = _as_role("app_patient", pat_id, "SELECT string_agg(user_id::text, ',') FROM patient_profiles")
    assert own.returncode == 0 and own.stdout.splitlines()[-2] == str(pat_id)
    other = _as_role(
        "app_patient", pat_id,
        f"UPDATE patient_profiles SET phone = '+374 11 111111' WHERE user_id = {pat2_id}",
    )
    assert other.returncode == 0 and "UPDATE 0" in other.stdout
    for column in ("user_id = user_id", "updated_at = now()"):
        denied = _as_role("app_patient", pat_id, f"UPDATE patient_profiles SET {column}")
        assert denied.returncode != 0 and "permission denied" in denied.stderr
    insert = _as_role(
        "app_patient", pat_id,
        f"INSERT INTO patient_profiles (user_id, full_name, phone) VALUES ({pat_id}, 'X Y', '12345')",
    )
    assert insert.returncode != 0 and "permission denied" in insert.stderr


def test_database_checks_reject_bad_values_from_direct_updates():
    pat2_id, reg_id = _user_id(PAT2), _user_id(REG)
    for value in ("full_name = 'A'", "phone = 'call me'", "full_name = E'Ani\\x01'"):
        result = _as_role(
            "app_registrar", reg_id, f"UPDATE patient_profiles SET {value} WHERE user_id = {pat2_id}"
        )
        assert result.returncode != 0 and "violates check constraint" in result.stderr, value
    staff = _as_role(
        "app_registrar", reg_id,
        f"UPDATE patient_profiles SET phone = '12345' WHERE user_id = {_user_id(DOC)}",
    )
    assert staff.returncode == 0 and "UPDATE 0" in staff.stdout


def test_admin_sees_patient_name_but_not_phone():
    with _client() as admin:
        _login(admin, ADMIN)
        page = admin.get("/admin/users").text
        assert PAT_NAME in page and PAT2_NAME in page
        assert PAT_PHONE not in page and PAT2_PHONE not in page
    admin_id = _user_id(ADMIN)
    phone = _as_role("app_admin", admin_id, "SELECT phone FROM patient_profiles")
    assert phone.returncode != 0 and "permission denied" in phone.stderr
    update = _as_role("app_admin", admin_id, "UPDATE patient_profiles SET full_name = 'X Y'")
    assert update.returncode != 0 and "permission denied" in update.stderr


def test_guest_and_api_roles_have_no_profile_or_user_insert():
    for role in ("app_guest", "clinic_api"):
        result = _as_role(role, 0, "SELECT count(*) FROM patient_profiles")
        assert result.returncode != 0 and "permission denied" in result.stderr, role
    insert = _as_role(
        "app_guest", 0,
        "INSERT INTO users (email, password_hash, role, blocked) "
        "VALUES ('guest-direct@example.com', 'x', 'patient', false)",
    )
    assert insert.returncode != 0 and "permission denied" in insert.stderr
    assert _psql(
        "SELECT count(*) FROM pg_policies WHERE tablename = 'users' AND policyname = 'users_guest_insert'"
    ) == ["0"]
    assert _psql(
        "SELECT relforcerowsecurity FROM pg_class WHERE oid = 'public.patient_profiles'::regclass"
    ) == ["t"]
    definer = _psql(
        "SELECT p.prosecdef, array_to_string(p.proconfig, ',') FROM pg_proc p "
        "WHERE p.proname = 'register_patient'"
    )
    assert definer == ["t|search_path=pg_catalog, public, pg_temp"]
    grantees = _psql(
        "SELECT string_agg(grantee, ',' ORDER BY grantee) FROM information_schema.routine_privileges "
        "WHERE routine_name = 'register_patient' AND privilege_type = 'EXECUTE' AND grantee <> 'clinic'"
    )
    assert grantees == ["app_guest"]
