"""AUDIT_ROLES_2 fixes: neutral answer for a blocked account at sign-in,
patient name and phone (patient_profiles), email confirmation before sign-in."""
import json
import os
import re
import subprocess
import uuid
from pathlib import Path

import httpx

from tests.clinical_notes import cleanup_cross_doctor_notes, insert_cross_doctor_notes
from tests.csrf_client import CsrfClient
from tests.demo_secret import demo_password
from tests.registration import (
    MAILPIT,
    confirm_registration,
    latest_verification_token,
    register_patient,
    registration_form,
    registration_limit_reset,  # noqa: F401 (autouse)
    verification_messages,
)

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
        f"DELETE FROM email_verification_attempts WHERE email_fingerprint = public.digest('{email}', 'sha256'); "
        f"DELETE FROM password_reset_attempts WHERE email_fingerprint = public.digest('{email}', 'sha256'); "
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


# --- R2-A-reg-no-email-confirm -----------------------------------------------

CONFIRM_FIRST = "Please confirm your email before signing in."
RESENT = "If this email belongs to an unconfirmed account, we sent a new link."
NEUTRAL_INVALID = "This confirmation link is invalid or already used. If you already confirmed your email, sign in."
REG_PASSWORD = "Confirm-Check-2026!"


def _verified_at(email: str) -> str:
    return _psql(f"SELECT coalesce(email_verified_at::text, 'NULL') FROM users WHERE email = '{email}'")[0]


def _reset_messages(address: str) -> list[dict]:
    response = httpx.get(
        f"{MAILPIT}/api/v1/search",
        params={"query": f'to:"{address}" subject:"Reset your clinic password"'},
        timeout=5,
    )
    response.raise_for_status()
    return response.json().get("messages") or []


def _latest_reset_token(address: str) -> str:
    messages = _reset_messages(address)
    assert messages, "reset email was not delivered"
    message_id = messages[0].get("ID") or messages[0].get("Id")
    body = httpx.get(f"{MAILPIT}/api/v1/message/{message_id}", timeout=5).json().get("Text") or ""
    match = re.search(r"reset-password\?token=([0-9a-f]{64})", body)
    assert match, "reset link missing"
    return match.group(1)


def _in_api(script: str) -> dict:
    completed = subprocess.run(
        ["docker", "compose", "exec", "-T", "api", "python", "-"],
        input=script, cwd=ROOT, capture_output=True, text=True,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    return json.loads(completed.stdout.strip().splitlines()[-1])


def test_email_column_has_no_default_and_restart_keeps_pending_unconfirmed():
    assert _psql(
        "SELECT coalesce(column_default, 'none'), is_nullable FROM information_schema.columns "
        "WHERE table_name = 'users' AND column_name = 'email_verified_at'"
    ) == ["none|YES"]
    email = f"restart-{uuid.uuid4().hex}@example.com"
    try:
        with _client() as guest:
            register_patient(guest, email, REG_PASSWORD, confirm=False)
        assert _verified_at(email) == "NULL"
        rerun = subprocess.run(
            ["docker", "compose", "exec", "-T", "db", "psql", "-X", "-q", "-U", "clinic", "-d", "clinic",
             "-v", "ON_ERROR_STOP=1", "-f", "/docker-entrypoint-initdb.d/init.sql"],
            cwd=ROOT, capture_output=True, text=True,
        )
        assert rerun.returncode == 0, rerun.stderr[-2000:]
        assert _verified_at(email) == "NULL"
        for demo in (ADMIN, DOC, REG, PAT, PAT2):
            assert _verified_at(demo) != "NULL", demo
    finally:
        _delete_user(email)


def test_registration_mails_once_and_sign_in_waits_for_confirmation():
    stamp = uuid.uuid4().hex[:10]
    email = f"confirm-{stamp}@example.com"
    name = f"Confirm Person {stamp}"
    try:
        with _client() as guest:
            created = register_patient(guest, email, REG_PASSWORD, confirm=False, full_name=name)
            assert "registered=1" in str(created.url)
            assert "sign-in becomes available after confirmation" in created.text
        messages = verification_messages(email)
        assert len(messages) == 1
        assert [to["Address"] for to in messages[0]["To"]] == [email]
        assert name not in messages[0]["Subject"] and name not in json.dumps(messages[0]["To"])
        assert name in messages[0]["Text"]
        user_id = _user_id(email)
        assert _verified_at(email) == "NULL"

        with _client() as c:
            for _ in range(2):
                c.post("/login", data={"email": email, "password": "wrong-password"})
            page = c.post("/login", data={"email": email, "password": REG_PASSWORD})
            assert page.status_code == 403 and CONFIRM_FIRST in page.text
            assert 'action="/resend-verification"' in page.text
            assert c.get("/me").url.path == "/login"
        assert _psql(
            f"SELECT count(*) FROM login_attempts WHERE email_fingerprint = public.digest('{email}', 'sha256')"
        ) == ["0"]
        assert _psql(
            "SELECT reason FROM audit_events WHERE action = 'auth.login.failure' "
            f"AND actor_user_id = {user_id} ORDER BY id DESC LIMIT 1"
        ) == ["unverified"]
        wrong = _client().post("/login", data={"email": email, "password": "wrong-password"})
        assert wrong.status_code == 401 and CONFIRM_FIRST not in wrong.text

        token = latest_verification_token(email)
        with _client() as c:
            form = c.get("/verify-email", params={"token": token})
            assert form.status_code == 200
            assert email not in form.text and "@" not in form.text.split("<main", 1)[-1].split("</main>", 1)[0]
            assert _verified_at(email) == "NULL", "GET must not confirm"
            confirmed = c.post("/verify-email", data={"token": token})
            assert confirmed.url.path == "/login" and "verified=1" in str(confirmed.url)
            assert "Email confirmed." in confirmed.text
            assert c.get("/me").url.path == "/login", "no automatic sign-in"
            again = c.post("/verify-email", data={"token": token})
            assert again.status_code == 400 and NEUTRAL_INVALID in again.text
            stale_get = c.get("/verify-email", params={"token": token})
            assert stale_get.status_code == 400
        assert _verified_at(email) != "NULL"
        assert _psql(
            f"SELECT count(*) FROM email_verification_tokens WHERE user_id = {user_id} AND used_at IS NULL"
        ) == ["0"]
        with _client() as c:
            _login(c, email, REG_PASSWORD)

        events = _audit_rows_for(user_id, "user.email_verified")
        assert events == [f"{user_id}|patient|user.email_verified|user|{user_id}"]
        journal = "\n".join(_psql(
            "SELECT concat_ws('|', action, target_type, target_id, reason, source, old_value, new_value) "
            f"FROM audit_events WHERE actor_user_id = {user_id} OR target_id = {user_id}"
        ))
        for secret in (token, stamp, "000111", email):
            assert secret not in journal
    finally:
        _delete_user(email)


def test_expired_or_forged_tokens_are_invalid_without_500():
    email = f"expired-{uuid.uuid4().hex}@example.com"
    try:
        with _client() as guest:
            register_patient(guest, email, REG_PASSWORD, confirm=False)
        token = latest_verification_token(email)
        _psql(
            "UPDATE email_verification_tokens SET expires_at = now() - interval '1 minute' "
            f"WHERE user_id = {_user_id(email)}"
        )
        with _client() as c:
            assert c.get("/verify-email", params={"token": token}).status_code == 400
            expired = c.post("/verify-email", data={"token": token})
            assert expired.status_code == 400 and NEUTRAL_INVALID in expired.text
            for forged in ("", "abc", "g" * 64, token.upper(), token[:-1], token + "0", uuid.uuid4().hex * 2):
                got = c.get("/verify-email", params={"token": forged})
                assert got.status_code == 400 and "@" not in got.text.split("<main", 1)[-1].split("</main>", 1)[0]
                posted = c.post("/verify-email", data={"token": forged})
                assert posted.status_code == 400 and NEUTRAL_INVALID in posted.text
        assert _verified_at(email) == "NULL"
    finally:
        _delete_user(email)


def test_resend_answers_the_same_and_mails_only_unconfirmed_patients():
    stamp = uuid.uuid4().hex[:10]
    pending = f"resend-pending-{stamp}@example.com"
    blocked = f"resend-blocked-{stamp}@example.com"
    unknown = f"resend-unknown-{stamp}@example.com"
    try:
        with _client() as guest:
            register_patient(guest, pending, REG_PASSWORD, confirm=False)
            register_patient(guest, blocked, REG_PASSWORD, confirm=False)
        _psql(f"UPDATE users SET blocked = TRUE WHERE email = '{blocked}'")
        old_token = latest_verification_token(pending)
        before = {address: len(verification_messages(address)) for address in (pending, blocked, unknown, PAT)}
        answers = []
        for address in (unknown, PAT, blocked, pending):
            with _client() as c:
                page = c.post("/resend-verification", data={"email": address})
                answers.append((page.status_code, str(page.url).split("?", 1)[-1], RESENT in page.text))
        assert answers == [(200, "resent=1", True)] * 4
        after = {address: len(verification_messages(address)) for address in before}
        assert after[unknown] == before[unknown] == 0
        assert after[PAT] == before[PAT]
        assert after[blocked] == before[blocked]
        assert after[pending] == before[pending] + 1
        new_token = latest_verification_token(pending)
        assert new_token != old_token
        with _client() as c:
            stale = c.post("/verify-email", data={"token": old_token})
            assert stale.status_code == 400
        confirm_registration(pending)
        assert _verified_at(pending) != "NULL"
        assert _verified_at(blocked) == "NULL"
    finally:
        for address in (pending, blocked, unknown, PAT):
            _psql(
                "DELETE FROM email_verification_attempts "
                f"WHERE email_fingerprint = public.digest('{address}', 'sha256')"
            )
        _delete_user(pending)
        _delete_user(blocked)


def test_resend_rate_limits_do_not_reveal_the_address():
    stamp = uuid.uuid4().hex[:10]
    pending = f"limit-pending-{stamp}@example.com"
    unknown = f"limit-unknown-{stamp}@example.com"
    try:
        with _client() as guest:
            register_patient(guest, pending, REG_PASSWORD, confirm=False)
        for address in (pending, unknown):
            with _client() as c:
                for _ in range(7):
                    page = c.post("/resend-verification", data={"email": address})
                    assert page.status_code == 200 and RESENT in page.text
        # one mail at registration plus five accepted resends; the rest is limited
        assert len(verification_messages(pending)) == 6
        assert len(verification_messages(unknown)) == 0
        daily = f"limit-daily-{stamp}@example.com"
        limited = _psql(
            "SELECT string_agg(rate_limited::text, ',' ORDER BY g) FROM generate_series(1, 11) AS g, "
            f"LATERAL public.request_email_verification('{daily}', 'daily-source-' || g)"
        )
        assert limited == [",".join(["false"] * 10 + ["true"])]
        _psql(f"DELETE FROM email_verification_attempts WHERE email_fingerprint = public.digest('{daily}', 'sha256')")
        assert _psql("SELECT count(*) FROM pg_proc WHERE proname = 'request_email_verification' "
                     "AND prosrc LIKE '%password_reset_attempts%'") == ["0"]
    finally:
        _psql(f"DELETE FROM email_verification_attempts WHERE email_fingerprint = public.digest('{unknown}', 'sha256')")
        _delete_user(pending)


def test_smtp_failure_keeps_registration_and_resend_answers_the_same():
    email = f"smtp-down-{uuid.uuid4().hex}@example.com"
    script = f"""
import json
from starlette.requests import Request
import routes_auth

def boom(*args, **kwargs):
    raise OSError("smtp down")

routes_auth.send_email_verification = boom

def request(path):
    return Request({{"type": "http", "method": "POST", "path": path, "headers": [],
                    "query_string": b"", "client": ("10.200.0.9", 4000), "session": {{}},
                    "server": ("test", 80), "scheme": "http"}})

created = routes_auth.register(request("/register"), email={email!r}, password={REG_PASSWORD!r},
                               confirm_password={REG_PASSWORD!r}, full_name="Smtp Down", phone="+374 10 101010")
resent = routes_auth.resend_verification(request("/resend-verification"), email={email!r})
print(json.dumps({{"created": [created.status_code, created.headers["location"]],
                  "resent": [resent.status_code, resent.headers["location"]]}}))
"""
    try:
        result = _in_api(script)
        assert result["created"] == [303, "/login?registered=1&mail=failed"]
        assert result["resent"] == [303, "/login?resent=1"]
        user_id = _user_id(email)
        assert _psql(f"SELECT count(*) FROM patient_profiles WHERE user_id = {user_id}") == ["1"]
        assert _psql(
            f"SELECT count(*) FROM email_verification_tokens WHERE user_id = {user_id} AND used_at IS NULL"
        ) == ["1"]
        with _client() as c:
            page = c.get("/login", params={"registered": "1", "mail": "failed"})
            assert "could not be sent" in page.text and 'action="/resend-verification"' in page.text
    finally:
        _delete_user(email)


def test_password_reset_confirms_email_and_locks_out_the_pre_registrant():
    email = f"prehijack-{uuid.uuid4().hex}@example.com"
    attacker_password = "Attacker-Pass-2026!"
    owner_password = "Owner-Takes-Back-2026!"
    try:
        with _client() as attacker:
            register_patient(attacker, email, attacker_password, confirm=False)
        user_id = _user_id(email)
        version_before = int(_psql(f"SELECT auth_version FROM users WHERE id = {user_id}")[0])
        with _client() as owner:
            sent = owner.post("/forgot-password", data={"email": email})
            assert "sent=1" in str(sent.url)
            assert len(_reset_messages(email)) == 1
            changed = owner.post("/reset-password", data={
                "token": _latest_reset_token(email),
                "new_password": owner_password,
                "confirm_password": owner_password,
            })
            assert "Password updated." in changed.text
        assert _verified_at(email) != "NULL"
        assert int(_psql(f"SELECT auth_version FROM users WHERE id = {user_id}")[0]) == version_before + 1
        with _client() as attacker:
            denied = attacker.post("/login", data={"email": email, "password": attacker_password})
            assert denied.status_code == 401
        with _client() as owner:
            _login(owner, email, owner_password)
        assert _audit_rows_for(user_id, "user.email_verified") == [
            f"{user_id}|patient|user.email_verified|user|{user_id}"
        ]
    finally:
        _delete_user(email)


def test_staff_invite_is_unconfirmed_until_the_setup_link_is_used():
    email = f"invite-{uuid.uuid4().hex}@example.com"
    password = "Invited-Registrar-2026!"
    try:
        with _client() as admin:
            _login(admin, ADMIN)
            created = admin.post("/admin/users", data={"email": email, "role": "registrar"})
            assert "Staff account created." in created.text
        assert _verified_at(email) == "NULL"
        with _client() as staff:
            changed = staff.post("/reset-password", data={
                "token": _latest_reset_token(email),
                "new_password": password,
                "confirm_password": password,
            })
            assert "Password updated." in changed.text
            assert _verified_at(email) != "NULL"
            _login(staff, email, password)
    finally:
        _psql(
            f"DELETE FROM audit_events WHERE actor_user_id = (SELECT id FROM users WHERE email = '{email}') "
            f"OR (target_type IN ('user', 'registrar') AND target_id = (SELECT id FROM users WHERE email = '{email}'))"
        )
        _delete_user(email)


def test_blocked_unconfirmed_account_answers_401_not_403():
    email = f"blocked-pending-{uuid.uuid4().hex}@example.com"
    try:
        with _client() as guest:
            register_patient(guest, email, REG_PASSWORD, confirm=False)
        _psql(f"UPDATE users SET blocked = TRUE WHERE email = '{email}'")
        with _client() as c:
            page = c.post("/login", data={"email": email, "password": REG_PASSWORD})
            assert page.status_code == 401 and INVALID in page.text
            assert CONFIRM_FIRST not in page.text and 'action="/resend-verification"' not in page.text
        token = latest_verification_token(email)
        with _client() as c:
            assert c.post("/verify-email", data={"token": token}).status_code == 400
        assert _verified_at(email) == "NULL"
    finally:
        _delete_user(email)
