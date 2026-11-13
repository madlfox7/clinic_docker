import os
import re
import time
from typing import List
from urllib.parse import urlencode

import psycopg2.errors
from psycopg2.errors import UniqueViolation
from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse





from db import (
    MAX_EMAIL_LENGTH,
    MAX_PASSWORD_LENGTH,
    PG_INT_MAX,
    clean_person_name,
    clean_phone,
    contains_nul,
    db_as_guest,
    db,
    db_as,
    load_session_user,
    log,
    patient_profile_needs_update,
    pwd,
    record_audit_event,
    templates,
    within_length,
)
from client_ip import client_ip
from date_filters import clean_search, escape_like
from mailer import (
    send_account_message,
    send_email_verification,
    send_existing_account_notice,
    send_password_changed,
    send_password_reset,
    smtp_ready,
)

router = APIRouter()

EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)
DEFAULT_REGISTRATION_PASSWORDS = {
    "password",
    "password1",
    "password123",
    "12345678",
    "123456789",
    "qwerty",
    "qwertyui",
    "qwerty123",
    "admin",
    "admin123",
    "adminadmin",
    "letmein",
    "letmein1",
    "welcome1",
    "changeme",
    "passw0rd",
    "11111111",
    "aaaaaaaa",
}
SAME_PASSWORD_ERROR = "Choose a password different from your current one."
EDGE_SPACE_ERROR = "Password must not start or end with a space."
# One answer for every failed sign-in (unknown email, wrong password, blocked
# or unconfirmed account), so the login form does not tell who is registered.
LOGIN_FAILED = "Invalid email or password. If you have just registered, confirm your email first."


def has_edge_space(password: str) -> bool:
    """Reject accidental edge whitespace without changing the password."""
    return isinstance(password, str) and password != password.strip()


def is_weak_password(password: str, email: str | None = None) -> bool:
    """Reject blank, repeated, listed, and email-derived passwords before hashing."""
    if not isinstance(password, str) or contains_nul(password) or has_edge_space(password):
        return True
    if not within_length(password, MAX_PASSWORD_LENGTH) or len(password) < 8:
        return True
    folded = password.casefold()
    if folded in DEFAULT_REGISTRATION_PASSWORDS or len(set(folded)) < 4:
        return True
    if not any(char.isalpha() for char in password) or not any(char.isdigit() for char in password):
        return True
    if email:
        normalized = email.strip().casefold()
        local_part = normalized.split("@", 1)[0]
        if folded == normalized or (local_part and folded == local_part):
            return True
        if len(local_part) >= 3 and local_part in folded:
            return True
    return False


def _login_page(
    request: Request,
    error: str | None,
    status_code: int = 200,
    role: str = "guest",
    email=None,
    registered: bool = False,
    password_reset: bool = False,
    doctor_id: int | None = None,
    expired: bool = False,
    notice: str | None = None,
):
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "request": request,
            "error": error,
            "expired": expired,
            "role": role,
            "email": email,
            "registered": registered,
            "password_reset": password_reset,
            "notice": notice,
            # Only a validated integer ever reaches the form, never the raw value.
            "doctor_id": doctor_id,
        },
        status_code=status_code,
    )


LOGIN_DOCTOR_MAX_DIGITS = 9


def _login_doctor_id(values) -> int | None:
    """Doctor id from the guest "Book" button (?doctor=<id>), or None.

    Exactly one value of 1-9 ASCII digits, positive and inside int4. Anything else,
    including duplicates, is ignored. There is no free-form return URL.
    """
    if len(values) != 1:
        return None
    raw = values[0]
    if (
        not isinstance(raw, str)
        or not 1 <= len(raw) <= LOGIN_DOCTOR_MAX_DIGITS
        or not (raw.isascii() and raw.isdigit())
    ):
        return None
    value = int(raw)
    if not 1 <= value <= PG_INT_MAX:
        return None
    return value


def _patient_landing_page(user_id: int, doctor_id: int | None) -> str:
    """Where a patient lands after login: the chosen doctor's slots if that doctor is active."""
    if doctor_id is None:
        return "/me"
    try:
        conn = db_as({"id": user_id, "role": "patient"})
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT public.doctor_is_active(%s)", (doctor_id,))
                active = bool(cur.fetchone()[0])
            conn.commit()
        finally:
            conn.close()
    except Exception:
        log.exception("could not check the doctor chosen before login")
        return "/me"
    if not active:
        return "/me"
    return f"/doctors/{doctor_id}/slots"


def _register_page(
    request: Request,
    error: str | None = None,
    status_code: int = 200,
    email: str = "",
    full_name: str = "",
    phone: str = "",
):
    return templates.TemplateResponse(
        request,
        "register.html",
        {
            "request": request,
            "role": "guest",
            "error": error,
            "email": email,
            "full_name": full_name,
            "phone": phone,
        },
        status_code=status_code,
    )


def normalize_email_query(value: str) -> str | None:
    """Strip and lowercase a search fragment. Internal spaces are rejected."""
    if not isinstance(value, str) or contains_nul(value):
        return None
    normalized = value.strip().lower()
    if " " in normalized or not within_length(normalized, MAX_EMAIL_LENGTH):
        return None
    return normalized


def _normalize_registration_email(email: str) -> str | None:
    if not isinstance(email, str) or contains_nul(email):
        return None
    normalized = email.strip().lower()
    if (
        not normalized
        or " " in normalized
        or not within_length(normalized, MAX_EMAIL_LENGTH)
        or not EMAIL_PATTERN.fullmatch(normalized)
    ):
        return None
    local, domain = normalized.rsplit("@", 1)
    if (
        len(local) > 64
        or len(domain) > 253
        or local.startswith(".")
        or local.endswith(".")
        or ".." in local
    ):
        return None
    return normalized


def viewer(request: Request):
    """Current user for pages that only display the role. Blocked sessions are logged out."""
    user, status = load_session_user(request)
    if status == "ok":
        return user
    return None


def require_user(request: Request, *roles, login_doctor_id: int | None = None):
    """Load id, role and blocked from users. Cookie role is ignored.

    An expired session goes to /login?expired=1; login_doctor_id (already
    validated) keeps the patient's way back to the selected doctor.
    """
    user, status = load_session_user(request)
    if status == "blocked":
        return None, _login_page(request, "Account is blocked", 403)
    if status == "expired":
        target = "/login?expired=1"
        if login_doctor_id is not None:
            target += f"&doctor={login_doctor_id}"
        return None, RedirectResponse(target, status_code=303)
    if status != "ok":
        return None, RedirectResponse("/login", status_code=303)
    if roles and user["role"] not in roles:
        return None, templates.TemplateResponse(
            request,
            "forbidden.html",
            {"request": request, "role": user["role"]},
            status_code=403,
        )
    return user, None


@router.get("/")
def home(request: Request):
    user = viewer(request)
    conn = db_as_guest()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT address, phone FROM clinic_settings WHERE id = 1")
            settings = cur.fetchone()
    finally:
        conn.close()
    if settings is None:
        raise RuntimeError("Clinic settings row is missing")
    return templates.TemplateResponse(
        request,
        "home.html",
        {
            "request": request,
            "role": user["role"] if user else "guest",
            "clinic_address": settings[0],
            "clinic_phone": settings[1],
        },
    )


@router.get("/login")
def login_form(request: Request):
    user, status = load_session_user(request)
    if status == "blocked":
        return _login_page(request, "Account is blocked", 403)
    if status == "ok":
        return _login_page(request, None, role=user["role"], email=user["email"])
    notice = None
    if request.query_params.get("verified") == "1":
        notice = "verified"
    elif request.query_params.get("resent") == "1":
        notice = "resent"
    elif request.query_params.get("mail") == "failed":
        notice = "mail_failed"
    return _login_page(
        request,
        None,
        registered=request.query_params.get("registered") == "1",
        password_reset=request.query_params.get("reset") == "1",
        doctor_id=_login_doctor_id(request.query_params.getlist("doctor")),
        expired=request.query_params.get("expired") == "1",
        notice=notice,
    )


@router.get("/register")
def register_form(request: Request):
    user, status = load_session_user(request)
    if status == "blocked":
        return _register_page(request, "Account is blocked", 403)
    if status == "ok":
        return RedirectResponse("/me", status_code=303)
    return _register_page(request)


@router.post("/register")
def register(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    full_name: str = Form(""),
    phone: str = Form(""),
):
    user, status = load_session_user(request)
    if status == "blocked":
        return _register_page(request, "Account is blocked", 403)
    if status == "ok":
        return RedirectResponse("/me", status_code=303)

    if contains_nul(email, password, confirm_password, full_name, phone):
        return _register_page(request, "NUL characters are not allowed.", 400)
    normalized_email = _normalize_registration_email(email)
    if normalized_email is None:
        return _register_page(request, "Enter a valid email address.", 400, email)
    clean_name = clean_person_name(full_name)
    if clean_name is None:
        return _register_page(
            request, "Enter your full name (2–100 characters).", 400, normalized_email,
            phone=phone if clean_phone(phone) else "",
        )
    cleaned_phone = clean_phone(phone)
    if cleaned_phone is None:
        return _register_page(
            request,
            "Enter a valid phone number (digits, spaces, + ( ) -, at least 5 digits).",
            400,
            normalized_email,
            clean_name,
        )
    keep = {"full_name": clean_name, "phone": cleaned_phone}
    if has_edge_space(password) or has_edge_space(confirm_password):
        return _register_page(request, EDGE_SPACE_ERROR, 400, normalized_email, **keep)
    if not within_length(password, MAX_PASSWORD_LENGTH) or len(password) < 8:
        return _register_page(
            request,
            "Password must be 8–72 bytes and at least 8 characters.",
            400,
            normalized_email,
            **keep,
        )
    if is_weak_password(password, normalized_email):
        return _register_page(
            request,
            "Choose a non-default password.",
            400,
            normalized_email,
            **keep,
        )
    if password != confirm_password:
        return _register_page(
            request,
            "Passwords do not match.",
            400,
            normalized_email,
            **keep,
        )

    # Rate limit before bcrypt and register_patient, the same for a new and an
    # existing email. A database failure here fails closed (503).
    try:
        conn = db()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT public.note_registration_attempt(%s, %s)",
                    (normalized_email, client_ip(request)),
                )
                limited = cur.fetchone()[0]
            conn.commit()
        finally:
            conn.close()
    except psycopg2.Error:
        log.exception("registration rate limit check failed")
        response = _register_page(
            request, "Registration is temporarily unavailable. Try again later.", 503
        )
        response.headers["Retry-After"] = "60"
        return response
    if limited:
        response = _register_page(
            request, "Too many registration attempts. Try again later.", 429
        )
        response.headers["Retry-After"] = "900"
        return response

    token = None
    conn = db_as_guest()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT status, verification_token
                FROM public.register_patient(%s, %s, %s, %s)
                """,
                (normalized_email, pwd.hash(password), clean_name, cleaned_phone),
            )
            outcome, token = cur.fetchone()
        conn.commit()
    except UniqueViolation:
        conn.rollback()
        outcome = "exists"
    finally:
        conn.close()
    if outcome not in ("created", "exists") or (outcome == "created" and not token):
        return _register_page(
            request, "Check the registration details.", 400, normalized_email, **keep
        )
    # The same answer for a new and an existing email (always a redirect): the owner of an
    # existing account gets a notice instead of a confirmation link. A new
    # account, profile and token stay even if the mail fails.
    try:
        if outcome == "created":
            send_email_verification(normalized_email, clean_name, token)
        else:
            send_existing_account_notice(normalized_email)
    except Exception as exc:
        # One line for both branches, no stack: a traceback would name the
        # mail function (new or taken email), SMTPRecipientsRefused the address.
        log.warning("could not send registration email (%s)", type(exc).__name__)
        return RedirectResponse("/login?registered=1&mail=failed", status_code=303)
    return RedirectResponse("/login?registered=1", status_code=303)


@router.post("/login")
def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    doctor: List[str] = Form(default=[]),
):
    user, status = load_session_user(request)
    if status == "blocked":
        return _login_page(request, "Account is blocked", 403)
    if status == "ok":
        return _login_page(request, None, role=user["role"], email=user["email"])
    doctor_id = _login_doctor_id(doctor)
    if contains_nul(email, password):
        return _login_page(request, "NUL characters are not allowed.", 400, doctor_id=doctor_id)
    normalized_email = _normalize_registration_email(email)
    if (
        normalized_email is None
        or not within_length(password, MAX_PASSWORD_LENGTH)
    ):
        return _login_page(request, LOGIN_FAILED, 401, doctor_id=doctor_id)
    client_source = client_ip(request)
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, email, role, blocked, auth_version, rate_limited
                FROM public.authenticate_user(%s, %s, %s)
                """,
                (normalized_email, password, client_source),
            )
            row = cur.fetchone()
        conn.commit()
    finally:
        conn.close()
    if not row:
        return _login_page(request, LOGIN_FAILED, 401, doctor_id=doctor_id)
    if row[5]:
        response = _login_page(
            request,
            "Too many login attempts. Try again in 15 minutes.",
            429,
            doctor_id=doctor_id,
        )
        response.headers["Retry-After"] = "900"
        return response
    request.session.clear()
    signed_in_at = int(time.time())
    request.session["user_id"] = row[0]
    request.session["auth_version"] = row[4]
    request.session["iat"] = signed_in_at
    request.session["seen"] = signed_in_at
    target = "/me"
    if row[2] == "patient":
        target = _patient_landing_page(row[0], doctor_id)
    return RedirectResponse(target, status_code=303)


RESET_TOKEN_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _verify_email_page(request: Request, token: str, error: bool, status_code: int = 200):
    # The page never shows the email of the account behind the token.
    return templates.TemplateResponse(
        request,
        "verify_email.html",
        {"request": request, "role": "guest", "token": token, "error": error},
        status_code=status_code,
    )


def _verification_token_is_open(token: str) -> bool:
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT public.email_verification_token_status(%s)", (token,))
            return cur.fetchone()[0] == "valid"
    finally:
        conn.close()


@router.get("/verify-email")
def verify_email_form(request: Request, token: str = ""):
    # GET only shows a button: a mail client preview must not burn the token.
    if not RESET_TOKEN_PATTERN.fullmatch(token) or not _verification_token_is_open(token):
        return _verify_email_page(request, "", True, 400)
    return _verify_email_page(request, token, False)


@router.post("/verify-email")
def verify_email(request: Request, token: str = Form("")):
    if contains_nul(token) or not RESET_TOKEN_PATTERN.fullmatch(token):
        return _verify_email_page(request, "", True, 400)
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT public.confirm_email_verification(%s)", (token,))
            status = cur.fetchone()[0]
        conn.commit()
    finally:
        conn.close()
    if status != "verified":
        return _verify_email_page(request, "", True, 400)
    return RedirectResponse("/login?verified=1", status_code=303)


@router.post("/resend-verification")
def resend_verification(request: Request, email: str = Form("")):
    """Always the same answer: unknown, confirmed, blocked, rate-limited and
    SMTP failure all end at /login?resent=1. SMTP errors go only to the log."""
    user, status = load_session_user(request)
    if status == "ok":
        return RedirectResponse("/me", status_code=303)
    if status == "blocked":
        return _login_page(request, "Account is blocked", 403)
    if contains_nul(email) or any(char in email for char in "\r\n"):
        return _login_page(request, "Enter a valid email address.", 400)
    normalized_email = _normalize_registration_email(email)
    if normalized_email is None:
        return _login_page(request, "Enter a valid email address.", 400)
    row = None
    try:
        conn = db()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT verification_token, recipient, recipient_name, rate_limited
                    FROM public.request_email_verification(%s, %s)
                    """,
                    (normalized_email, client_ip(request)),
                )
                row = cur.fetchone()
            conn.commit()
        finally:
            conn.close()
    except Exception:
        log.exception("could not issue an email confirmation link")
    if row and row[0]:
        try:
            send_email_verification(row[1], row[2], row[0])
        except Exception:
            log.exception("could not send email confirmation")
    return RedirectResponse("/login?resent=1", status_code=303)


def _forgot_password_page(
    request: Request,
    error: str | None = None,
    status_code: int = 200,
    sent: bool = False,
):
    return templates.TemplateResponse(
        request,
        "forgot_password.html",
        {
            "request": request,
            "role": "guest",
            "error": error,
            "sent": sent,
        },
        status_code=status_code,
    )


def deliver_password_reset(email: str, token: str) -> bool:
    try:
        send_password_reset(email, token)
        return True
    except Exception:
        log.exception("could not send password reset email")
        try:
            _revoke_reset_token(token)
        except Exception:
            log.exception("could not revoke undelivered password reset token")
        return False


def _revoke_reset_token(token: str) -> None:
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT public.revoke_patient_password_reset(%s)",
                (token,),
            )
        conn.commit()
    finally:
        conn.close()


def _reset_password_page(
    request: Request,
    token: str,
    error: str | None = None,
    status_code: int = 200,
):
    return templates.TemplateResponse(
        request,
        "reset_password.html",
        {
            "request": request,
            "role": "guest",
            "token": token,
            "error": error,
        },
        status_code=status_code,
    )


@router.get("/forgot-password")
def forgot_password_form(request: Request):
    user, status = load_session_user(request)
    if status == "ok":
        return RedirectResponse("/me", status_code=303)
    if status == "blocked":
        return _login_page(request, "Account is blocked", 403)
    return _forgot_password_page(
        request,
        sent=request.query_params.get("sent") == "1",
    )


@router.post("/forgot-password")
def forgot_password(request: Request, email: str = Form(...)):
    user, status = load_session_user(request)
    if status == "ok":
        return RedirectResponse("/me", status_code=303)
    if status == "blocked":
        return _login_page(request, "Account is blocked", 403)
    if contains_nul(email) or any(char in email for char in "\r\n"):
        return _forgot_password_page(request, "NUL characters are not allowed.", 400)
    normalized_email = _normalize_registration_email(email)
    if normalized_email is None:
        return _forgot_password_page(request, "Enter a valid email address.", 400)
    if not smtp_ready():
        return _forgot_password_page(
            request,
            "The reset email could not be sent. Try again later.",
            503,
        )
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT reset_token, rate_limited, outcome
                FROM public.request_password_reset(%s, %s, FALSE)
                """,
                (normalized_email, client_ip(request)),
            )
            row = cur.fetchone()
        conn.commit()
    finally:
        conn.close()
    if row and row[1]:
        response = _forgot_password_page(
            request,
            "Too many password reset attempts. Try again later.",
            429,
        )
        response.headers["Retry-After"] = "900"
        return response
    token = row[0] if row else None
    if token and not deliver_password_reset(normalized_email, token):
        return _forgot_password_page(
            request,
            "The reset email could not be sent. Try again later.",
            503,
        )
    return RedirectResponse("/forgot-password?sent=1", status_code=303)


def _notify_password_changed(email: str) -> None:
    try:
        send_password_changed(email)
    except Exception:
        log.exception("could not send password-changed notice")


def _reset_account_email(token: str) -> str | None:
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT public.password_reset_account_email(%s)",
                (token,),
            )
            return cur.fetchone()[0]
    finally:
        conn.close()


def _reset_token_is_open(token: str) -> bool:
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT public.password_reset_token_status(%s)",
                (token,),
            )
            status = cur.fetchone()[0]
        return status == "valid"
    finally:
        conn.close()


@router.get("/reset-password")
def reset_password_form(request: Request, token: str = ""):
    if not RESET_TOKEN_PATTERN.fullmatch(token) or not _reset_token_is_open(token):
        return _reset_password_page(
            request, "", "This reset link is invalid or has expired.", 400
        )
    return _reset_password_page(request, token)


@router.post("/reset-password")
def reset_password(
    request: Request,
    token: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
):
    if contains_nul(token, new_password, confirm_password):
        return _reset_password_page(request, "", "NUL characters are not allowed.", 400)
    if not RESET_TOKEN_PATTERN.fullmatch(token):
        return _reset_password_page(
            request, "", "This reset link is invalid or has expired.", 400
        )
    if new_password != confirm_password:
        return _reset_password_page(request, token, "Passwords do not match.", 400)
    if has_edge_space(new_password):
        return _reset_password_page(request, token, EDGE_SPACE_ERROR, 400)
    account_email = _reset_account_email(token)
    if (
        not within_length(new_password, MAX_PASSWORD_LENGTH)
        or len(new_password) < 8
        or is_weak_password(new_password, account_email)
    ):
        return _reset_password_page(
            request, token, "Choose a non-default password.", 400
        )
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT result, resulting_auth_version
                FROM public.consume_password_reset(%s, %s, %s)
                """,
                (token, new_password, pwd.hash(new_password)),
            )
            row = cur.fetchone()
        conn.commit()
    finally:
        conn.close()
    if row and row[0] == "weak":
        return _reset_password_page(
            request, token, "Choose a non-default password.", 400
        )
    if row and row[0] == "edge_space":
        return _reset_password_page(request, token, EDGE_SPACE_ERROR, 400)
    if row and row[0] == "same":
        return _reset_password_page(request, token, SAME_PASSWORD_ERROR, 400)
    if row is None or row[0] != "changed":
        return _reset_password_page(
            request, "", "This reset link is invalid or has expired.", 400
        )
    request.session.clear()
    if account_email:
        _notify_password_changed(account_email)
    return RedirectResponse("/login?reset=1", status_code=303)


@router.get("/me")
def me(request: Request):
    user, denied = require_user(request)
    if denied:
        return denied
    upcoming_visits = []
    profile = None
    if user["role"] == "patient":
        conn = db_as(user)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT full_name, phone FROM patient_profiles WHERE user_id = %s",
                    (user["id"],),
                )
                row = cur.fetchone()
                profile = {
                    "full_name": row[0] if row else "",
                    "phone": row[1] if row else "",
                    "needs_update": patient_profile_needs_update(
                        user["id"], row[0] if row else None, row[1] if row else None
                    ),
                }
                cur.execute(
                    """
                    SELECT a.id, d.full_name, svc.name, a.starts_at, a.ends_at
                    FROM appointments a
                    JOIN slots s ON s.id = a.slot_id
                    JOIN doctors d ON d.id = a.doctor_id
                    JOIN services svc ON svc.id = s.service_id
                    WHERE a.patient_user_id = %s
                      AND a.status = 'scheduled'
                      AND a.starts_at > CURRENT_TIMESTAMP
                    ORDER BY a.starts_at
                    LIMIT 3
                    """,
                    (user["id"],),
                )
                upcoming_visits = [
                    {
                        "id": row[0],
                        "doctor_name": row[1],
                        "service_name": row[2],
                        "starts_at": row[3],
                        "ends_at": row[4],
                    }
                    for row in cur.fetchall()
                ]
        finally:
            conn.close()
    email_notifications = True
    conn = db_as(user)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT public.own_email_notifications()")
            row = cur.fetchone()
            email_notifications = bool(row and row[0])
    finally:
        conn.close()
    return templates.TemplateResponse(
        request,
        "me.html",
        {
            "request": request,
            "email": user["email"],
            "role": user["role"],
            "upcoming_visits": upcoming_visits,
            "profile": profile,
            "profile_saved": request.query_params.get("profile_saved"),
            "profile_error": request.query_params.get("profile_error"),
            "email_notifications": email_notifications,
            "notifications_saved": request.query_params.get("notifications_saved"),
            "notifications_error": request.query_params.get("notifications_error"),
            "password_changed": request.query_params.get("password_changed"),
            "password_error": request.query_params.get("password_error"),
            "email_change": request.query_params.get("email_change"),
            "email_error": request.query_params.get("email_error"),
        },
    )


def update_patient_profile(cur, patient_id: int, full_name, phone) -> str:
    """Validate and store a patient's name and phone under the caller's role.

    Returns "saved", "name", "phone" or "unavailable". The journal entry carries
    only ids, never the name or the phone.
    """
    clean_name = clean_person_name(full_name)
    if clean_name is None:
        return "name"
    cleaned_phone = clean_phone(phone)
    if cleaned_phone is None:
        return "phone"
    try:
        cur.execute(
            "UPDATE patient_profiles SET full_name = %s, phone = %s WHERE user_id = %s",
            (clean_name, cleaned_phone, patient_id),
        )
    except psycopg2.errors.CheckViolation:
        return "invalid"
    if cur.rowcount != 1:
        return "unavailable"
    record_audit_event(cur, "patient.profile.update", "patient", patient_id)
    return "saved"


@router.post("/me/profile")
def update_own_profile(
    request: Request,
    full_name: str = Form(""),
    phone: str = Form(""),
):
    user, denied = require_user(request, "patient")
    if denied:
        return denied
    conn = db_as(user)
    try:
        with conn.cursor() as cur:
            result = update_patient_profile(cur, user["id"], full_name, phone)
            if result != "saved":
                conn.rollback()
                return RedirectResponse(f"/me?profile_error={result}", status_code=303)
        conn.commit()
    finally:
        conn.close()
    return RedirectResponse("/me?profile_saved=1", status_code=303)


@router.post("/me/notifications")
def update_email_notifications(
    request: Request,
    email_notifications: str = Form(None),
):
    user, denied = require_user(request)
    if denied:
        return denied
    enabled = email_notifications == "1"
    conn = db_as(user)
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT public.set_own_email_notifications(%s)",
                (enabled,),
            )
            row = cur.fetchone()
            if not row or row[0] is None:
                conn.rollback()
                return RedirectResponse("/me?notifications_error=1", status_code=303)
            record_audit_event(cur, "user.email_notifications", "user", user["id"])
        conn.commit()
    finally:
        conn.close()
    return RedirectResponse("/me?notifications_saved=1", status_code=303)


def _public_base_url() -> str:
    return os.environ.get("PUBLIC_BASE_URL", "http://localhost:8080").strip().rstrip("/")


def _send_email_change(old_email: str, new_email: str, old_token: str, new_token: str) -> None:
    base_url = _public_base_url()
    send_account_message(
        old_email,
        "Confirm your clinic email change",
        "Confirm that you want to change this account's email.\n"
        "The link expires in 15 minutes and works once.\n\n"
        f"{base_url}/confirm-email?token={old_token}\n\n"
        "If you did not request this, you can ignore this message.\n",
    )
    send_account_message(
        new_email,
        "Confirm your new clinic email",
        "Confirm this address for an existing clinic account.\n"
        "The link expires in 15 minutes and works once.\n\n"
        f"{base_url}/confirm-email?token={new_token}\n\n"
        "If you did not request this, you can ignore this message.\n",
    )


@router.post("/me/email")
def change_own_email(request: Request, new_email: str = Form(...)):
    user, denied = require_user(request)
    if denied:
        return denied
    if contains_nul(new_email) or any(char in new_email for char in "\r\n"):
        return RedirectResponse("/me?email_error=invalid", status_code=303)
    normalized = _normalize_registration_email(new_email)
    if normalized is None:
        return RedirectResponse("/me?email_error=invalid", status_code=303)
    if not smtp_ready():
        return RedirectResponse("/me?email_error=failed", status_code=303)
    conn = db_as(user)
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT status, old_email, new_email, old_token, new_token
                    FROM public.request_email_change(%s)
                    """,
                    (normalized,),
                )
                row = cur.fetchone()
    finally:
        conn.close()
    status = row[0] if row else "invalid"
    if status == "rate_limited":
        return RedirectResponse("/me?email_error=rate_limited", status_code=303)
    if status != "issued":
        return RedirectResponse(f"/me?email_error={status}", status_code=303)
    try:
        _send_email_change(row[1], row[2], row[3], row[4])
    except Exception:
        log.exception("could not send email-change confirmation")
        revoke = db()
        try:
            with revoke.cursor() as cur:
                cur.execute(
                    "SELECT public.revoke_email_change(%s, %s)",
                    (row[3], row[4]),
                )
            revoke.commit()
        finally:
            revoke.close()
        return RedirectResponse("/me?email_error=failed", status_code=303)
    return RedirectResponse("/me?email_change=sent", status_code=303)


@router.get("/confirm-email")
def confirm_email_form(request: Request, token: str = ""):
    if not RESET_TOKEN_PATTERN.fullmatch(token):
        return templates.TemplateResponse(
            request,
            "confirm_email.html",
            {"request": request, "role": "guest", "token": "", "error": "invalid"},
            status_code=400,
        )
    return templates.TemplateResponse(
        request,
        "confirm_email.html",
        {"request": request, "role": "guest", "token": token, "error": None},
    )


@router.post("/confirm-email")
def confirm_email(request: Request, token: str = Form(...)):
    if contains_nul(token) or not RESET_TOKEN_PATTERN.fullmatch(token):
        return templates.TemplateResponse(
            request,
            "confirm_email.html",
            {"request": request, "role": "guest", "token": "", "error": "invalid"},
            status_code=400,
        )
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT public.confirm_email_change(%s)", (token,))
            status = cur.fetchone()[0]
        conn.commit()
    finally:
        conn.close()
    if status == "changed":
        request.session.clear()
        return RedirectResponse("/login?email_changed=1", status_code=303)
    if status in ("confirmed_old", "confirmed_new"):
        return templates.TemplateResponse(
            request,
            "confirm_email.html",
            {"request": request, "role": "guest", "token": "", "error": status},
        )
    return templates.TemplateResponse(
        request,
        "confirm_email.html",
        {"request": request, "role": "guest", "token": "", "error": "invalid"},
        status_code=400,
    )


@router.post("/me/password")
def change_own_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
):
    user, denied = require_user(request)
    if denied:
        return denied
    if contains_nul(current_password, new_password, confirm_password):
        return RedirectResponse("/me?password_error=invalid", status_code=303)
    if has_edge_space(new_password) or has_edge_space(confirm_password):
        return RedirectResponse("/me?password_error=edge_space", status_code=303)
    if (
        not within_length(new_password, MAX_PASSWORD_LENGTH)
        or len(new_password) < 8
        or is_weak_password(new_password, user["email"])
    ):
        return RedirectResponse("/me?password_error=invalid", status_code=303)
    if new_password != confirm_password:
        return RedirectResponse("/me?password_error=mismatch", status_code=303)
    if not within_length(current_password, MAX_PASSWORD_LENGTH):
        return RedirectResponse("/me?password_error=current", status_code=303)

    conn = db_as(user)
    new_auth_version = None
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT result, resulting_auth_version
                    FROM public.change_own_patient_password(%s, %s, %s)
                    """,
                    (current_password, new_password, pwd.hash(new_password)),
                )
                row = cur.fetchone()
                if row is None or row[0] is None:
                    return RedirectResponse(
                        "/me?password_error=unavailable", status_code=303
                    )
                result, new_auth_version = row
                if result != "changed":
                    return RedirectResponse(
                        f"/me?password_error={result}", status_code=303
                    )
                record_audit_event(
                    cur, "user.password_change", user["role"], user["id"]
                )
    finally:
        conn.close()
    request.session["auth_version"] = new_auth_version
    _notify_password_changed(user["email"])
    return RedirectResponse("/me?password_changed=1", status_code=303)


# POST only: the global CSRF check runs first, so a cross-site request or a
# missing/wrong token cannot end the session. GET /logout answers 405.
@router.post("/logout")
def logout(request: Request):
    user = viewer(request)
    if user:
        conn = db_as(user)
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT public.revoke_own_sessions()")
        finally:
            conn.close()
    request.session.clear()
    return RedirectResponse("/", status_code=303)


@router.get("/doctors")
def doctors_list(request: Request):
    user = viewer(request)
    selected_patient_email = ""
    if user and user["role"] == "registrar":
        candidate = request.query_params.get("patient_email", "").strip()
        if not contains_nul(candidate) and within_length(candidate, MAX_EMAIL_LENGTH):
            selected_patient_email = candidate
    filter_errors = []
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT DISTINCT d.specialty
        FROM doctors d
        JOIN users u ON u.id = d.user_id
        WHERE u.role = 'doctor' AND NOT u.blocked
        ORDER BY d.specialty
        """
    )
    specialties = [row[0] for row in cur.fetchall()]
    raw_specialty = request.query_params.get("specialty", "")
    selected_specialty = ""
    if raw_specialty:
        if raw_specialty in specialties:
            selected_specialty = raw_specialty
        else:
            filter_errors.append("invalid_filter")
    search, search_error = clean_search(request.query_params.get("q"))
    if search_error:
        filter_errors.append(search_error)
    cur.execute(
        """
        SELECT d.id, d.full_name, d.specialty, d.experience_years
        FROM doctors d
        JOIN users u ON u.id = d.user_id
        WHERE u.role = 'doctor' AND NOT u.blocked
          AND (%s = '' OR d.specialty = %s)
          AND (%s = '' OR d.full_name ILIKE %s ESCAPE '\\')
        ORDER BY d.id
        """,
        (
            selected_specialty,
            selected_specialty,
            search,
            f"%{escape_like(search)}%",
        ),
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    doctors = []
    for row in rows:
        slots_url = f"/doctors/{row[0]}/slots"
        if selected_patient_email:
            slots_url += f"?{urlencode({'patient_email': selected_patient_email})}"
        doctors.append(
            {
                "id": row[0],
                "full_name": row[1],
                "specialty": row[2],
                "experience_years": row[3],
                "slots_url": slots_url,
            }
        )
    return templates.TemplateResponse(
        request,
        "doctors.html",
        {
            "request": request,
            "doctors": doctors,
            "role": user["role"] if user else "guest",
            "selected_patient_email": selected_patient_email,
            "specialties": specialties,
            "selected_specialty": selected_specialty,
            "search": search,
            "filter_errors": filter_errors,
            "filtered": bool(selected_specialty or search),
        },
    )
