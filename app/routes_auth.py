import re
from urllib.parse import urlencode

from psycopg2.errors import UniqueViolation
from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse





from db import (
    MAX_EMAIL_LENGTH,
    MAX_PASSWORD_LENGTH,
    db_as_guest,
    db,
    db_as,
    load_session_user,
    pwd,
    record_audit_event,
    templates,
    within_length,
)

router = APIRouter()

EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)
DEFAULT_REGISTRATION_PASSWORDS = {
    "password",
    "password123",
    "12345678",
    "123456789",
    "qwerty123",
    "admin123",
    "letmein",
    "welcome1",
    "changeme",
    "passw0rd",
}


def _login_page(
    request: Request,
    error: str | None,
    status_code: int = 200,
    role: str = "guest",
    email=None,
    registered: bool = False,
):
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "error": error,
            "role": role,
            "email": email,
            "registered": registered,
        },
        status_code=status_code,
    )


def _register_page(
    request: Request,
    error: str | None = None,
    status_code: int = 200,
    email: str = "",
):
    return templates.TemplateResponse(
        "register.html",
        {
            "request": request,
            "role": "guest",
            "error": error,
            "email": email,
        },
        status_code=status_code,
    )


def _normalize_registration_email(email: str) -> str | None:
    if not within_length(email, MAX_EMAIL_LENGTH):
        return None
    normalized = email.strip().lower()
    if not EMAIL_PATTERN.fullmatch(normalized):
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


def require_user(request: Request, *roles):
    """Load id, role and blocked from users. Cookie role is ignored."""
    user, status = load_session_user(request)
    if status == "blocked":
        return None, _login_page(request, "Account is blocked", 403)
    if status != "ok":
        return None, RedirectResponse("/login", status_code=303)
    if roles and user["role"] not in roles:
        return None, RedirectResponse("/login", status_code=303)
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
    return _login_page(
        request,
        None,
        registered=request.query_params.get("registered") == "1",
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
):
    user, status = load_session_user(request)
    if status == "blocked":
        return _register_page(request, "Account is blocked", 403)
    if status == "ok":
        return RedirectResponse("/me", status_code=303)

    normalized_email = _normalize_registration_email(email)
    if normalized_email is None:
        return _register_page(request, "Enter a valid email address.", 400, email)
    if not within_length(password, MAX_PASSWORD_LENGTH) or len(password) < 8:
        return _register_page(
            request,
            "Password must be 8–72 bytes and at least 8 characters.",
            400,
            normalized_email,
        )
    if password.strip().casefold() in DEFAULT_REGISTRATION_PASSWORDS:
        return _register_page(
            request,
            "Choose a non-default password.",
            400,
            normalized_email,
        )
    if password != confirm_password:
        return _register_page(
            request,
            "Passwords do not match.",
            400,
            normalized_email,
        )

    conn = db_as_guest()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO users (email, password_hash, role, blocked)
                VALUES (%s, %s, 'patient', FALSE)
                """,
                (normalized_email, pwd.hash(password)),
            )
        conn.commit()
    except UniqueViolation:
        conn.rollback()
        return _register_page(
            request,
            "An account with this email already exists.",
            409,
            normalized_email,
        )
    finally:
        conn.close()
    return RedirectResponse("/login?registered=1", status_code=303)


@router.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    user, status = load_session_user(request)
    if status == "blocked":
        return _login_page(request, "Account is blocked", 403)
    if status == "ok":
        return _login_page(request, None, role=user["role"], email=user["email"])
    if not within_length(email, MAX_EMAIL_LENGTH) or not within_length(password, MAX_PASSWORD_LENGTH):
        return _login_page(request, "Invalid email or password", 401)
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, email, role, blocked, auth_version
                FROM public.authenticate_user(%s, %s)
                """,
                (email, password),
            )
            row = cur.fetchone()
    finally:
        conn.close()
    if not row:
        return _login_page(request, "Invalid email or password", 401)
    if row[3]:
        return _login_page(request, "Account is blocked", 403)
    request.session.clear()
    request.session["user_id"] = row[0]
    request.session["email"] = row[1]
    request.session["auth_version"] = row[4]
    return RedirectResponse("/me", status_code=303)


@router.get("/me")
def me(request: Request):
    user, denied = require_user(request)
    if denied:
        return denied
    upcoming_visits = []
    if user["role"] == "patient":
        conn = db_as(user)
        try:
            with conn.cursor() as cur:
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
    return templates.TemplateResponse(
        "me.html",
        {
            "request": request,
            "email": user["email"],
            "role": user["role"],
            "upcoming_visits": upcoming_visits,
            "password_changed": request.query_params.get("password_changed"),
            "password_error": request.query_params.get("password_error"),
        },
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
    if (
        not within_length(new_password, MAX_PASSWORD_LENGTH)
        or len(new_password) < 8
        or new_password.strip().casefold() in DEFAULT_REGISTRATION_PASSWORDS
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
    return RedirectResponse("/me?password_changed=1", status_code=303)


@router.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=303)


@router.get("/doctors")
def doctors_list(request: Request):
    user = viewer(request)
    selected_patient_email = ""
    if user and user["role"] == "registrar":
        candidate = request.query_params.get("patient_email", "").strip()
        if within_length(candidate, MAX_EMAIL_LENGTH):
            selected_patient_email = candidate
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT d.id, d.full_name, d.specialty, d.experience_years
        FROM doctors d
        JOIN users u ON u.id = d.user_id
        WHERE u.role = 'doctor' AND NOT u.blocked
        ORDER BY d.id
        """
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
        "doctors.html",
        {
            "request": request,
            "doctors": doctors,
            "role": user["role"] if user else "guest",
            "selected_patient_email": selected_patient_email,
        },
    )
