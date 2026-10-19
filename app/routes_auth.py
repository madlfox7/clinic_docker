import re

from psycopg2.errors import UniqueViolation
from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse





from db import (
    MAX_EMAIL_LENGTH,
    MAX_PASSWORD_LENGTH,
    db_as_guest,
    db,
    load_session_user,
    pwd,
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
    cur = conn.cursor()
    cur.execute(
        "SELECT id, email, password_hash, role, blocked FROM users WHERE email = %s",
        (email,),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row or not pwd.verify(password, row[2]):
        return _login_page(request, "Invalid email or password", 401)
    if row[4]:
        return _login_page(request, "Account is blocked", 403)
    request.session.clear()
    request.session["user_id"] = row[0]
    request.session["email"] = row[1]
    return RedirectResponse("/me", status_code=303)


@router.get("/me")
def me(request: Request):
    user, denied = require_user(request)
    if denied:
        return denied
    return templates.TemplateResponse(
        "me.html",
        {"request": request, "email": user["email"], "role": user["role"]},
    )


@router.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=303)


@router.get("/doctors")
def doctors_list(request: Request):
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
    doctors = [
        {"id": r[0], "full_name": r[1], "specialty": r[2], "experience_years": r[3]}
        for r in rows
    ]
    user = viewer(request)
    return templates.TemplateResponse(
        "doctors.html",
        {
            "request": request,
            "doctors": doctors,
            "role": user["role"] if user else "guest",
        },
    )
