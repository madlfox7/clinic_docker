from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse





from db import (
    MAX_EMAIL_LENGTH,
    MAX_PASSWORD_LENGTH,
    db,
    load_session_user,
    pwd,
    templates,
    within_length,
)

router = APIRouter()


def _login_page(request: Request, error: str | None, status_code: int = 200, role: str = "guest", email=None):
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "error": error,
            "role": role,
            "email": email,
        },
        status_code=status_code,
    )


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
    return templates.TemplateResponse(
        "home.html",
        {"request": request, "role": user["role"] if user else "guest"},
    )


@router.get("/login")
def login_form(request: Request):
    user, status = load_session_user(request)
    if status == "blocked":
        return _login_page(request, "Account is blocked", 403)
    if status == "ok":
        return _login_page(request, None, role=user["role"], email=user["email"])
    return _login_page(request, None)


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
    cur.execute("SELECT id, full_name, specialty, experience_years FROM doctors ORDER BY id")
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

