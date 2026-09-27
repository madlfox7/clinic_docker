from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from db import db, pwd, templates

router = APIRouter()

@router.get("/")
def home(request: Request):
    return templates.TemplateResponse(
        "home.html",
        {"request": request, "role": request.session.get("role") or "guest"},
    )


def _login_page(request: Request, error: str | None, status_code: int = 200):
    # A failed attempt must not pretend the previous session was cleared.
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "error": error,
            "role": request.session.get("role") or "guest",
            "email": request.session.get("email"),
        },
        status_code=status_code,
    )


@router.get("/login")
def login_form(request: Request):
    # Stay on /login so role-restricted redirects still land on a stable
    # "not permitted" page; just hide the credential form when already signed in.
    return _login_page(request, None)


@router.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    # Already signed in: do not collect a second set of credentials or
    # replace the session. Log out first to switch accounts.
    if request.session.get("email"):
        return _login_page(request, None)
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "SELECT email, password_hash, role, blocked FROM users WHERE email = %s",
        (email,),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row or not pwd.verify(password, row[1]):
        return _login_page(request, "Invalid email or password", 401)
    if row[3]:
        return _login_page(request, "Account is blocked", 403)
    request.session["email"] = row[0]
    request.session["role"] = row[2]
    return RedirectResponse("/me", status_code=303)


@router.get("/me")
def me(request: Request):
    email = request.session.get("email")
    role = request.session.get("role")
    if not email:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(
        "me.html",
        {"request": request, "email": email, "role": role or "guest"},
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
    return templates.TemplateResponse(
        "doctors.html",
        {
            "request": request,
            "doctors": doctors,
            "role": request.session.get("role") or "guest",
        },
    )

