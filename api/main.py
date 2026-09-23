import os
from fastapi import FastAPI, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from starlette.middleware.sessions import SessionMiddleware
import psycopg2

DATABASE_URL = os.environ["DATABASE_URL"]
SESSION_SECRET = os.environ.get("SESSION_SECRET", "dev-secret-change-me")

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
templates = Jinja2Templates(directory="templates")
app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)

SEED_USERS = [
    ("admin@clinic.local", "password123", "admin"),
    ("doc@clinic.local", "password123", "doctor"),
    ("pat@clinic.local", "password123", "patient"),
    ("reg@clinic.local", "password123", "registrar"),
]


def db():
    return psycopg2.connect(DATABASE_URL)


def seed_users():
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT count(*) FROM users")
    n = cur.fetchone()[0]
    if n == 0:
        for email, raw, role in SEED_USERS:
            cur.execute(
                "INSERT INTO users (email, password_hash, role) VALUES (%s, %s, %s)",
                (email, pwd.hash(raw), role),
            )
        conn.commit()
    cur.close()
    conn.close()


@app.on_event("startup")
def on_start():
    seed_users()


@app.get("/")
def home(request: Request):
    return templates.TemplateResponse(
        "home.html",
        {"request": request, "role": request.session.get("role")},
    )


@app.get("/login")
def login_form(request: Request):
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": None, "role": request.session.get("role")},
    )


@app.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT email, password_hash, role FROM users WHERE email = %s", (email,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row or not pwd.verify(password, row[1]):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Неверный email или пароль", "role": None},
            status_code=401,
        )
    request.session["email"] = row[0]
    request.session["role"] = row[2]
    return RedirectResponse("/me", status_code=303)


@app.get("/me")
def me(request: Request):
    email = request.session.get("email")
    role = request.session.get("role")
    if not email:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(
        "me.html",
        {"request": request, "email": email, "role": role},
    )


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=303)