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
    ("doc2@clinic.local", "password123", "doctor"),
    ("pat@clinic.local", "password123", "patient"),
    ("pat2@clinic.local", "password123", "patient"),
    ("reg@clinic.local", "password123", "registrar"),
]


def db():
    return psycopg2.connect(DATABASE_URL)


def seed_users():
    conn = db()
    cur = conn.cursor()
    for email, raw, role in SEED_USERS:
        cur.execute("SELECT 1 FROM users WHERE email=%s", (email,))
        if cur.fetchone() is None:
            cur.execute(
                "INSERT INTO users (email, password_hash, role) VALUES (%s, %s, %s)",
                (email, pwd.hash(raw), role),
            )
    conn.commit()
    cur.close()
    conn.close()


def ensure_schema():
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS blocked BOOLEAN NOT NULL DEFAULT FALSE;
        CREATE TABLE IF NOT EXISTS doctors (
          id SERIAL PRIMARY KEY,
          user_id INTEGER UNIQUE REFERENCES users(id),
          full_name TEXT NOT NULL,
          specialty TEXT NOT NULL,
          experience_years INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS slots (
          id SERIAL PRIMARY KEY,
          doctor_id INTEGER NOT NULL REFERENCES doctors(id),
          starts_at TIMESTAMP NOT NULL,
          ends_at TIMESTAMP NOT NULL
        );
        CREATE TABLE IF NOT EXISTS appointments (
          id SERIAL PRIMARY KEY,
          slot_id INTEGER NOT NULL REFERENCES slots(id),
          patient_user_id INTEGER NOT NULL REFERENCES users(id),
          status TEXT NOT NULL DEFAULT 'scheduled'
        );
        ALTER TABLE appointments DROP CONSTRAINT IF EXISTS appointments_slot_id_key;
        DROP INDEX IF EXISTS appointments_slot_id_key;
        CREATE UNIQUE INDEX IF NOT EXISTS appointments_one_scheduled_per_slot
          ON appointments(slot_id)
          WHERE status = 'scheduled';
        """
    )
    conn.commit()
    cur.close()
    conn.close()


def seed_clinic():
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT count(*) FROM doctors")
    if cur.fetchone()[0] == 0:
        cur.execute("SELECT id FROM users WHERE email=%s", ("doc@clinic.local",))
        d1 = cur.fetchone()[0]
        cur.execute("SELECT id FROM users WHERE email=%s", ("doc2@clinic.local",))
        d2 = cur.fetchone()[0]
        cur.execute(
            "INSERT INTO doctors (user_id, full_name, specialty, experience_years) VALUES (%s,%s,%s,%s) RETURNING id",
            (d1, "Anna Ohanyan", "Therapist", 8),
        )
        id1 = cur.fetchone()[0]
        cur.execute(
            "INSERT INTO doctors (user_id, full_name, specialty, experience_years) VALUES (%s,%s,%s,%s) RETURNING id",
            (d2, "Levon Petrosyan", "Dentist", 5),
        )
        id2 = cur.fetchone()[0]
        cur.execute(
            """
            INSERT INTO slots (doctor_id, starts_at, ends_at) VALUES
            (%s, '2026-10-01 09:00', '2026-10-01 09:30'),
            (%s, '2026-10-01 10:00', '2026-10-01 10:30'),
            (%s, '2026-10-01 11:00', '2026-10-01 11:30'),
            (%s, '2026-10-02 09:00', '2026-10-02 09:30'),
            (%s, '2026-10-01 09:00', '2026-10-01 09:30'),
            (%s, '2026-10-01 10:00', '2026-10-01 10:30'),
            (%s, '2026-10-03 10:00', '2026-10-03 11:00'),
            (%s, '2026-10-03 10:30', '2026-10-03 11:30')
            """,
            (id1, id1, id1, id1, id2, id2, id1, id2),
        )
        conn.commit()

    cur.close()
    conn.close()


@app.on_event("startup")
def on_start():
    ensure_schema()
    seed_users()
    seed_clinic()


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
    cur.execute(
        "SELECT email, password_hash, role, blocked FROM users WHERE email = %s",
        (email,),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row or not pwd.verify(password, row[1]):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid email or password", "role": None},
            status_code=401,
        )
    if row[3]:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "This account is blocked", "role": None},
            status_code=403,
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


@app.get("/doctors")
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
        {"request": request, "doctors": doctors, "role": request.session.get("role")},
    )


@app.get("/doctors/{doctor_id}/slots")
def doctor_slots(request: Request, doctor_id: int):
    role = request.session.get("role")
    if role not in ("patient", "registrar"):
        return RedirectResponse("/login", status_code=303)
    error = request.query_params.get("error")
    booked = request.query_params.get("booked")
    conflict = None
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id, full_name FROM doctors WHERE id=%s", (doctor_id,))
    doc = cur.fetchone()
    conflict_appointment_id = request.query_params.get("conflict_appointment_id")
    email = request.session.get("email")
    conflict_patient_id = request.query_params.get("conflict_patient_id")
    if error == "overlap" and conflict_appointment_id and role == "patient" and email:
        cur.execute(
            """
            SELECT d.full_name, s.starts_at, s.ends_at
            FROM appointments a
            JOIN slots s ON s.id = a.slot_id
            JOIN doctors d ON d.id = s.doctor_id
            JOIN users u ON u.id = a.patient_user_id
            WHERE a.id=%s AND u.email=%s AND a.status='scheduled'
            """,
            (conflict_appointment_id, email),
        )
        row = cur.fetchone()
        if row:
            conflict = {
                "doctor_name": row[0],
                "starts_at": row[1],
                "ends_at": row[2],
            }
    elif (
        error == "overlap"
        and conflict_appointment_id
        and conflict_patient_id
        and role == "registrar"
        and conflict_patient_id.isdigit()
    ):
        cur.execute(
            """
            SELECT d.full_name, s.starts_at, s.ends_at
            FROM appointments a
            JOIN slots s ON s.id = a.slot_id
            JOIN doctors d ON d.id = s.doctor_id
            WHERE a.id=%s AND a.patient_user_id=%s AND a.status='scheduled'
            """,
            (conflict_appointment_id, conflict_patient_id),
        )
        row = cur.fetchone()
        if row:
            conflict = {
                "doctor_name": row[0],
                "starts_at": row[1],
                "ends_at": row[2],
            }
    cur.execute(
        """
        SELECT s.id, s.starts_at, s.ends_at,
               EXISTS(
                   SELECT 1
                   FROM appointments a
                   WHERE a.slot_id = s.id
                     AND a.status = 'scheduled'
               ) AS taken
        FROM slots s
        WHERE s.doctor_id=%s
        ORDER BY s.starts_at
        """,
        (doctor_id,),
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    if not doc:
        return RedirectResponse("/doctors", status_code=303)
    slots = [
        {"id": r[0], "starts_at": r[1], "ends_at": r[2], "taken": r[3]}
        for r in rows
    ]
    return templates.TemplateResponse(
        "slots.html",
        {
            "request": request,
            "doctor": {"id": doc[0], "full_name": doc[1]},
            "slots": slots,
            "error": error,
            "booked": booked,
            "conflict": conflict,
            "role": role,
        },
    )


@app.post("/slots/{slot_id}/book")
def book_slot(request: Request, slot_id: int, patient_email: str = Form(None)):
    email = request.session.get("email")
    role = request.session.get("role")
    if role not in ("patient", "registrar") or not email:
        return RedirectResponse("/login", status_code=303)
    target_email = email if role == "patient" else patient_email
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT doctor_id, starts_at, ends_at FROM slots WHERE id=%s", (slot_id,))
    slot = cur.fetchone()
    if not slot:
        cur.close()
        conn.close()
        return RedirectResponse("/doctors", status_code=303)
    doctor_id, starts_at, ends_at = slot
    if not target_email:
        cur.close()
        conn.close()
        return RedirectResponse(f"/doctors/{doctor_id}/slots?error=patient_required", status_code=303)
    cur.execute(
        "SELECT id, blocked FROM users WHERE email=%s AND role='patient'",
        (target_email,),
    )
    patient = cur.fetchone()
    if not patient:
        cur.close()
        conn.close()
        return RedirectResponse(f"/doctors/{doctor_id}/slots?error=patient_not_found", status_code=303)
    patient_id, patient_blocked = patient
    if patient_blocked:
        cur.close()
        conn.close()
        return RedirectResponse(f"/doctors/{doctor_id}/slots?error=patient_blocked", status_code=303)
    cur.execute("SELECT pg_advisory_xact_lock(%s)", (patient_id,))

    cur.execute(
        """
        SELECT a.id
        FROM appointments a
        JOIN slots s ON s.id = a.slot_id
        WHERE a.patient_user_id = %s
          AND a.status = 'scheduled'
          AND s.starts_at < %s
          AND s.ends_at > %s
        """,
        (patient_id, ends_at, starts_at),
    )
    conflict_row = cur.fetchone()
    if conflict_row:
        cur.close()
        conn.close()
        return RedirectResponse(
            f"/doctors/{doctor_id}/slots?error=overlap&conflict_appointment_id={conflict_row[0]}&conflict_patient_id={patient_id}",
            status_code=303,
        )

    cur.execute(
        "SELECT 1 FROM appointments WHERE slot_id=%s AND status='scheduled'",
        (slot_id,),
    )
    if cur.fetchone():
        cur.close()
        conn.close()
        return RedirectResponse(f"/doctors/{doctor_id}/slots?error=unavailable", status_code=303)

    try:
        cur.execute(
            "INSERT INTO appointments (slot_id, patient_user_id) VALUES (%s, %s)",
            (slot_id, patient_id),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        cur.close()
        conn.close()
        return RedirectResponse(f"/doctors/{doctor_id}/slots?error=unavailable", status_code=303)
    cur.close()
    conn.close()
    if role == "registrar":
        return RedirectResponse(f"/doctors/{doctor_id}/slots?booked=1", status_code=303)
    return RedirectResponse("/my", status_code=303)


@app.post("/appointments/{appointment_id}/cancel")
def cancel_appointment(request: Request, appointment_id: int):
    email = request.session.get("email")
    role = request.session.get("role")
    if role != "patient" or not email:
        return RedirectResponse("/login", status_code=303)
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE appointments a
        SET status='cancelled'
        FROM users u
        WHERE a.id=%s
          AND a.patient_user_id=u.id
          AND u.email=%s
          AND a.status='scheduled'
        RETURNING a.id
        """,
        (appointment_id, email),
    )
    cancelled = cur.fetchone() is not None
    conn.commit()
    cur.close()
    conn.close()
    if cancelled:
        return RedirectResponse("/my?cancelled=1", status_code=303)
    return RedirectResponse("/my?cancel_error=1", status_code=303)


@app.get("/my")
def my_appointments(request: Request):
    email = request.session.get("email")
    role = request.session.get("role")
    if role != "patient" or not email:
        return RedirectResponse("/login", status_code=303)
    cancelled = request.query_params.get("cancelled")
    cancel_error = request.query_params.get("cancel_error")
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT a.id, d.full_name, s.starts_at, s.ends_at, a.status
        FROM appointments a
        JOIN slots s ON s.id=a.slot_id
        JOIN doctors d ON d.id=s.doctor_id
        JOIN users u ON u.id=a.patient_user_id
        WHERE u.email=%s
        ORDER BY s.starts_at
        """,
        (email,),
    )
    items = [
        {
            "id": r[0],
            "doctor_name": r[1],
            "starts_at": r[2],
            "ends_at": r[3],
            "status": r[4],
        }
        for r in cur.fetchall()
    ]
    cur.close()
    conn.close()
    return templates.TemplateResponse(
        "my_appointments.html",
        {
            "request": request,
            "items": items,
            "role": role,
            "cancelled": cancelled,
            "cancel_error": cancel_error,
        },
    )


@app.get("/doctor/appointments")
def doctor_appointments(request: Request):
    email = request.session.get("email")
    role = request.session.get("role")
    if role != "doctor" or not email:
        return RedirectResponse("/login", status_code=303)
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT u.email, s.starts_at, a.status
        FROM appointments a
        JOIN slots s ON s.id=a.slot_id
        JOIN doctors d ON d.id=s.doctor_id
        JOIN users u ON u.id=a.patient_user_id
        JOIN users du ON du.id=d.user_id
        WHERE du.email=%s
        ORDER BY s.starts_at
        """,
        (email,),
    )
    items = [
        {"patient_email": r[0], "starts_at": r[1], "status": r[2]}
        for r in cur.fetchall()
    ]
    cur.close()
    conn.close()
    return templates.TemplateResponse(
        "doctor_appointments.html",
        {"request": request, "items": items, "role": role},
    )


@app.get("/admin/users")
def admin_users(request: Request):
    if request.session.get("role") != "admin":
        return RedirectResponse("/login", status_code=303)
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, email, blocked FROM users WHERE role='patient' ORDER BY email"
    )
    users = [
        {"id": row[0], "email": row[1], "blocked": row[2]}
        for row in cur.fetchall()
    ]
    cur.close()
    conn.close()
    return templates.TemplateResponse(
        "admin_users.html",
        {"request": request, "users": users, "role": "admin"},
    )


@app.post("/admin/users/{user_id}/block")
def block_user(request: Request, user_id: int):
    if request.session.get("role") != "admin":
        return RedirectResponse("/login", status_code=303)
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET blocked=TRUE WHERE id=%s AND role='patient'",
        (user_id,),
    )
    conn.commit()
    cur.close()
    conn.close()
    return RedirectResponse("/admin/users", status_code=303)


@app.post("/admin/users/{user_id}/unblock")
def unblock_user(request: Request, user_id: int):
    if request.session.get("role") != "admin":
        return RedirectResponse("/login", status_code=303)
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET blocked=FALSE WHERE id=%s AND role='patient'",
        (user_id,),
    )
    conn.commit()
    cur.close()
    conn.close()
    return RedirectResponse("/admin/users", status_code=303)