import logging
import os
from datetime import date, datetime, timedelta
from datetime import time as datetime_time
from fastapi import FastAPI, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from starlette.middleware.sessions import SessionMiddleware
import psycopg2

DATABASE_URL = os.environ["DATABASE_URL"]
SESSION_SECRET = os.environ.get("SESSION_SECRET", "dev-secret-change-me")

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
log = logging.getLogger("clinic")
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
                CREATE TABLE IF NOT EXISTS work_hours (
                    id SERIAL PRIMARY KEY,
                    doctor_id INTEGER NOT NULL REFERENCES doctors(id),
                    weekday INTEGER NOT NULL CHECK (weekday BETWEEN 0 AND 6),
                    start_time TIME NOT NULL,
                    end_time TIME NOT NULL,
                    slot_minutes INTEGER NOT NULL CHECK (slot_minutes > 0),
                    UNIQUE (doctor_id, weekday)
                );
                CREATE TABLE IF NOT EXISTS time_off (
                    id SERIAL PRIMARY KEY,
                    doctor_id INTEGER NOT NULL REFERENCES doctors(id),
                    starts_on DATE NOT NULL,
                    ends_on DATE NOT NULL,
                    CHECK (ends_on >= starts_on)
                );
                CREATE TABLE IF NOT EXISTS holidays (
                    day DATE PRIMARY KEY,
                    name TEXT NOT NULL
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
                    ON appointments (slot_id)
                    WHERE status = 'scheduled';
                CREATE UNIQUE INDEX IF NOT EXISTS slots_doctor_start
                    ON slots (doctor_id, starts_at);
                CREATE UNIQUE INDEX IF NOT EXISTS time_off_doctor_period
                    ON time_off (doctor_id, starts_on, ends_on);
                CREATE EXTENSION IF NOT EXISTS btree_gist;
                ALTER TABLE slots
                    ADD COLUMN IF NOT EXISTS time_range tsrange
                    GENERATED ALWAYS AS (tsrange(starts_at, ends_at, '[)')) STORED;
                ALTER TABLE slots DROP CONSTRAINT IF EXISTS slots_no_overlap_per_doctor;
                ALTER TABLE slots
                    ADD CONSTRAINT slots_no_overlap_per_doctor
                    EXCLUDE USING gist (
                        doctor_id WITH =,
                        time_range WITH &&
                    );
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


def seed_work_schedule():
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "SELECT d.id FROM doctors d JOIN users u ON u.id=d.user_id WHERE u.email=%s",
        ("doc@clinic.local",),
    )
    anna = cur.fetchone()[0]
    cur.execute(
        "SELECT d.id FROM doctors d JOIN users u ON u.id=d.user_id WHERE u.email=%s",
        ("doc2@clinic.local",),
    )
    levon = cur.fetchone()[0]

    for weekday in range(5):
        cur.execute(
            """
            INSERT INTO work_hours (doctor_id, weekday, start_time, end_time, slot_minutes)
            VALUES (%s, %s, '09:00', '12:00', 30)
            ON CONFLICT (doctor_id, weekday) DO NOTHING
            """,
            (anna, weekday),
        )
    for weekday in (0, 2, 4):
        cur.execute(
            """
            INSERT INTO work_hours (doctor_id, weekday, start_time, end_time, slot_minutes)
            VALUES (%s, %s, '09:00', '11:00', 30)
            ON CONFLICT (doctor_id, weekday) DO NOTHING
            """,
            (levon, weekday),
        )

    cur.execute(
        """
        SELECT 1 FROM time_off
        WHERE doctor_id=%s AND starts_on=%s AND ends_on=%s
        """,
        (anna, date(2026, 10, 12), date(2026, 10, 18)),
    )
    if cur.fetchone() is None:
        cur.execute(
            "INSERT INTO time_off (doctor_id, starts_on, ends_on) VALUES (%s, %s, %s)",
            (anna, date(2026, 10, 12), date(2026, 10, 18)),
        )
    cur.execute(
        """
        INSERT INTO holidays (day, name)
        VALUES (%s, %s)
        ON CONFLICT (day) DO NOTHING
        """,
        (date(2026, 11, 26), "Thanksgiving"),
    )
    conn.commit()
    cur.close()
    conn.close()


@app.on_event("startup")
def on_start():
    ensure_schema()
    seed_users()
    seed_clinic()
    seed_work_schedule()


@app.get("/")
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


@app.get("/login")
def login_form(request: Request):
    # Stay on /login so role-restricted redirects still land on a stable
    # "not permitted" page; just hide the credential form when already signed in.
    return _login_page(request, None)


@app.post("/login")
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


@app.get("/me")
def me(request: Request):
    email = request.session.get("email")
    role = request.session.get("role")
    if not email:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(
        "me.html",
        {"request": request, "email": email, "role": role or "guest"},
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
        {
            "request": request,
            "doctors": doctors,
            "role": request.session.get("role") or "guest",
        },
    )


@app.get("/doctors/{doctor_id}/slots")
def doctor_slots(request: Request, doctor_id: int):
    role = request.session.get("role")
    if role not in ("patient", "registrar"):
        return RedirectResponse("/login", status_code=303)
    error = request.query_params.get("error")
    booked = request.query_params.get("booked")
    cancelled = request.query_params.get("cancelled")
    cancel_error = request.query_params.get("cancel_error")
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
             ) AS taken,
             EXISTS(
                 SELECT 1
                 FROM appointments a
                 JOIN users u ON u.id = a.patient_user_id
                 WHERE a.slot_id = s.id
                AND a.status = 'scheduled'
                AND u.email = %s
                             ) AS mine,
                             (
                                     SELECT a.id
                                     FROM appointments a
                                     WHERE a.slot_id = s.id
                                         AND a.status = 'scheduled'
                                     LIMIT 1
                             ) AS appointment_id
                               , (
                                   EXISTS (
                                       SELECT 1 FROM time_off t
                                       WHERE t.doctor_id=s.doctor_id
                                         AND s.starts_at::date BETWEEN t.starts_on AND t.ends_on
                                   )
                                   OR EXISTS (
                                       SELECT 1 FROM holidays h WHERE h.day=s.starts_at::date
                                   )
                               ) AS closed
                               , s.starts_at <= CURRENT_TIMESTAMP AS is_past
        FROM slots s
        WHERE s.doctor_id=%s
        ORDER BY s.starts_at
        """,
         (email, doctor_id),
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    if not doc:
        return RedirectResponse("/doctors", status_code=303)
    slots_by_day = {}
    for row in rows:
        slot = {
            "id": row[0],
            "starts_at": row[1],
            "ends_at": row[2],
            "taken": row[3],
            "mine": row[4],
            "appointment_id": row[5],
            "closed": row[6],
            "past": row[7],
        }
        slots_by_day.setdefault(row[1].date(), []).append(slot)
    days = [
        {
            "label": day.strftime("%A, %Y-%m-%d"),
            "slots": day_slots,
        }
        for day, day_slots in sorted(slots_by_day.items())
    ]
    return templates.TemplateResponse(
        "slots.html",
        {
            "request": request,
            "doctor": {"id": doc[0], "full_name": doc[1]},
            "days": days,
            "error": error,
            "booked": booked,
            "cancelled": cancelled,
            "cancel_error": cancel_error,
            "conflict": conflict,
            "role": role or "guest",
        },
    )


@app.post("/slots/{slot_id}/book")
def book_slot(request: Request, slot_id: int, patient_email: str = Form(None)):
    email = request.session.get("email")
    role = request.session.get("role")
    if role not in ("patient", "registrar") or not email:
        return RedirectResponse("/login", status_code=303)
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT s.doctor_id, s.starts_at, s.ends_at,
               s.starts_at <= CURRENT_TIMESTAMP AS is_past,
               EXISTS (
                   SELECT 1 FROM time_off t
                   WHERE t.doctor_id=s.doctor_id
                     AND s.starts_at::date BETWEEN t.starts_on AND t.ends_on
               ) OR EXISTS (
                   SELECT 1 FROM holidays h WHERE h.day=s.starts_at::date
               ) AS closed
        FROM slots s
        WHERE s.id=%s
        """,
        (slot_id,),
    )
    slot = cur.fetchone()
    if not slot:
        cur.close()
        conn.close()
        return RedirectResponse("/doctors", status_code=303)
    doctor_id, starts_at, ends_at, is_past, is_closed = slot
    if is_past:
        cur.close()
        conn.close()
        return RedirectResponse(f"/doctors/{doctor_id}/slots?error=past", status_code=303)
    if is_closed:
        cur.close()
        conn.close()
        return RedirectResponse(f"/doctors/{doctor_id}/slots?error=closed", status_code=303)
    if role == "patient":
        target_email = email
    else:
        target_email = (patient_email or "").strip()
        if not target_email:
            cur.close()
            conn.close()
            return RedirectResponse(
                f"/doctors/{doctor_id}/slots?error=patient_required", status_code=303
            )
    cur.execute(
        "SELECT id, role, blocked FROM users WHERE email=%s",
        (target_email,),
    )
    target = cur.fetchone()
    if not target or target[1] != "patient":
        cur.close()
        conn.close()
        return RedirectResponse(f"/doctors/{doctor_id}/slots?error=patient_not_found", status_code=303)
    patient_id = target[0]
    if target[2]:
        cur.close()
        conn.close()
        return RedirectResponse(f"/doctors/{doctor_id}/slots?error=patient_blocked", status_code=303)
    cur.execute("SELECT pg_advisory_xact_lock(%s)", (patient_id,))

    cur.execute(
        "SELECT 1 FROM appointments WHERE slot_id=%s AND status='scheduled'",
        (slot_id,),
    )
    if cur.fetchone():
        cur.close()
        conn.close()
        return RedirectResponse(f"/doctors/{doctor_id}/slots?error=unavailable", status_code=303)

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

    try:
        cur.execute(
            "INSERT INTO appointments (slot_id, patient_user_id) VALUES (%s, %s)",
            (slot_id, patient_id),
        )
        conn.commit()
    except (psycopg2.errors.UniqueViolation, psycopg2.errors.ExclusionViolation):
        conn.rollback()
        cur.close()
        conn.close()
        return RedirectResponse(f"/doctors/{doctor_id}/slots?error=unavailable", status_code=303)
    except Exception:
        log.exception("could not book slot %s", slot_id)
        conn.rollback()
        cur.close()
        conn.close()
        return RedirectResponse(f"/doctors/{doctor_id}/slots?error=could_not_book", status_code=303)
    cur.close()
    conn.close()
    if role == "registrar":
        return RedirectResponse(f"/doctors/{doctor_id}/slots?booked=1", status_code=303)
    return RedirectResponse("/my", status_code=303)


@app.post("/appointments/{appointment_id}/cancel")
def cancel_appointment(request: Request, appointment_id: int):
    email = request.session.get("email")
    role = request.session.get("role")
    if role not in ("patient", "registrar", "admin") or not email:
        return RedirectResponse("/login", status_code=303)
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
         SELECT s.doctor_id, a.patient_user_id,
             s.starts_at > CURRENT_TIMESTAMP AS is_future
        FROM appointments a
        JOIN slots s ON s.id=a.slot_id
        WHERE a.id=%s AND a.status='scheduled'
        """,
        (appointment_id,),
    )
    appointment = cur.fetchone()
    if not appointment:
        cur.close()
        conn.close()
        if role == "patient":
            return RedirectResponse("/my?cancel_error=1", status_code=303)
        return RedirectResponse("/doctors", status_code=303)

    doctor_id, patient_user_id, is_future = appointment
    if role == "patient":
        if not is_future:
            cur.close()
            conn.close()
            return RedirectResponse("/my?cancel_error=1", status_code=303)
        cur.execute(
            """
            UPDATE appointments a
            SET status='cancelled'
            WHERE a.id=%s
              AND a.patient_user_id=%s
              AND a.status='scheduled'
              AND EXISTS (
                  SELECT 1 FROM users u
                  WHERE u.id=a.patient_user_id AND u.email=%s
              )
              AND EXISTS (
                  SELECT 1 FROM slots s
                  WHERE s.id=a.slot_id AND s.starts_at > CURRENT_TIMESTAMP
              )
            """,
            (appointment_id, patient_user_id, email),
        )
    else:
        cur.execute(
            """
            UPDATE appointments
            SET status='cancelled'
            WHERE id=%s AND status='scheduled'
            """,
            (appointment_id,),
        )
    updated = cur.rowcount
    conn.commit()
    cur.close()
    conn.close()
    if role == "patient":
        if updated:
            return RedirectResponse("/my?cancelled=1", status_code=303)
        return RedirectResponse("/my?cancel_error=1", status_code=303)
    if role == "admin":
        return RedirectResponse("/admin/schedule?visit_cancelled=1", status_code=303)
    if updated:
        return RedirectResponse(f"/doctors/{doctor_id}/slots?cancelled=1", status_code=303)
    return RedirectResponse(f"/doctors/{doctor_id}/slots?cancel_error=1", status_code=303)


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
         SELECT a.id, d.full_name, s.starts_at, s.ends_at, a.status,
             s.starts_at > CURRENT_TIMESTAMP AS cancellable
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
            "cancellable": r[5],
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
            "role": role or "guest",
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
        SELECT u.email, s.starts_at, s.ends_at, a.status, u.blocked
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
        {
            "patient_email": r[0],
            "starts_at": r[1],
            "ends_at": r[2],
            "status": r[3],
            "patient_blocked": r[4],
        }
        for r in cur.fetchall()
    ]
    cur.close()
    conn.close()
    return templates.TemplateResponse(
        "doctor_appointments.html",
        {"request": request, "items": items, "role": role or "guest"},
    )


@app.get("/admin/users")
def admin_users(request: Request):
    if request.session.get("role") != "admin":
        return RedirectResponse("/login", status_code=303)
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT p.id, p.email, p.blocked,
               (
                   SELECT count(*)
                   FROM appointments a
                   JOIN slots s ON s.id = a.slot_id
                   WHERE a.patient_user_id = p.id
                     AND a.status = 'scheduled'
                     AND s.starts_at > CURRENT_TIMESTAMP
               ) AS future_scheduled
        FROM users p
        WHERE p.role='patient'
        ORDER BY p.email
        """
    )
    users = [
        {
            "id": row[0],
            "email": row[1],
            "blocked": row[2],
            "future_scheduled": row[3],
        }
        for row in cur.fetchall()
    ]
    cur.close()
    conn.close()
    return templates.TemplateResponse(
        "admin_users.html",
        {
            "request": request,
            "users": users,
            "role": "admin",
            "future_cancelled": request.query_params.get("future_cancelled"),
        },
    )


def _purge_slots_without_scheduled(cur, where_sql, params):
    # Cancelled history must not keep a closed or out-of-hours slot on the calendar.
    cur.execute(
        f"""
        DELETE FROM appointments a
        WHERE a.status <> 'scheduled'
          AND a.slot_id IN (
              SELECT s.id
              FROM slots s
              WHERE {where_sql}
                AND NOT EXISTS (
                    SELECT 1 FROM appointments live
                    WHERE live.slot_id = s.id AND live.status = 'scheduled'
                )
          )
        """,
        params,
    )
    cur.execute(
        f"""
        DELETE FROM slots s
        WHERE {where_sql}
          AND NOT EXISTS (
              SELECT 1 FROM appointments a
              WHERE a.slot_id = s.id AND a.status = 'scheduled'
          )
        """,
        params,
    )
    return cur.rowcount


def _outside_hours_sql(alias="s"):
    # work_hours.weekday is Python's Monday=0, not PostgreSQL DOW (Sunday=0).
    return f"""
        NOT EXISTS (
            SELECT 1 FROM work_hours w
            WHERE w.doctor_id = {alias}.doctor_id
              AND w.weekday = ((EXTRACT(DOW FROM {alias}.starts_at)::int + 6) %% 7)
              AND {alias}.starts_at::date = {alias}.ends_at::date
              AND {alias}.starts_at::time >= w.start_time
              AND {alias}.ends_at::time <= w.end_time
        )
    """


def _scheduled_visit_rows(cur, where_sql, params):
    cur.execute(
        f"""
        SELECT a.id, u.email, d.full_name, s.starts_at, s.ends_at
        FROM appointments a
        JOIN users u ON u.id = a.patient_user_id
        JOIN slots s ON s.id = a.slot_id
        JOIN doctors d ON d.id = s.doctor_id
        WHERE a.status = 'scheduled'
          AND {where_sql}
        ORDER BY s.starts_at
        """,
        params,
    )
    return [
        {
            "appointment_id": row[0],
            "patient_email": row[1],
            "doctor_name": row[2],
            "starts_at": row[3],
            "ends_at": row[4],
        }
        for row in cur.fetchall()
    ]


def _close_slots_for_period(cur, starts_on: date, ends_on: date, doctor_id=None):
    if doctor_id is None:
        where_sql = "s.starts_at::date BETWEEN %s AND %s"
        params = (starts_on, ends_on)
    else:
        where_sql = "s.doctor_id=%s AND s.starts_at::date BETWEEN %s AND %s"
        params = (doctor_id, starts_on, ends_on)
    scheduled_visits = _scheduled_visit_rows(cur, where_sql, params)
    removed = _purge_slots_without_scheduled(cur, where_sql, params)
    return removed, scheduled_visits


@app.get("/admin/schedule")
def admin_schedule(request: Request):
    if request.session.get("role") != "admin":
        return RedirectResponse("/login", status_code=303)
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id, full_name FROM doctors ORDER BY full_name")
    doctors = [{"id": row[0], "full_name": row[1]} for row in cur.fetchall()]
    cur.execute(
        """
        SELECT d.full_name, w.weekday, w.start_time, w.end_time, w.slot_minutes
        FROM work_hours w
        JOIN doctors d ON d.id=w.doctor_id
        ORDER BY d.full_name, w.weekday
        """
    )
    work_hours = [
        {
            "doctor_name": row[0],
            "weekday": row[1],
            "start_time": row[2],
            "end_time": row[3],
            "slot_minutes": row[4],
        }
        for row in cur.fetchall()
    ]
    cur.execute(
        """
        SELECT d.full_name, t.starts_on, t.ends_on
        FROM time_off t
        JOIN doctors d ON d.id=t.doctor_id
        ORDER BY d.full_name, t.starts_on
        """
    )
    time_off = [
        {"doctor_name": row[0], "starts_on": row[1], "ends_on": row[2]}
        for row in cur.fetchall()
    ]
    cur.execute("SELECT day, name FROM holidays ORDER BY day")
    holidays = [{"day": row[0], "name": row[1]} for row in cur.fetchall()]
    closure_report = request.session.pop("closure_report", None)
    hours_report = request.session.pop("hours_report", None)
    manual_cancel_visits = _scheduled_visit_rows(
        cur,
        """
        (
            EXISTS (SELECT 1 FROM holidays h WHERE h.day = s.starts_at::date)
            OR EXISTS (
                SELECT 1 FROM time_off t
                WHERE t.doctor_id = s.doctor_id
                  AND s.starts_at::date BETWEEN t.starts_on AND t.ends_on
            )
        )
        """,
        (),
    )
    outside_hours_visits = _scheduled_visit_rows(cur, _outside_hours_sql("s"), ())
    cur.close()
    conn.close()
    return templates.TemplateResponse(
        "admin_schedule.html",
        {
            "request": request,
            "role": request.session.get("role") or "guest",
            "doctors": doctors,
            "work_hours": work_hours,
            "time_off": time_off,
            "holidays": holidays,
            "closure_report": closure_report,
            "hours_report": hours_report,
            "manual_cancel_visits": manual_cancel_visits,
            "outside_hours_visits": outside_hours_visits,
            "visit_cancelled": request.query_params.get("visit_cancelled"),
            "weekdays": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"],
            "saved": request.query_params.get("saved"),
            "error": request.query_params.get("error"),
            "generated": request.query_params.get("generated"),
            "skipped": request.query_params.get("skipped"),
        },
    )


@app.post("/admin/work-hours")
def admin_save_work_hours(
    request: Request,
    doctor_id: int = Form(...),
    weekday: int = Form(...),
    start_time: datetime_time = Form(...),
    end_time: datetime_time = Form(...),
    slot_minutes: int = Form(...),
):
    if request.session.get("role") != "admin":
        return RedirectResponse("/login", status_code=303)
    if not 0 <= weekday <= 6 or start_time >= end_time or slot_minutes <= 0:
        return RedirectResponse("/admin/schedule?error=invalid_work_hours", status_code=303)
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM doctors WHERE id=%s", (doctor_id,))
    if cur.fetchone() is None:
        cur.close()
        conn.close()
        return RedirectResponse("/admin/schedule?error=doctor_not_found", status_code=303)
    cur.execute(
        """
        INSERT INTO work_hours (doctor_id, weekday, start_time, end_time, slot_minutes)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (doctor_id, weekday) DO UPDATE
        SET start_time=EXCLUDED.start_time,
            end_time=EXCLUDED.end_time,
            slot_minutes=EXCLUDED.slot_minutes
        """,
        (doctor_id, weekday, start_time, end_time, slot_minutes),
    )
    conn.commit()
    cur.close()
    conn.close()
    return RedirectResponse("/admin/schedule?saved=work-hours", status_code=303)


@app.post("/admin/doctors/{doctor_id}/apply-hours")
def admin_apply_hours(request: Request, doctor_id: int):
    if request.session.get("role") != "admin":
        return RedirectResponse("/login", status_code=303)
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM doctors WHERE id=%s", (doctor_id,))
    if cur.fetchone() is None:
        cur.close()
        conn.close()
        return RedirectResponse("/admin/schedule?error=doctor_not_found", status_code=303)
    where_sql = f"s.doctor_id=%s AND {_outside_hours_sql('s')}"
    removed = _purge_slots_without_scheduled(cur, where_sql, (doctor_id,))
    conn.commit()
    cur.close()
    conn.close()
    request.session["hours_report"] = {
        "doctor_id": doctor_id,
        "removed_slots": removed,
    }
    return RedirectResponse("/admin/schedule?saved=apply-hours", status_code=303)


@app.post("/admin/time-off")
def admin_add_time_off(
    request: Request,
    doctor_id: int = Form(...),
    starts_on: date = Form(...),
    ends_on: date = Form(...),
):
    if request.session.get("role") != "admin":
        return RedirectResponse("/login", status_code=303)
    if starts_on > ends_on:
        return RedirectResponse("/admin/schedule?error=invalid_time_off", status_code=303)
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM doctors WHERE id=%s", (doctor_id,))
    if cur.fetchone() is None:
        cur.close()
        conn.close()
        return RedirectResponse("/admin/schedule?error=doctor_not_found", status_code=303)
    cur.execute(
        """
        INSERT INTO time_off (doctor_id, starts_on, ends_on)
        VALUES (%s, %s, %s)
        ON CONFLICT (doctor_id, starts_on, ends_on) DO NOTHING
        """,
        (doctor_id, starts_on, ends_on),
    )
    removed_slots, _ = _close_slots_for_period(cur, starts_on, ends_on, doctor_id)
    conn.commit()
    cur.close()
    conn.close()
    request.session["closure_report"] = {
        "kind": "time-off",
        "starts_on": starts_on.isoformat(),
        "ends_on": ends_on.isoformat(),
        "doctor_id": doctor_id,
        "removed_slots": removed_slots,
    }
    return RedirectResponse("/admin/schedule?saved=time-off", status_code=303)


@app.post("/admin/holidays")
def admin_save_holiday(
    request: Request,
    holiday_day: date = Form(...),
    name: str = Form(...),
):
    if request.session.get("role") != "admin":
        return RedirectResponse("/login", status_code=303)
    holiday_name = name.strip()
    if not holiday_name:
        return RedirectResponse("/admin/schedule?error=holiday_name_required", status_code=303)
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO holidays (day, name)
        VALUES (%s, %s)
        ON CONFLICT (day) DO UPDATE SET name=EXCLUDED.name
        """,
        (holiday_day, holiday_name),
    )
    removed_slots, _ = _close_slots_for_period(cur, holiday_day, holiday_day)
    conn.commit()
    cur.close()
    conn.close()
    request.session["closure_report"] = {
        "kind": "holiday",
        "starts_on": holiday_day.isoformat(),
        "ends_on": holiday_day.isoformat(),
        "doctor_id": None,
        "removed_slots": removed_slots,
    }
    return RedirectResponse("/admin/schedule?saved=holiday", status_code=303)


@app.post("/admin/doctors/{doctor_id}/generate")
def generate_doctor_slots(
    request: Request,
    doctor_id: int,
    from_date: date = Form(...),
    to_date: date = Form(...),
):
    if request.session.get("role") != "admin":
        return RedirectResponse("/login", status_code=303)
    if from_date > to_date or (to_date - from_date).days > 90:
        return RedirectResponse("/admin/schedule?error=invalid_range", status_code=303)

    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM doctors WHERE id=%s", (doctor_id,))
    if cur.fetchone() is None:
        cur.close()
        conn.close()
        return RedirectResponse("/admin/schedule?error=doctor_not_found", status_code=303)

    cur.execute(
        """
        SELECT weekday, start_time, end_time, slot_minutes
        FROM work_hours
        WHERE doctor_id=%s
        ORDER BY weekday
        """,
        (doctor_id,),
    )
    work_hours = cur.fetchall()
    cur.execute(
        """
        SELECT starts_on, ends_on
        FROM time_off
        WHERE doctor_id=%s AND starts_on <= %s AND ends_on >= %s
        """,
        (doctor_id, to_date, from_date),
    )
    time_off = cur.fetchall()
    cur.execute(
        "SELECT day FROM holidays WHERE day BETWEEN %s AND %s",
        (from_date, to_date),
    )
    holidays = {row[0] for row in cur.fetchall()}

    created = 0
    skipped = 0
    cur.execute("SELECT CURRENT_TIMESTAMP::timestamp")
    now = cur.fetchone()[0]
    today = now.date()
    current_date = from_date
    while current_date <= to_date:
        day_hours = [row for row in work_hours if row[0] == current_date.weekday()]
        is_day_off = (
            current_date in holidays
            or any(start <= current_date <= end for start, end in time_off)
        )
        for _, start_time, end_time, slot_minutes in day_hours:
            slot_duration = timedelta(minutes=slot_minutes)
            start_at = datetime.combine(current_date, start_time)
            day_end = datetime.combine(current_date, end_time)
            if is_day_off:
                while start_at + slot_duration <= day_end:
                    skipped += 1
                    start_at += slot_duration
                continue
            while start_at + slot_duration <= day_end:
                if current_date < today or start_at <= now:
                    skipped += 1
                    start_at += slot_duration
                    continue
                cur.execute("SAVEPOINT generate_slot")
                try:
                    cur.execute(
                        """
                        INSERT INTO slots (doctor_id, starts_at, ends_at)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (doctor_id, starts_at) DO NOTHING
                        """,
                        (doctor_id, start_at, start_at + slot_duration),
                    )
                    if cur.rowcount:
                        created += 1
                    else:
                        skipped += 1
                except psycopg2.errors.ExclusionViolation:
                    cur.execute("ROLLBACK TO SAVEPOINT generate_slot")
                    skipped += 1
                finally:
                    cur.execute("RELEASE SAVEPOINT generate_slot")
                start_at += slot_duration

        current_date += timedelta(days=1)

    conn.commit()
    cur.close()
    conn.close()
    return RedirectResponse(
        f"/admin/schedule?generated={created}&skipped={skipped}",
        status_code=303,
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


@app.post("/admin/users/{user_id}/cancel-future-appointments")
def cancel_future_appointments(request: Request, user_id: int):
    if request.session.get("role") != "admin":
        return RedirectResponse("/login", status_code=303)
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE appointments a
        SET status='cancelled'
        FROM slots s, users u
        WHERE a.slot_id=s.id
          AND a.patient_user_id=u.id
          AND u.id=%s
          AND u.role='patient'
          AND a.status='scheduled'
          AND s.starts_at > CURRENT_TIMESTAMP
        """,
        (user_id,),
    )
    cancelled_count = cur.rowcount
    conn.commit()
    cur.close()
    conn.close()
    return RedirectResponse(
        f"/admin/users?future_cancelled={cancelled_count}", status_code=303
    )