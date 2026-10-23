import logging
import os
from datetime import date

import psycopg2
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext

from csrf import csrf_token




DATABASE_URL = os.environ.get("DATABASE_URL")
pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
log = logging.getLogger("clinic")
templates = Jinja2Templates(directory="templates")
templates.env.globals["csrf_token"] = csrf_token

ROLE_BY_APP = {
    "guest": "app_guest",
    "patient": "app_patient",
    "doctor": "app_doctor",
    "registrar": "app_registrar",
    "admin": "app_admin",
}

PG_INT_MIN = -2_147_483_648
PG_INT_MAX = 2_147_483_647
MAX_SLOT_MINUTES = 24 * 60
MAX_EMAIL_LENGTH = 254
MAX_PASSWORD_LENGTH = 72  # hashes <=72 bytes, other bytes ignored
MAX_TEXT_LENGTH = 200
MAX_RECORD_BODY_LENGTH = 4000
NAME_MIN_LENGTH = 2
NAME_MAX_LENGTH = 100
ADDRESS_MAX_LENGTH = 300
PHONE_MAX_LENGTH = 40
EXPERIENCE_MAX_YEARS = 70
SERVICE_DURATION_MIN = 5
SERVICE_DURATION_MAX = 480
SERVICE_BUFFER_MAX = 120
SLOT_MINUTES_MIN = 5
SLOT_MINUTES_MAX = 240
MAX_CLOSURE_DAYS = 366
MAX_FUTURE_DAYS = 366 * 2


def within_length(raw, max_length: int) -> bool:
    """Reject non-str or input whose UTF-8 byte length exceeds max_length, so oversized
    payloads (10-50KB manual input) never reach bcrypt or the database unbounded."""
    return isinstance(raw, str) and len(raw.encode("utf-8")) <= max_length


def contains_nul(*values) -> bool:
    return any(isinstance(value, str) and "\x00" in value for value in values)


def has_control_char(value: str) -> bool:
    return any(ord(char) < 32 or ord(char) == 127 for char in value)


def clean_label(value, min_length=NAME_MIN_LENGTH, max_length=NAME_MAX_LENGTH):
    """Strip a required label. Reject empty, short, long, and control characters."""
    if not isinstance(value, str) or contains_nul(value) or has_control_char(value):
        return None
    cleaned = value.strip()
    if len(cleaned) < min_length or len(cleaned) > max_length:
        return None
    if not within_length(cleaned, max_length * 4):
        return None
    return cleaned


def clean_optional_text(value, max_length):
    """Strip optional text. An empty result is allowed; control characters are not."""
    if not isinstance(value, str) or contains_nul(value) or has_control_char(value):
        return None
    cleaned = value.strip()
    if len(cleaned) > max_length or not within_length(cleaned, max_length * 4):
        return None
    return cleaned


def clean_phone(value):
    """Strip a phone number and allow only digits, spaces, and +()-."""
    if not isinstance(value, str) or contains_nul(value) or has_control_char(value):
        return None
    cleaned = value.strip()
    digits = sum(char.isdigit() for char in cleaned)
    if (
        not cleaned
        or len(cleaned) > PHONE_MAX_LENGTH
        or digits < 5
        or any(char not in "0123456789+()- " for char in cleaned)
    ):
        return None
    return cleaned



def parse_strict_int(raw, min_value: int = PG_INT_MIN, max_value: int = PG_INT_MAX):
    """Strict int parsing (like ft_atoi with no leniency): rejects None, empty, signs without digits, and any non-digit characters instead of trusting str/int coercion."""
    if not isinstance(raw, str):
        return None
    raw = raw.strip()
    if raw == "":
        return None
    body = raw
    negative = False
    if raw[0] in "+-":
        body = raw[1:]
        negative = raw[0] == "-"
    # ASCII only: "²".isdigit() is True but int("²") raises
    if body == "" or not (body.isascii() and body.isdigit()):
        return None
    value = -int(body) if negative else int(body)
    if not min_value <= value <= max_value:
        return None
    return value


SEED_USERS = [
    ("admin@clinic.local", "password123", "admin"),
    ("doc@clinic.local", "password123", "doctor"),
    ("doc2@clinic.local", "password123", "doctor"),
    ("pat@clinic.local", "password123", "patient"),
    ("pat2@clinic.local", "password123", "patient"),
    ("reg@clinic.local", "password123", "registrar"),
]


def db():
    if DATABASE_URL:
        return psycopg2.connect(DATABASE_URL)
    return psycopg2.connect(
        host=os.environ["PGHOST"],
        dbname=os.environ["PGDATABASE"],
        user=os.environ["PGUSER"],
        password=os.environ["PGPASSWORD"],
    )


def _set_db_context(conn, role, user_id):
    if role not in ROLE_BY_APP.values():
        raise ValueError("Unknown application database role")
    try:
        with conn.cursor() as cur:
            cur.execute(f"SET LOCAL ROLE {role}")
            cur.execute(
                "SELECT set_config('app.user_id', %s, true)",
                (str(user_id),),
            )
    except psycopg2.Error:
        conn.close()
        raise


def set_db_context(conn, user):
    role = ROLE_BY_APP[user["role"]]
    _set_db_context(conn, role, user["id"])


def load_appointment_notice(cur, appointment_id: int):
    cur.execute(
        """
        SELECT patient_email, doctor_email, doctor_name, service_name,
               starts_at, ends_at, patient_notifications, doctor_notifications
        FROM public.appointment_notice(%s)
        """,
        (appointment_id,),
    )
    row = cur.fetchone()
    if not row or not row[0]:
        return None
    return {
        "patient_email": row[0],
        "doctor_email": row[1],
        "doctor_name": row[2],
        "service_name": row[3],
        "starts_at": row[4],
        "ends_at": row[5],
        "patient_notifications": row[6],
        "doctor_notifications": row[7],
    }


def record_audit_event(cur, action: str, target_type: str, target_id: int | None = None):
    cur.execute(
        "SELECT public.record_audit_event(%s, %s, %s)",
        (action, target_type, target_id),
    )


def db_as(user):
    role = ROLE_BY_APP[user["role"]]
    conn = db()
    _set_db_context(conn, role, user["id"])
    return conn


def db_as_guest():
    conn = db()
    _set_db_context(conn, ROLE_BY_APP["guest"], 0)
    return conn


#
def load_session_user(request):
    """Re-read identity, role, blocked state and auth version from users.

    The signed cookie carries only a user id and revocable auth version.
    Returns (user, status): status is 'ok', 'anonymous', 'missing', or 'blocked'.
    A missing, stale or blocked account clears the session.
    """
    raw_id = request.session.get("user_id")
    raw_auth_version = request.session.get("auth_version")
    has_auth_cookie = (
        raw_id is not None
        or raw_auth_version is not None
        or request.session.get("email")
        or request.session.get("role")
    )
    if type(raw_id) is not int or raw_id < 1:
        if has_auth_cookie:
            request.session.clear()
            return None, "missing"
        return None, "anonymous"
    if type(raw_auth_version) is not int or raw_auth_version < 0:
        request.session.clear()
        return None, "missing"
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, email, role, blocked, auth_version FROM users WHERE id=%s",
            (raw_id,),
        )
        row = cur.fetchone()
        cur.close()
    finally:
        conn.close()
    if not row:
        request.session.clear()
        return None, "missing"
    if row[4] != raw_auth_version:
        request.session.clear()
        return None, "missing"
    if row[3]:
        request.session.clear()
        return None, "blocked"
    request.session.pop("role", None)
    request.session["email"] = row[1]
    return {
        "id": row[0],
        "email": row[1],
        "role": row[2],
        "blocked": False,
        "auth_version": row[4],
    }, "ok"


def seed_users():
    conn = db()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id FROM users WHERE email=%s AND role='admin'",
                    ("admin@clinic.local",),
                )
                row = cur.fetchone()
                if row is None:
                    admin_email, raw_password, _ = next(
                        user for user in SEED_USERS if user[2] == "admin"
                    )
                    cur.execute(
                        "SELECT public.bootstrap_seed_admin(%s, %s)",
                        (admin_email, pwd.hash(raw_password)),
                    )

            for email, raw_password, role in SEED_USERS:
                if role == "admin":
                    continue
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT public.bootstrap_seed_user(%s, %s, %s)",
                        (email, pwd.hash(raw_password), role),
                    )
    finally:
        conn.close()


def _set_seed_admin_context(conn):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id FROM users WHERE email=%s AND role='admin'",
            ("admin@clinic.local",),
        )
        row = cur.fetchone()
    if row is None:
        raise RuntimeError("Seed administrator is missing; seed_users() must run first")
    _set_db_context(conn, ROLE_BY_APP["admin"], row[0])


def seed_clinic():
    conn = db()
    try:
        with conn:
            _set_seed_admin_context(conn)
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) FROM doctors")
                if cur.fetchone()[0] == 0:
                    cur.execute(
                        "SELECT id FROM users WHERE email=%s",
                        ("doc@clinic.local",),
                    )
                    d1 = cur.fetchone()[0]
                    cur.execute(
                        "SELECT id FROM users WHERE email=%s",
                        ("doc2@clinic.local",),
                    )
                    d2 = cur.fetchone()[0]
                    cur.execute(
                        """
                        INSERT INTO doctors
                          (user_id, full_name, specialty, experience_years)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (d1, "Anna Ohanyan", "Therapist", 8),
                    )
                    cur.execute(
                        """
                        INSERT INTO doctors
                          (user_id, full_name, specialty, experience_years)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (d2, "Levon Petrosyan", "Dentist", 5),
                    )
                    cur.execute(
                        """
                        INSERT INTO doctor_services (doctor_id, service_id)
                        SELECT d.id, svc.id
                        FROM doctors d
                        CROSS JOIN services svc
                        WHERE d.user_id IN (%s, %s) AND svc.active
                        ON CONFLICT DO NOTHING
                        """,
                        (d1, d2),
                    )
    finally:
        conn.close()


def seed_work_schedule():
    conn = db()
    try:
        with conn:
            _set_seed_admin_context(conn)
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT d.id FROM doctors d
                    JOIN users u ON u.id=d.user_id WHERE u.email=%s
                    """,
                    ("doc@clinic.local",),
                )
                anna = cur.fetchone()[0]
                cur.execute(
                    """
                    SELECT d.id FROM doctors d
                    JOIN users u ON u.id=d.user_id WHERE u.email=%s
                    """,
                    ("doc2@clinic.local",),
                )
                levon = cur.fetchone()[0]

                for weekday in range(5):
                    cur.execute(
                        """
                        INSERT INTO work_hours
                          (doctor_id, weekday, start_time, end_time, slot_minutes)
                        VALUES (%s, %s, '09:00', '12:00', 30)
                        ON CONFLICT (doctor_id, weekday) DO NOTHING
                        """,
                        (anna, weekday),
                    )
                for weekday in (0, 2, 4):
                    cur.execute(
                        """
                        INSERT INTO work_hours
                          (doctor_id, weekday, start_time, end_time, slot_minutes)
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
                        """
                        INSERT INTO time_off (doctor_id, starts_on, ends_on)
                        VALUES (%s, %s, %s)
                        """,
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
                seed_future_slots(cur)
    finally:
        conn.close()





def seed_future_slots(cur):
    cur.execute(
        """
        WITH clock AS (
            SELECT (CURRENT_TIMESTAMP AT TIME ZONE 'Asia/Yerevan') AS now_local
        ),
        horizon AS (
            SELECT ((SELECT now_local FROM clock)::date + n) AS day
            FROM generate_series(0, 21) AS n
        ),
        windows AS (
            SELECT d.id AS doctor_id,
                   svc.id AS service_id,
                   h.day,
                   (h.day + w.start_time) AS window_start,
                   (h.day + w.end_time) AS window_end,
                   svc.duration_minutes,
                   svc.buffer_minutes,
                   svc.duration_minutes + svc.buffer_minutes AS total_minutes,
                   GREATEST(
                       w.slot_minutes,
                       svc.duration_minutes + svc.buffer_minutes
                   ) AS step_minutes
            FROM doctors d
            JOIN users u ON u.id = d.user_id AND NOT u.blocked
            JOIN doctor_services ds ON ds.doctor_id = d.id
            JOIN services svc ON svc.id = ds.service_id
            JOIN horizon h ON true
            JOIN work_hours w
              ON w.doctor_id = d.id
             AND w.weekday = (EXTRACT(ISODOW FROM h.day)::int - 1)
            WHERE svc.active
              AND w.end_time > w.start_time
              AND NOT EXISTS (SELECT 1 FROM holidays hol WHERE hol.day = h.day)
              AND NOT EXISTS (
                  SELECT 1 FROM time_off t
                  WHERE t.doctor_id = d.id
                    AND h.day BETWEEN t.starts_on AND t.ends_on
              )
        ),
        grid AS (
            SELECT w.doctor_id,
                   w.service_id,
                   w.duration_minutes,
                   w.buffer_minutes,
                   gs AS starts_at,
                   gs + make_interval(mins => w.total_minutes) AS ends_at
            FROM windows w
            JOIN clock c ON true
            CROSS JOIN LATERAL generate_series(
                w.window_start,
                w.window_end - make_interval(mins => w.total_minutes),
                make_interval(mins => w.step_minutes)
            ) AS gs
            WHERE gs > c.now_local
        ),
        planned AS (
            SELECT doctor_id, service_id, duration_minutes, buffer_minutes,
                   starts_at, ends_at
            FROM (
                SELECT g.*,
                       row_number() OVER (
                           PARTITION BY doctor_id, service_id
                           ORDER BY starts_at
                       ) AS slot_number
                FROM grid g
            ) ranked
            WHERE slot_number <= 6
        )
        INSERT INTO slots (
            doctor_id, service_id, starts_at, ends_at,
            duration_minutes, buffer_minutes
        )
        SELECT p.doctor_id, p.service_id, p.starts_at, p.ends_at,
               p.duration_minutes, p.buffer_minutes
        FROM planned p
        ON CONFLICT (doctor_id, service_id, starts_at) DO NOTHING
        """
    )
