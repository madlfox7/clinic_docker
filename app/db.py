import logging
import os
from datetime import date

import psycopg2
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext




DATABASE_URL = os.environ["DATABASE_URL"]
pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
log = logging.getLogger("clinic")
templates = Jinja2Templates(directory="templates")

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


def within_length(raw, max_length: int) -> bool:
    """Reject non-str or input whose UTF-8 byte length exceeds max_length, so oversized
    payloads (10-50KB manual input) never reach bcrypt or the database unbounded."""
    return isinstance(raw, str) and len(raw.encode("utf-8")) <= max_length



def parse_strict_int(raw, min_value: int = PG_INT_MIN, max_value: int = PG_INT_MAX):
    """Strict int parsing (like ft_atoi with no leniency): rejects None, empty, whitespace,
    signs without digits, and any non-digit characters instead of trusting str/int coercion."""
    if not isinstance(raw, str):
        return None
    if raw == "" or raw != raw.strip():
        return None
    body = raw
    negative = False
    if raw[0] in "+-":
        body = raw[1:]
        negative = raw[0] == "-"
    if body == "" or not body.isdigit():
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
    return psycopg2.connect(DATABASE_URL)


def _set_db_context(conn, role, user_id):
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT set_config('role', %s, true)", (role,))
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


def db_as(user):
    role = ROLE_BY_APP[user["role"]]
    conn = db()
    _set_db_context(conn, role, user["id"])
    return conn


#
def load_session_user(request):
    """Re-read id, email, role and blocked from users.

    The signed cookie is only a user id. Role is never taken from the session.
    Returns (user, status): status is 'ok', 'anonymous', 'missing', or 'blocked'.
    A missing or blocked account clears the session.
    """
    raw_id = request.session.get("user_id")
    has_auth_cookie = (
        raw_id is not None
        or request.session.get("email")
        or request.session.get("role")
    )
    if type(raw_id) is not int or raw_id < 1:
        if has_auth_cookie:
            request.session.clear()
            return None, "missing"
        return None, "anonymous"
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, email, role, blocked FROM users WHERE id=%s",
            (raw_id,),
        )
        row = cur.fetchone()
        cur.close()
    finally:
        conn.close()
    if not row:
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
    }, "ok"


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
            "INSERT INTO doctors (user_id, full_name, specialty, experience_years) VALUES (%s,%s,%s,%s)",
            (d1, "Anna Ohanyan", "Therapist", 8),
        )
        cur.execute(
            "INSERT INTO doctors (user_id, full_name, specialty, experience_years) VALUES (%s,%s,%s,%s)",
            (d2, "Levon Petrosyan", "Dentist", 5),
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
    seed_future_slots(cur)
    conn.commit()
    cur.close()
    conn.close()





def seed_future_slots(cur):
   
    cur.execute(
        """
        WITH clock AS (
            SELECT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC') AS now_utc
        ),
        horizon AS (
            SELECT ((SELECT now_utc FROM clock)::date + n) AS day
            FROM generate_series(0, 21) AS n
        ),
        windows AS (
            SELECT d.id AS doctor_id,
                   h.day,
                   (h.day + w.start_time) AS window_start,
                   (h.day + w.end_time) AS window_end,
                   w.slot_minutes
            FROM doctors d
            JOIN horizon h ON true
            JOIN work_hours w
              ON w.doctor_id = d.id
             AND w.weekday = (EXTRACT(ISODOW FROM h.day)::int - 1)
            WHERE w.end_time > w.start_time
              AND NOT EXISTS (SELECT 1 FROM holidays hol WHERE hol.day = h.day)
              AND NOT EXISTS (
                  SELECT 1 FROM time_off t
                  WHERE t.doctor_id = d.id
                    AND h.day BETWEEN t.starts_on AND t.ends_on
              )
        ),
        grid AS (
            SELECT w.doctor_id,
                   gs AS starts_at,
                   gs + make_interval(mins => w.slot_minutes) AS ends_at
            FROM windows w
            JOIN clock c ON true
            CROSS JOIN LATERAL generate_series(
                w.window_start,
                w.window_end - make_interval(mins => w.slot_minutes),
                make_interval(mins => w.slot_minutes)
            ) AS gs
            WHERE gs > c.now_utc
        ),
        shared_starts AS (
            SELECT starts_at, ends_at
            FROM grid
            GROUP BY starts_at, ends_at
            HAVING count(DISTINCT doctor_id) = (SELECT count(*) FROM doctors)
        ),
        shared_limited AS (
            SELECT g.doctor_id, g.starts_at, g.ends_at
            FROM grid g
            WHERE (g.starts_at, g.ends_at) IN (
                SELECT starts_at, ends_at
                FROM shared_starts
                ORDER BY starts_at
                LIMIT 4
            )
        ),
        extras AS (
            SELECT g.doctor_id, g.starts_at, g.ends_at
            FROM grid g
            WHERE (
                NOT EXISTS (SELECT 1 FROM shared_starts)
                OR g.starts_at >= (SELECT min(starts_at) FROM shared_starts)
            )
              AND NOT EXISTS (
                  SELECT 1 FROM shared_limited s
                  WHERE s.doctor_id = g.doctor_id
                    AND g.starts_at < s.ends_at
                    AND g.ends_at > s.starts_at
              )
        ),
        extras_limited AS (
            SELECT doctor_id, starts_at, ends_at
            FROM (
                SELECT e.doctor_id, e.starts_at, e.ends_at,
                       row_number() OVER (PARTITION BY e.doctor_id ORDER BY e.starts_at) AS n
                FROM extras e
            ) ranked
            WHERE n <= 2
        ),
        planned AS (
            SELECT doctor_id, starts_at, ends_at FROM shared_limited
            UNION
            SELECT doctor_id, starts_at, ends_at FROM extras_limited
        )
        INSERT INTO slots (doctor_id, starts_at, ends_at)
        SELECT p.doctor_id, p.starts_at, p.ends_at
        FROM planned p
        WHERE NOT EXISTS (
            SELECT 1 FROM slots s
            WHERE s.doctor_id = p.doctor_id
              AND s.starts_at > (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
        )
        ON CONFLICT (doctor_id, starts_at) DO NOTHING
        """
    )
