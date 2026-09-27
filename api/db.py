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

