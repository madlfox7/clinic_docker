import json
import os
import subprocess
from pathlib import Path

import httpx

from tests.csrf_client import CsrfClient


ROOT = Path(__file__).resolve().parents[1]
PATIENT_A = "pat@clinic.local"
DOCTOR = "doc@clinic.local"
ADMIN = "admin@clinic.local"
TEST_BASE = os.environ.get("CLINIC_TEST_BASE", "http://localhost:8080")


def compose_exec(service: str, command: list[str], *, input_text: str = "") -> str:
    completed = subprocess.run(
        ["docker", "compose", "exec", "-T", service, *command],
        cwd=ROOT,
        input=input_text,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    return completed.stdout.strip()


def test_clinic_api_authenticates_without_reading_password_hash():
    result = compose_exec(
        "db",
        [
            "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
            "-U", "clinic", "-d", "clinic", "-At", "-F", "|",
            "-c",
            """
            BEGIN;
            SET LOCAL ROLE clinic_api;
            DO $$
            BEGIN
              BEGIN
                EXECUTE 'SELECT password_hash FROM public.users LIMIT 1';
                RAISE EXCEPTION 'clinic_api unexpectedly read password_hash';
              EXCEPTION WHEN insufficient_privilege THEN
                NULL;
              END;
            END $$;
            SELECT
                has_column_privilege(
                    'clinic_api', 'public.users', 'password_hash', 'SELECT'
                )::text,
                (SELECT role
                 FROM public.authenticate_user(
                   'pat@clinic.local', 'password123', '127.0.0.1'
                 )),
                (SELECT count(*)
                 FROM public.authenticate_user(
                   'pat@clinic.local', 'wrong', '127.0.0.1'
                 ))
            ROLLBACK;
            """,
        ],
    )
    assert result == "false|patient|0"


def test_doctor_cannot_write_records_for_other_or_cancelled_visits():
    compose_exec(
        "db",
        [
            "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
            "-U", "clinic", "-d", "clinic", "-c",
            """
            BEGIN;
            WITH identities AS (
                SELECT
                    (SELECT id FROM doctors WHERE user_id =
                        (SELECT id FROM users WHERE email = 'doc@clinic.local')) AS doctor_a,
                    (SELECT id FROM doctors WHERE user_id =
                        (SELECT id FROM users WHERE email = 'doc2@clinic.local')) AS doctor_b,
                    (SELECT id FROM users WHERE email = 'pat@clinic.local') AS patient_id,
                    (SELECT id FROM users WHERE email = 'doc@clinic.local') AS doctor_user_id
            ),
            times AS (
                SELECT clock_timestamp()::timestamp + INTERVAL '250 days' AS starts_at
            ),
            slot_a AS (
                INSERT INTO slots (doctor_id, starts_at, ends_at)
                SELECT doctor_a, starts_at, starts_at + INTERVAL '30 minutes'
                FROM identities CROSS JOIN times
                RETURNING id, doctor_id, starts_at, ends_at
            ),
            slot_b AS (
                INSERT INTO slots (doctor_id, starts_at, ends_at)
                SELECT doctor_b, starts_at + INTERVAL '2 hours',
                       starts_at + INTERVAL '2 hours 30 minutes'
                FROM identities CROSS JOIN times
                RETURNING id, doctor_id, starts_at, ends_at
            ),
            slot_cancelled AS (
                INSERT INTO slots (doctor_id, starts_at, ends_at)
                SELECT doctor_a, starts_at + INTERVAL '4 hours',
                       starts_at + INTERVAL '4 hours 30 minutes'
                FROM identities CROSS JOIN times
                RETURNING id, doctor_id, starts_at, ends_at
            ),
            appointment_a AS (
                INSERT INTO appointments
                    (slot_id, patient_user_id, doctor_id, starts_at, ends_at, status)
                SELECT slot_a.id, identities.patient_id, slot_a.doctor_id,
                       slot_a.starts_at, slot_a.ends_at, 'scheduled'
                FROM slot_a CROSS JOIN identities
                RETURNING id
            ),
            appointment_b AS (
                INSERT INTO appointments
                    (slot_id, patient_user_id, doctor_id, starts_at, ends_at, status)
                SELECT slot_b.id, identities.patient_id, slot_b.doctor_id,
                       slot_b.starts_at, slot_b.ends_at, 'scheduled'
                FROM slot_b CROSS JOIN identities
                RETURNING id
            ),
            appointment_cancelled AS (
                INSERT INTO appointments
                    (slot_id, patient_user_id, doctor_id, starts_at, ends_at, status)
                SELECT slot_cancelled.id, identities.patient_id,
                       slot_cancelled.doctor_id, slot_cancelled.starts_at,
                       slot_cancelled.ends_at, 'cancelled'
                FROM slot_cancelled CROSS JOIN identities
                RETURNING id
            )
            SELECT
                set_config('app.user_id', identities.doctor_user_id::text, true),
                set_config('test.doctor_id', identities.doctor_a::text, true),
                set_config('test.patient_id', identities.patient_id::text, true),
                set_config('test.other_appointment_id', appointment_b.id::text, true),
                set_config(
                    'test.cancelled_appointment_id',
                    appointment_cancelled.id::text,
                    true
                )
            FROM identities, appointment_b, appointment_cancelled;

            SET LOCAL ROLE app_doctor;
            DO $$
            DECLARE
                doctor_id integer := current_setting('test.doctor_id')::integer;
                patient_id integer := current_setting('test.patient_id')::integer;
                other_appointment_id integer :=
                    current_setting('test.other_appointment_id')::integer;
                cancelled_appointment_id integer :=
                    current_setting('test.cancelled_appointment_id')::integer;
            BEGIN
                BEGIN
                    INSERT INTO visit_notes
                        (appointment_id, doctor_id, patient_user_id, body)
                    VALUES (
                        other_appointment_id, doctor_id, patient_id,
                        'wrong-appointment-doctor'
                    );
                    RAISE EXCEPTION 'cross-appointment note insert unexpectedly succeeded';
                EXCEPTION WHEN insufficient_privilege THEN
                    NULL;
                END;

                BEGIN
                    INSERT INTO prescriptions
                        (appointment_id, doctor_id, patient_user_id, body)
                    VALUES (
                        cancelled_appointment_id, doctor_id, patient_id,
                        'cancelled-appointment-prescription'
                    );
                    RAISE EXCEPTION 'cancelled-appointment record insert unexpectedly succeeded';
                EXCEPTION WHEN insufficient_privilege THEN
                    NULL;
                END;
            END
            $$;
            ROLLBACK;
            """,
        ],
    )


def test_unfiltered_broken_selects_obey_role_rls():
    fixture = compose_exec(
        "db",
        [
            "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
            "-U", "clinic", "-d", "clinic", "-At", "-F", "|",
            "-c",
            """
            WITH identities AS (
                SELECT
                    (SELECT id FROM doctors WHERE user_id =
                        (SELECT id FROM users WHERE email = 'doc@clinic.local')) AS doctor_a,
                    (SELECT id FROM doctors WHERE user_id =
                        (SELECT id FROM users WHERE email = 'doc2@clinic.local')) AS doctor_b,
                    (SELECT id FROM users WHERE email = 'pat@clinic.local') AS patient_a,
                    (SELECT id FROM users WHERE email = 'pat2@clinic.local') AS patient_b
            ),
            times AS (
                SELECT (
                           SELECT CURRENT_DATE + candidate.day_offset + TIME '10:00'
                           FROM generate_series(30, 365) AS candidate(day_offset)
                           WHERE NOT EXISTS (
                               SELECT 1
                               FROM holidays h
                               WHERE h.day = CURRENT_DATE + candidate.day_offset
                           )
                             AND NOT EXISTS (
                                 SELECT 1
                                 FROM time_off t
                                 WHERE t.doctor_id = identities.doctor_a
                                   AND CURRENT_DATE + candidate.day_offset
                                       BETWEEN t.starts_on AND t.ends_on
                             )
                           ORDER BY candidate.day_offset
                           LIMIT 1
                       ) AS start_a,
                       clock_timestamp() + INTERVAL '30 days 2 hours' AS start_b
                FROM identities
            ),
            slot_a AS (
                INSERT INTO slots (doctor_id, starts_at, ends_at)
                SELECT doctor_a, start_a, start_a + INTERVAL '30 minutes'
                FROM identities, times
                RETURNING id, doctor_id, starts_at, ends_at
            ),
            slot_c AS (
                INSERT INTO slots (doctor_id, starts_at, ends_at)
                SELECT doctor_a, start_a + INTERVAL '4 hours',
                       start_a + INTERVAL '4 hours 30 minutes'
                FROM identities, times
                RETURNING id
            ),
            slot_b AS (
                INSERT INTO slots (doctor_id, starts_at, ends_at)
                SELECT doctor_b, start_b, start_b + INTERVAL '30 minutes'
                FROM identities, times
                RETURNING id, doctor_id, starts_at, ends_at
            ),
            appointment_a AS (
                INSERT INTO appointments
                    (slot_id, patient_user_id, doctor_id, starts_at, ends_at, status)
                SELECT slot_a.id, identities.patient_a, slot_a.doctor_id,
                       slot_a.starts_at, slot_a.ends_at, 'scheduled'
                FROM slot_a CROSS JOIN identities
                RETURNING id
            ),
            appointment_b AS (
                INSERT INTO appointments
                    (slot_id, patient_user_id, doctor_id, starts_at, ends_at, status)
                SELECT slot_b.id, identities.patient_b, slot_b.doctor_id,
                       slot_b.starts_at, slot_b.ends_at, 'scheduled'
                FROM slot_b CROSS JOIN identities
                RETURNING id
            ),
            note_a AS (
                INSERT INTO visit_notes (appointment_id, doctor_id, patient_user_id, body)
                SELECT appointment_a.id, identities.doctor_a, identities.patient_a,
                       'week8-rls-boundary-patient-a'
                FROM appointment_a CROSS JOIN identities
                RETURNING id, appointment_id
            ),
            note_b AS (
                INSERT INTO visit_notes (appointment_id, doctor_id, patient_user_id, body)
                SELECT appointment_b.id, identities.doctor_b, identities.patient_b,
                       'week8-rls-boundary-patient-b'
                FROM appointment_b CROSS JOIN identities
                RETURNING id, appointment_id
            ),
            prescription_a AS (
                INSERT INTO prescriptions (appointment_id, doctor_id, patient_user_id, body)
                SELECT note_a.appointment_id, identities.doctor_a, identities.patient_a,
                       'week8-rls-boundary-prescription-a'
                FROM note_a CROSS JOIN identities
                RETURNING id
            ),
            prescription_b AS (
                INSERT INTO prescriptions (appointment_id, doctor_id, patient_user_id, body)
                SELECT note_b.appointment_id, identities.doctor_b, identities.patient_b,
                       'week8-rls-boundary-prescription-b'
                FROM note_b CROSS JOIN identities
                RETURNING id
            )
            SELECT appointment_a.id, appointment_b.id,
                   (SELECT id FROM note_a), (SELECT id FROM note_b),
                   (SELECT id FROM prescription_a), (SELECT id FROM prescription_b),
                   (SELECT id FROM slot_a), (SELECT id FROM slot_b),
                   (SELECT id FROM slot_c),
                   identities.patient_a, identities.patient_b
            FROM appointment_a CROSS JOIN appointment_b
            CROSS JOIN prescription_a CROSS JOIN prescription_b
            CROSS JOIN identities;
            """,
        ],
    )
    (
        appointment_a,
        appointment_b,
        note_a,
        note_b,
        prescription_a,
        prescription_b,
        slot_a,
        slot_b,
        slot_c,
        patient_a_id,
        patient_b_id,
    ) = map(int, fixture.split("|"))

    api_script = '''
import json
import psycopg2
from db import db, db_as

def get_user(email):
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, email, role FROM users WHERE email = %s", (email,))
            row = cur.fetchone()
            return {"id": row[0], "email": row[1], "role": row[2]}
    finally:
        conn.close()

patient_a = get_user("pat@clinic.local")
patient_b = get_user("pat2@clinic.local")
doctor = get_user("doc@clinic.local")
doctor_b = get_user("doc2@clinic.local")
admin = get_user("admin@clinic.local")
registrar = get_user("reg@clinic.local")

conn = db()
try:
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM doctors WHERE user_id = %s", (doctor["id"],))
        doctor_id = cur.fetchone()[0]
        cur.execute("SELECT id FROM doctors WHERE user_id = %s", (doctor_b["id"],))
        doctor_b_id = cur.fetchone()[0]
finally:
    conn.close()

conn = db_as(patient_a)
try:
    with conn.cursor() as cur:
        cur.execute("SELECT id, patient_user_id FROM appointments")
        patient_appointments = cur.fetchall()
        cur.execute("SELECT id, patient_user_id FROM visit_notes")
        patient_notes = cur.fetchall()
        cur.execute("SELECT id, patient_user_id FROM prescriptions")
        patient_prescriptions = cur.fetchall()
        cur.execute("SELECT public.scheduled_slot_is_taken(%s)", (__SLOT_B_ID__,))
        other_patient_slot_taken = cur.fetchone()[0]
finally:
    conn.close()

conn = db()
try:
    with conn.cursor() as cur:
        try:
            cur.execute("SELECT * FROM appointments")
        except psycopg2.errors.InsufficientPrivilege:
            api_access_denied = True
        else:
            api_access_denied = False
finally:
    conn.close()

conn = db_as(doctor)
try:
    with conn.cursor() as cur:
        cur.execute("SELECT id, doctor_id FROM visit_notes")
        doctor_notes = cur.fetchall()
        cur.execute("SELECT id, doctor_id FROM prescriptions")
        doctor_prescriptions = cur.fetchall()
        cur.execute(
            "SELECT id, doctor_id FROM slots WHERE id IN (%s, %s) ORDER BY id",
            (__SLOT_A_ID__, __SLOT_B_ID__),
        )
        doctor_slots = cur.fetchall()
finally:
    conn.close()

def doctor_cannot_insert_time_off(user, target_doctor_id):
    conn = db_as(user)
    try:
        with conn.cursor() as cur:
            try:
                cur.execute(
                    """
                    INSERT INTO time_off (doctor_id, starts_on, ends_on)
                    VALUES (%s, CURRENT_DATE + 400, CURRENT_DATE + 400)
                    """,
                    (target_doctor_id,),
                )
            except psycopg2.errors.InsufficientPrivilege:
                return True
            return False
    finally:
        conn.rollback()
        conn.close()

doctor_cannot_edit_schedule = doctor_cannot_insert_time_off(doctor, doctor_id)

def doctor_cannot_request_other_doctor_time_off(user, target_doctor_id):
    conn = db_as(user)
    try:
        with conn.cursor() as cur:
            try:
                cur.execute(
                    """
                    INSERT INTO time_off_requests
                        (doctor_id, starts_on, ends_on, comment)
                    VALUES (%s, CURRENT_DATE + 400, CURRENT_DATE + 400,
                            'rls-boundary-other-doctor')
                    """,
                    (target_doctor_id,),
                )
            except psycopg2.errors.InsufficientPrivilege:
                return True
            return False
    finally:
        conn.rollback()
        conn.close()

doctor_cannot_request_for_other = doctor_cannot_request_other_doctor_time_off(
    doctor, doctor_b_id
)

def body_denied(user):
    conn = db_as(user)
    try:
        with conn.cursor() as cur:
            try:
                cur.execute("SELECT body FROM visit_notes")
            except psycopg2.errors.InsufficientPrivilege:
                return "permission denied"
            return cur.fetchall()
    finally:
        conn.close()

registrar_body_result = body_denied(registrar)
admin_body_result = body_denied(admin)

def prescription_body_denied(user):
    conn = db_as(user)
    try:
        with conn.cursor() as cur:
            try:
                cur.execute("SELECT body FROM prescriptions")
            except psycopg2.errors.InsufficientPrivilege:
                return "permission denied"
            return cur.fetchall()
    finally:
        conn.close()

registrar_prescription_body_result = prescription_body_denied(registrar)
admin_prescription_body_result = prescription_body_denied(admin)

def audit_select_denied(user):
    conn = db_as(user)
    try:
        with conn.cursor() as cur:
            try:
                cur.execute("SELECT id FROM audit_events")
            except psycopg2.errors.InsufficientPrivilege:
                return True
            return False
    finally:
        conn.close()

patient_audit_select_denied = audit_select_denied(patient_a)
registrar_audit_select_denied = audit_select_denied(registrar)

def patient_insert(sql, params):
    conn = db_as(patient_a)
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            inserted = cur.fetchone()
        conn.rollback()
        return inserted is not None
    except psycopg2.errors.InsufficientPrivilege:
        conn.rollback()
        return False
    finally:
        conn.close()

conn = db_as(patient_a)
try:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT public.current_patient_is_active(),
                   public.doctor_is_active(%s),
                   public.is_valid_free_slot(
                       s.id, s.doctor_id, s.starts_at,
                       s.starts_at + make_interval(mins => s.duration_minutes),
                       s.ends_at
                   )
            FROM slots s
            WHERE s.id = %s
            """,
            (doctor_id, __FREE_SLOT_ID__),
        )
        free_slot_checks = cur.fetchone()
finally:
    conn.close()

valid_free_slot_insert_allowed = patient_insert(
    """
    INSERT INTO appointments (slot_id, patient_user_id, doctor_id, starts_at, ends_at)
    SELECT id, %s, doctor_id, starts_at, ends_at FROM slots WHERE id = %s
    RETURNING id
    """,
    (patient_a["id"], __FREE_SLOT_ID__),
)
spoofed_slot_insert_allowed = patient_insert(
    """
    INSERT INTO appointments (slot_id, patient_user_id, doctor_id, starts_at, ends_at)
    SELECT id, %s, %s, starts_at, ends_at FROM slots WHERE id = %s
    RETURNING id
    """,
    (patient_a["id"], doctor_b_id, __FREE_SLOT_ID__),
)
occupied_slot_insert_allowed = patient_insert(
    """
    INSERT INTO appointments (slot_id, patient_user_id, doctor_id, starts_at, ends_at)
    SELECT id, %s, doctor_id, starts_at, ends_at FROM slots WHERE id = %s
    RETURNING id
    """,
    (patient_a["id"], __SLOT_B_ID__),
)

conn = db_as(patient_a)
try:
    with conn.cursor() as cur:
        try:
            cur.execute("UPDATE appointments SET status='done' WHERE id=%s", (__APPOINTMENT_A_ID__,))
        except (psycopg2.errors.InsufficientPrivilege, psycopg2.errors.CheckViolation):
            arbitrary_status_denied = True
        else:
            arbitrary_status_denied = False
finally:
    conn.rollback()
    conn.close()

conn = db_as(patient_a)
try:
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE appointments SET status='cancelled' WHERE id=%s",
            (__APPOINTMENT_A_ID__,),
        )
        patient_cancelled = cur.rowcount
        cur.execute(
            "UPDATE appointments SET status='scheduled' WHERE id=%s",
            (__APPOINTMENT_A_ID__,),
        )
        patient_restored = cur.rowcount
finally:
    conn.rollback()
    conn.close()

conn = db_as(doctor)
try:
    with conn.cursor() as cur:
        try:
            cur.execute("SELECT email FROM users")
        except psycopg2.errors.InsufficientPrivilege:
            direct_email_denied = True
        else:
            direct_email_denied = False
finally:
    conn.close()

conn = db_as(doctor)
try:
    with conn.cursor() as cur:
        cur.execute("SELECT email FROM doctor_patients(%s)", (doctor["id"],))
        doctor_patient_emails = [row[0] for row in cur.fetchall()]
finally:
    conn.close()

def guest_insert_denied(email, role, blocked):
    guest = {"id": 0, "role": "guest"}
    conn = db_as(guest)
    try:
        with conn.cursor() as cur:
            try:
                cur.execute(
                    """
                    INSERT INTO users (email, password_hash, role, blocked)
                    VALUES (%s, 'not-a-real-hash', %s, %s)
                    """,
                    (email, role, blocked),
                )
            except psycopg2.errors.InsufficientPrivilege:
                return True
            return False
    finally:
        conn.rollback()
        conn.close()

guest_admin_insert_denied = guest_insert_denied(
    "rls-forbidden-admin@clinic.local", "admin", False
)
guest_blocked_patient_insert_denied = guest_insert_denied(
    "rls-forbidden-blocked-patient@clinic.local", "patient", True
)

print(json.dumps({
    "patient_appointments": patient_appointments,
    "patient_notes": patient_notes,
    "patient_prescriptions": patient_prescriptions,
    "doctor_notes": doctor_notes,
    "doctor_prescriptions": doctor_prescriptions,
    "doctor_slots": doctor_slots,
    "doctor_id": doctor_id,
    "doctor_b_id": doctor_b_id,
    "doctor_cannot_edit_schedule": doctor_cannot_edit_schedule,
    "doctor_cannot_request_for_other": doctor_cannot_request_for_other,
    "patient_a_id": patient_a["id"],
    "patient_b_id": patient_b["id"],
    "api_access_denied": api_access_denied,
    "registrar_body_result": registrar_body_result,
    "admin_body_result": admin_body_result,
    "registrar_prescription_body_result": registrar_prescription_body_result,
    "admin_prescription_body_result": admin_prescription_body_result,
    "patient_audit_select_denied": patient_audit_select_denied,
    "registrar_audit_select_denied": registrar_audit_select_denied,
    "other_patient_slot_taken": other_patient_slot_taken,
    "valid_free_slot_insert_allowed": valid_free_slot_insert_allowed,
    "free_slot_checks": free_slot_checks,
    "spoofed_slot_insert_allowed": spoofed_slot_insert_allowed,
    "occupied_slot_insert_allowed": occupied_slot_insert_allowed,
    "arbitrary_status_denied": arbitrary_status_denied,
    "patient_cancelled": patient_cancelled,
    "patient_restored": patient_restored,
    "direct_email_denied": direct_email_denied,
    "doctor_patient_emails": doctor_patient_emails,
    "guest_admin_insert_denied": guest_admin_insert_denied,
    "guest_blocked_patient_insert_denied": guest_blocked_patient_insert_denied,
}))
'''
    api_script = (
        api_script.replace("__SLOT_B_ID__", str(slot_b))
        .replace("__FREE_SLOT_ID__", str(slot_c))
        .replace("__APPOINTMENT_A_ID__", str(appointment_a))
        .replace("__SLOT_A_ID__", str(slot_a))
    )

    try:
        result = json.loads(compose_exec("api", ["python", "-"], input_text=api_script))
        assert result["patient_a_id"] == patient_a_id
        assert result["patient_b_id"] == patient_b_id
        assert [appointment_a, patient_a_id] in result["patient_appointments"]
        assert [note_a, patient_a_id] in result["patient_notes"]
        assert [prescription_a, patient_a_id] in result["patient_prescriptions"]
        assert all(patient_id == patient_a_id for _, patient_id in result["patient_appointments"])
        assert all(patient_id == patient_a_id for _, patient_id in result["patient_notes"])
        assert all(patient_id == patient_a_id for _, patient_id in result["patient_prescriptions"])
        assert all(row_id != appointment_b for row_id, _ in result["patient_appointments"])
        assert all(row_id != note_b for row_id, _ in result["patient_notes"])
        assert all(row_id != prescription_b for row_id, _ in result["patient_prescriptions"])
        assert result["doctor_notes"]
        assert all(doctor_id == result["doctor_id"] for _, doctor_id in result["doctor_notes"])
        assert note_a in [row_id for row_id, _ in result["doctor_notes"]]
        assert note_b not in [row_id for row_id, _ in result["doctor_notes"]]
        assert prescription_a in [row_id for row_id, _ in result["doctor_prescriptions"]]
        assert prescription_b not in [row_id for row_id, _ in result["doctor_prescriptions"]]
        assert all(
            doctor_id == result["doctor_id"]
            for _, doctor_id in result["doctor_prescriptions"]
        )
        assert [slot_a, result["doctor_id"]] in result["doctor_slots"]
        assert all(doctor_id == result["doctor_id"] for _, doctor_id in result["doctor_slots"])
        assert all(slot_id != slot_b for slot_id, _ in result["doctor_slots"])
        assert result["doctor_cannot_edit_schedule"] is True
        assert result["doctor_cannot_request_for_other"] is True
        assert result["api_access_denied"] is True
        assert result["registrar_body_result"] in ("permission denied", [])
        assert result["admin_body_result"] in ("permission denied", [])
        assert result["registrar_prescription_body_result"] in ("permission denied", [])
        assert result["admin_prescription_body_result"] in ("permission denied", [])
        assert result["patient_audit_select_denied"] is True
        assert result["registrar_audit_select_denied"] is True
        assert result["other_patient_slot_taken"] is True
        assert result["free_slot_checks"] == [True, True, True], result["free_slot_checks"]
        assert result["valid_free_slot_insert_allowed"] is True, result
        assert result["spoofed_slot_insert_allowed"] is False
        assert result["occupied_slot_insert_allowed"] is False
        assert result["arbitrary_status_denied"] is True
        assert result["patient_cancelled"] == 1
        assert result["patient_restored"] == 0
        assert result["direct_email_denied"] is True
        assert result["guest_admin_insert_denied"] is True
        assert result["guest_blocked_patient_insert_denied"] is True
        assert PATIENT_A in result["doctor_patient_emails"]

        with CsrfClient(base_url=TEST_BASE, follow_redirects=True, timeout=10.0) as client:
            login = client.post(
                "/login",
                data={"email": PATIENT_A, "password": "password123"},
            )
            assert login.status_code == 200
            page = client.get(f"/doctors/{result['doctor_b_id']}/slots")
            assert page.status_code == 200
            assert f'action="/slots/{slot_b}/book"' not in page.text
            assert "Unavailable" in page.text

        compose_exec(
            "db",
            [
                "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
                "-U", "clinic", "-d", "clinic", "-c",
                f"UPDATE users SET blocked=TRUE WHERE id={patient_a_id}",
            ],
        )
        blocked_script = '''
import json
import psycopg2
from db import db, db_as

conn = db()
try:
    with conn.cursor() as cur:
        cur.execute("SELECT id, role FROM users WHERE email=%s", ("pat@clinic.local",))
        row = cur.fetchone()
        patient = {"id": row[0], "role": row[1]}
        cur.execute("SELECT id, role FROM users WHERE email=%s", ("reg@clinic.local",))
        row = cur.fetchone()
        registrar = {"id": row[0], "role": row[1]}
finally:
    conn.close()

def blocked_patient_insert_denied_as(user, patient_id):
    conn = db_as(user)
    try:
        with conn.cursor() as cur:
            try:
                cur.execute(
                    """
                    INSERT INTO appointments (slot_id, patient_user_id, doctor_id, starts_at, ends_at)
                    SELECT id, %s, doctor_id, starts_at, ends_at
                    FROM slots WHERE id = __FREE_SLOT_ID__
                    """,
                    (patient_id,),
                )
            except psycopg2.errors.InsufficientPrivilege:
                return True
            return False
    finally:
        conn.rollback()
        conn.close()

blocked_insert_denied = blocked_patient_insert_denied_as(patient, patient["id"])
registrar_blocked_insert_denied = blocked_patient_insert_denied_as(
    registrar, patient["id"]
)

print(json.dumps({
    "blocked_insert_denied": blocked_insert_denied,
    "registrar_blocked_insert_denied": registrar_blocked_insert_denied,
}))
'''.replace("__FREE_SLOT_ID__", str(slot_c))
        try:
            blocked_result = json.loads(
                compose_exec("api", ["python", "-"], input_text=blocked_script)
            )
        finally:
            compose_exec(
                "db",
                [
                    "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
                    "-U", "clinic", "-d", "clinic", "-c",
                    f"UPDATE users SET blocked=FALSE WHERE id={patient_a_id}",
                ],
            )
        assert blocked_result["blocked_insert_denied"] is True
        assert blocked_result["registrar_blocked_insert_denied"] is True

        report = [
            "Regression: unfiltered SELECTs under app roles",
            "Context: db_as() sets SET LOCAL ROLE and app.user_id in one transaction.",
            "Patient SQL: SELECT id, patient_user_id FROM appointments;",
            f"Patient result: {result['patient_appointments']}",
            "Patient SQL: SELECT id, patient_user_id FROM visit_notes;",
            f"Patient result: {result['patient_notes']}",
            "Patient SQL: SELECT id, patient_user_id FROM prescriptions;",
            f"Patient result: {result['patient_prescriptions']}",
            "Doctor SQL: SELECT id, doctor_id FROM visit_notes;",
            f"Doctor result: {result['doctor_notes']}",
            "Doctor SQL: SELECT id, doctor_id FROM prescriptions;",
            f"Doctor result: {result['doctor_prescriptions']}",
            "Doctor SQL: SELECT id, doctor_id FROM slots;",
            f"Doctor result: {result['doctor_slots']}",
            f"Doctor time-off/schedule writes denied: {result['doctor_cannot_edit_schedule']}, {result['doctor_cannot_request_for_other']}",
            f"Guest admin-role INSERT denied: {result['guest_admin_insert_denied']}",
            f"Guest blocked-patient INSERT denied: {result['guest_blocked_patient_insert_denied']}",
            "Registrar SQL: SELECT body FROM visit_notes;",
            f"Registrar result: {result['registrar_body_result']}",
            "Registrar SQL: SELECT body FROM prescriptions;",
            f"Registrar result: {result['registrar_prescription_body_result']}",
            "Admin SQL: SELECT body FROM visit_notes;",
            f"Admin result: {result['admin_body_result']}",
            "Admin SQL: SELECT body FROM prescriptions;",
            f"Admin result: {result['admin_prescription_body_result']}",
            f"Patient/registrar audit SELECT denied: {result['patient_audit_select_denied']}, {result['registrar_audit_select_denied']}",
            f"Patient sees another patient's slot as taken: {result['other_patient_slot_taken']}",
            f"Valid free-slot insert accepted: {result['valid_free_slot_insert_allowed']}",
            f"Spoofed and occupied-slot inserts accepted: {result['spoofed_slot_insert_allowed']}, {result['occupied_slot_insert_allowed']}",
            f"Arbitrary status denied: {result['arbitrary_status_denied']}",
            f"Patient cancel/restore rowcounts: {result['patient_cancelled']}, {result['patient_restored']}",
            f"Blocked patient's insert denied: {blocked_result['blocked_insert_denied']}",
            f"Registrar insert for blocked patient denied: {blocked_result['registrar_blocked_insert_denied']}",
            "Patient page: booked slot renders unavailable without a booking action.",
        ]
        (ROOT / "experiments" / "rls_boundary_output.txt").write_text(
            "\n".join(report) + "\n",
            encoding="utf-8",
        )
    finally:
        compose_exec(
            "db",
            [
                "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
                "-U", "clinic", "-d", "clinic", "-c",
                f"""
                DELETE FROM prescriptions WHERE appointment_id IN ({appointment_a}, {appointment_b});
                DELETE FROM visit_notes WHERE appointment_id IN ({appointment_a}, {appointment_b});
                DELETE FROM appointments WHERE id IN ({appointment_a}, {appointment_b});
                DELETE FROM appointments WHERE slot_id = {slot_c};
                DELETE FROM slots WHERE id IN ({slot_a}, {slot_b}, {slot_c});
                """,
            ],
        )
