import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PATIENT_A = "pat@clinic.local"
DOCTOR = "doc@clinic.local"
ADMIN = "admin@clinic.local"
REGISTRAR = "reg@clinic.local"


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


def test_rls_boundary_for_app_roles():
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
                SELECT clock_timestamp() + INTERVAL '30 days' AS start_a,
                       clock_timestamp() + INTERVAL '30 days 2 hours' AS start_b
            ),
            slot_a AS (
                INSERT INTO slots (doctor_id, starts_at, ends_at)
                SELECT doctor_a, start_a, start_a + INTERVAL '30 minutes'
                FROM identities, times
                RETURNING id, doctor_id, starts_at, ends_at
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
                   (SELECT id FROM slot_a), (SELECT id FROM slot_b),
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
        slot_a,
        slot_b,
        patient_a_id,
        patient_b_id,
    ) = map(int, fixture.split("|"))

    api_script = """
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
admin = get_user("admin@clinic.local")
registrar = get_user("reg@clinic.local")

conn = db()
try:
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM doctors WHERE user_id = %s", (doctor["id"],))
        doctor_id = cur.fetchone()[0]
finally:
    conn.close()

conn = db_as(patient_a)
try:
    with conn.cursor() as cur:
        cur.execute("SELECT id, patient_user_id FROM appointments")
        patient_appointments = cur.fetchall()
        cur.execute("SELECT id, patient_user_id FROM visit_notes")
        patient_notes = cur.fetchall()
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
finally:
    conn.close()

def body_denied(user):
    conn = db_as(user)
    try:
        with conn.cursor() as cur:
            try:
                cur.execute("SELECT body FROM visit_notes")
            except psycopg2.errors.InsufficientPrivilege:
                return True
            return False
    finally:
        conn.close()

registrar_body_denied = body_denied(registrar)
admin_body_denied = body_denied(admin)

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

print(json.dumps({
    "patient_appointments": patient_appointments,
    "patient_notes": patient_notes,
    "doctor_notes": doctor_notes,
    "doctor_id": doctor_id,
    "patient_a_id": patient_a["id"],
    "patient_b_id": patient_b["id"],
    "api_access_denied": api_access_denied,
    "registrar_body_denied": registrar_body_denied,
    "admin_body_denied": admin_body_denied,
    "direct_email_denied": direct_email_denied,
    "doctor_patient_emails": doctor_patient_emails,
}))
"""

    try:
        result = json.loads(compose_exec("api", ["python", "-"], input_text=api_script))
        assert result["patient_a_id"] == patient_a_id
        assert result["patient_b_id"] == patient_b_id
        assert [appointment_a, patient_a_id] in result["patient_appointments"]
        assert [note_a, patient_a_id] in result["patient_notes"]
        assert all(patient_id == patient_a_id for _, patient_id in result["patient_appointments"])
        assert all(patient_id == patient_a_id for _, patient_id in result["patient_notes"])
        assert all(row_id != appointment_b for row_id, _ in result["patient_appointments"])
        assert all(row_id != note_b for row_id, _ in result["patient_notes"])
        assert result["doctor_notes"]
        assert all(doctor_id == result["doctor_id"] for _, doctor_id in result["doctor_notes"])
        assert note_a in [row_id for row_id, _ in result["doctor_notes"]]
        assert note_b not in [row_id for row_id, _ in result["doctor_notes"]]
        assert result["api_access_denied"] is True
        assert result["registrar_body_denied"] is True
        assert result["admin_body_denied"] is True
        assert result["direct_email_denied"] is True
        assert PATIENT_A in result["doctor_patient_emails"]
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
                DELETE FROM slots WHERE id IN ({slot_a}, {slot_b});
                """,
            ],
        )
