import psycopg2.errors
from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from db import (
    MAX_RECORD_BODY_LENGTH,
    contains_nul,
    db_as,
    parse_strict_int,
    record_audit_event,
    strip_control_chars,
    templates,
    within_length,
)
from field_crypto import decrypt_body, encrypt_body
from routes_auth import require_user


router = APIRouter()


@router.get("/doctor/patients")
def doctor_patients(request: Request):
    user, denied = require_user(request, "doctor")
    if denied:
        return denied

    conn = db_as(user)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT dp.id, dp.email, dp.blocked, dv.full_name,
               COUNT(a.id) AS visit_count,
               COUNT(a.id) FILTER (
                   WHERE a.status = 'scheduled' AND a.starts_at > CURRENT_TIMESTAMP
               ) AS upcoming_count,
               MIN(a.starts_at) FILTER (
                   WHERE a.status = 'scheduled' AND a.starts_at > CURRENT_TIMESTAMP
               ) AS next_visit,
               MAX(a.starts_at) FILTER (
                   WHERE a.starts_at <= CURRENT_TIMESTAMP
               ) AS last_visit
        FROM public.doctor_patients(%s) dp
        LEFT JOIN public.doctor_visit_patients(%s) dv ON dv.id = dp.id
        JOIN appointments a ON a.patient_user_id = dp.id
        JOIN doctors d ON d.id = a.doctor_id
        WHERE d.user_id = %s
        GROUP BY dp.id, dp.email, dp.blocked, dv.full_name
        ORDER BY MAX(a.starts_at) DESC, lower(dp.email), dp.id
        """,
        (user["id"], user["id"], user["id"]),
    )
    patients = [
        {
            "id": row[0],
            "email": row[1],
            "blocked": row[2],
            "full_name": row[3],
            "visit_count": row[4],
            "upcoming_count": row[5],
            "next_visit": row[6],
            "last_visit": row[7],
        }
        for row in cur.fetchall()
    ]
    cur.close()
    conn.close()
    return templates.TemplateResponse(
        request,
        "doctor_patients.html",
        {
            "request": request,
            "role": user["role"],
            "patients": patients,
            "error": request.query_params.get("error"),
        },
    )


@router.get("/doctor/patients/{patient_id}")
def doctor_patient_history(request: Request, patient_id: str):
    user, denied = require_user(request, "doctor")
    if denied:
        return denied
    patient_id = parse_strict_int(patient_id, min_value=1)
    if patient_id is None:
        return RedirectResponse(
            "/doctor/patients?error=patient_unavailable", status_code=303
        )

    conn = db_as(user)
    cur = conn.cursor()
    cur.execute(
        "SELECT id, full_name FROM doctors WHERE user_id = %s",
        (user["id"],),
    )
    doctor = cur.fetchone()
    if doctor is None:
        cur.close()
        conn.close()
        return RedirectResponse("/me?error=doctor_profile_missing", status_code=303)

    cur.execute(
        """
        SELECT dp.id, dp.email, dp.blocked, dv.full_name, dv.phone
        FROM public.doctor_patients(%s) dp
        LEFT JOIN public.doctor_visit_patients(%s) dv ON dv.id = dp.id
        WHERE dp.id = %s
        """,
        (user["id"], user["id"], patient_id),
    )
    patient = cur.fetchone()
    if patient is None:
        cur.close()
        conn.close()
        return RedirectResponse(
            "/doctor/patients?error=patient_unavailable", status_code=303
        )

    cur.execute(
        """
        SELECT a.id, svc.name, a.starts_at, a.ends_at, a.status,
               a.starts_at > CURRENT_TIMESTAMP - INTERVAL '12 months'
        FROM appointments a
        JOIN slots s ON s.id = a.slot_id
        JOIN services svc ON svc.id = s.service_id
        WHERE a.doctor_id = %s
          AND a.patient_user_id = %s
        ORDER BY a.starts_at DESC, a.id DESC
        """,
        (doctor[0], patient_id),
    )
    visits = [
        {
            "id": row[0],
            "service_name": row[1],
            "starts_at": row[2],
            "ends_at": row[3],
            "status": row[4],
            "records_available": row[5],
            "notes": [],
            "prescriptions": [],
        }
        for row in cur.fetchall()
    ]
    visits_by_id = {visit["id"]: visit for visit in visits}

    cur.execute(
        """
        SELECT id, appointment_id, body
        FROM visit_notes
        WHERE doctor_id = %s AND patient_user_id = %s
        ORDER BY appointment_id DESC, id
        """,
        (doctor[0], patient_id),
    )
    for record_id, appointment_id, body in cur.fetchall():
        visit = visits_by_id.get(appointment_id)
        if visit is not None:
            visit["notes"].append((record_id, appointment_id, body))

    cur.execute(
        """
        SELECT id, appointment_id, body
        FROM prescriptions
        WHERE doctor_id = %s AND patient_user_id = %s
        ORDER BY appointment_id DESC, id
        """,
        (doctor[0], patient_id),
    )
    for record_id, appointment_id, body in cur.fetchall():
        visit = visits_by_id.get(appointment_id)
        if visit is not None:
            visit["prescriptions"].append((record_id, appointment_id, body))

    record_audit_event(cur, "medical.patient_history.view", "patient", patient_id)
    conn.commit()
    cur.close()
    conn.close()

    for visit in visits:
        visit["notes"] = [decrypt_body("visit_notes", *row) for row in visit["notes"]]
        visit["prescriptions"] = [
            decrypt_body("prescriptions", *row) for row in visit["prescriptions"]
        ]

    return templates.TemplateResponse(
        request,
        "doctor_patient_history.html",
        {
            "request": request,
            "role": user["role"],
            "doctor_name": doctor[1],
            "patient": {
                "id": patient[0],
                "email": patient[1],
                "blocked": patient[2],
                "full_name": patient[3],
                "phone": patient[4],
            },
            "visits": visits,
        },
    )


@router.get("/doctor/appointments/{appointment_id}/records")
def doctor_records(request: Request, appointment_id: str):
    user, denied = require_user(request, "doctor")
    if denied:
        return denied
    appointment_id = parse_strict_int(appointment_id, min_value=1)
    if appointment_id is None:
        return RedirectResponse(
            "/doctor/appointments?error=record_unavailable", status_code=303
        )

    conn = db_as(user)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT a.id, dp.email, d.full_name, a.starts_at, a.ends_at, a.status,
               a.starts_at <= CURRENT_TIMESTAMP AS started, dp.full_name
        FROM appointments a
        JOIN doctors d ON d.id = a.doctor_id
        JOIN public.doctor_visit_patients(%s) dp ON dp.id = a.patient_user_id
        WHERE a.id = %s
          AND d.user_id = %s
        """,
        (user["id"], appointment_id, user["id"]),
    )
    appointment = cur.fetchone()
    if not appointment:
        cur.close()
        conn.close()
        return RedirectResponse(
            "/doctor/appointments?error=record_unavailable", status_code=303
        )

    cur.execute(
        """
        SELECT id, appointment_id, body FROM visit_notes
        WHERE appointment_id = %s
        ORDER BY id
        """,
        (appointment_id,),
    )
    notes = [
        {"id": row[0], "appointment_id": row[1], "body": row[2]} for row in cur.fetchall()
    ]
    cur.execute(
        """
        SELECT id, appointment_id, body FROM prescriptions
        WHERE appointment_id = %s
        ORDER BY id
        """,
        (appointment_id,),
    )
    prescriptions = cur.fetchall()
    record_audit_event(cur, "medical.records.view", "appointment", appointment_id)
    conn.commit()
    cur.close()
    conn.close()
    for note in notes:
        note["body"] = decrypt_body(
            "visit_notes", note["id"], note.pop("appointment_id"), note["body"]
        )
    prescriptions = [decrypt_body("prescriptions", *row) for row in prescriptions]

    return templates.TemplateResponse(
        request,
        "doctor_records.html",
        {
            "request": request,
            "role": user["role"],
            "appointment": {
                "id": appointment[0],
                "patient_email": appointment[1],
                "patient_name": appointment[7],
                "doctor_name": appointment[2],
                "starts_at": appointment[3],
                "ends_at": appointment[4],
                "status": appointment[5],
            },
            "can_edit": appointment[5] in ("scheduled", "completed"),
            "can_complete": appointment[5] == "scheduled" and appointment[6],
            "notes": notes,
            "prescriptions": prescriptions,
            "saved": request.query_params.get("saved"),
            "completed": request.query_params.get("completed"),
            "error": request.query_params.get("error"),
        },
    )


@router.post("/doctor/appointments/{appointment_id}/records")
def save_doctor_record(
    request: Request,
    appointment_id: str,
    record_type: str = Form(...),
    body: str = Form(...),
):
    user, denied = require_user(request, "doctor")
    if denied:
        return denied
    appointment_id = parse_strict_int(appointment_id, min_value=1)
    if appointment_id is None:
        return RedirectResponse(
            "/doctor/appointments?error=record_unavailable", status_code=303
        )

    if contains_nul(record_type, body):
        return RedirectResponse(
            f"/doctor/appointments/{appointment_id}/records?error=invalid_text",
            status_code=303,
        )
    record_type = record_type.strip().lower()
    body = strip_control_chars(body).strip()
    if record_type not in ("note", "prescription"):
        return RedirectResponse(
            f"/doctor/appointments/{appointment_id}/records?error=invalid_type",
            status_code=303,
        )
    if not body:
        return RedirectResponse(
            f"/doctor/appointments/{appointment_id}/records?error=empty",
            status_code=303,
        )
    if len(body) > MAX_RECORD_BODY_LENGTH or not within_length(
        body, MAX_RECORD_BODY_LENGTH * 4
    ):
        return RedirectResponse(
            f"/doctor/appointments/{appointment_id}/records?error=too_long",
            status_code=303,
        )

    conn = db_as(user)
    cur = conn.cursor()
    # Only locate the doctor's own appointment; the RLS policies decide
    # whether a record may be written (scheduled or completed visit,
    # last 12 months).
    cur.execute(
        """
        SELECT a.id, a.doctor_id, a.patient_user_id
        FROM appointments a
        JOIN doctors d ON d.id = a.doctor_id
        WHERE a.id = %s
          AND d.user_id = %s
        """,
        (appointment_id, user["id"]),
    )
    appointment = cur.fetchone()
    table = "visit_notes" if record_type == "note" else "prescriptions"
    action = "medical.note.save" if record_type == "note" else "medical.prescription.add"
    saved = False
    if appointment is not None:
        try:
            # The packet is bound to the row id and appointment id, so take the
            # id from the sequence first, encrypt (after the plaintext length
            # check), then insert with that id. Only the packet reaches SQL.
            cur.execute("SELECT nextval(%s::regclass)", (f"public.{table}_id_seq",))
            record_id = cur.fetchone()[0]
            stored_body = encrypt_body(table, record_id, appointment[0], body)
            cur.execute(
                f"""
                INSERT INTO {table} (id, appointment_id, doctor_id, patient_user_id, body)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (record_id, appointment[0], appointment[1], appointment[2], stored_body),
            )
            saved = cur.rowcount == 1
        except psycopg2.errors.InsufficientPrivilege:
            saved = False

    if not saved:
        conn.rollback()
        cur.close()
        conn.close()
        return RedirectResponse(
            f"/doctor/appointments/{appointment_id}/records?error=record_unavailable",
            status_code=303,
        )

    record_audit_event(cur, action, "appointment", appointment_id)
    conn.commit()
    cur.close()
    conn.close()
    return RedirectResponse(
        f"/doctor/appointments/{appointment_id}/records?saved={record_type}",
        status_code=303,
    )


@router.post("/doctor/appointments/{appointment_id}/complete")
def complete_doctor_appointment(request: Request, appointment_id: str):
    user, denied = require_user(request, "doctor")
    if denied:
        return denied
    appointment_id = parse_strict_int(appointment_id, min_value=1)
    if appointment_id is None:
        return RedirectResponse(
            "/doctor/appointments?error=record_unavailable", status_code=303
        )

    conn = db_as(user)
    cur = conn.cursor()
    # RLS allows only the doctor's own started scheduled visit -> completed.
    try:
        cur.execute(
            "UPDATE appointments SET status = 'completed' WHERE id = %s",
            (appointment_id,),
        )
        done = cur.rowcount == 1
    except psycopg2.errors.InsufficientPrivilege:
        done = False
    if not done:
        conn.rollback()
        cur.close()
        conn.close()
        return RedirectResponse(
            f"/doctor/appointments/{appointment_id}/records?error=complete_unavailable",
            status_code=303,
        )
    record_audit_event(cur, "appointment.complete", "appointment", appointment_id)
    conn.commit()
    cur.close()
    conn.close()
    return RedirectResponse(
        f"/doctor/appointments/{appointment_id}/records?completed=1",
        status_code=303,
    )


@router.get("/my/records")
def patient_records(request: Request):
    user, denied = require_user(request, "patient")
    if denied:
        return denied

    conn = db_as(user)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT record_type, body, doctor_name, starts_at, appointment_id, record_id
        FROM (
          SELECT 'Clinical note'::text AS record_type, n.body, n.id AS record_id,
                 d.full_name AS doctor_name, a.starts_at, a.id AS appointment_id
          FROM visit_notes n
          JOIN appointments a ON a.id = n.appointment_id
          JOIN doctors d ON d.id = a.doctor_id
          UNION ALL
          SELECT 'Prescription'::text AS record_type, p.body, p.id AS record_id,
                 d.full_name AS doctor_name, a.starts_at, a.id AS appointment_id
          FROM prescriptions p
          JOIN appointments a ON a.id = p.appointment_id
          JOIN doctors d ON d.id = a.doctor_id
        ) AS records
        ORDER BY starts_at DESC, appointment_id DESC, record_type, record_id
        """
    )
    records = [
        {
            "record_type": row[0],
            "body": row[1],
            "doctor_name": row[2],
            "starts_at": row[3],
            "appointment_id": row[4],
            "record_id": row[5],
        }
        for row in cur.fetchall()
    ]
    record_audit_event(cur, "medical.records.view", "patient", user["id"])
    conn.commit()
    cur.close()
    conn.close()
    for record in records:
        table = "visit_notes" if record["record_type"] == "Clinical note" else "prescriptions"
        record["body"] = decrypt_body(
            table, record.pop("record_id"), record["appointment_id"], record["body"]
        )
    return templates.TemplateResponse(
        request,
        "my_records.html",
        {"request": request, "role": user["role"], "records": records},
    )
