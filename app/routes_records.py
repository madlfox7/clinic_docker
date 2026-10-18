from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from db import (
    MAX_RECORD_BODY_LENGTH,
    db_as,
    parse_strict_int,
    record_audit_event,
    templates,
    within_length,
)
from routes_auth import require_user


router = APIRouter()


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
        SELECT a.id, dp.email, d.full_name, s.starts_at, s.ends_at, a.status
        FROM appointments a
        JOIN slots s ON s.id = a.slot_id
        JOIN doctors d ON d.id = a.doctor_id
        JOIN public.doctor_patients(%s) dp ON dp.id = a.patient_user_id
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
        SELECT id, body FROM visit_notes
        WHERE appointment_id = %s
        ORDER BY id
        """,
        (appointment_id,),
    )
    notes = [{"id": row[0], "body": row[1]} for row in cur.fetchall()]
    cur.execute(
        """
        SELECT body FROM prescriptions
        WHERE appointment_id = %s
        ORDER BY id
        """,
        (appointment_id,),
    )
    prescriptions = [row[0] for row in cur.fetchall()]
    record_audit_event(cur, "medical.records.view", "appointment", appointment_id)
    conn.commit()
    cur.close()
    conn.close()

    return templates.TemplateResponse(
        "doctor_records.html",
        {
            "request": request,
            "role": user["role"],
            "appointment": {
                "id": appointment[0],
                "patient_email": appointment[1],
                "doctor_name": appointment[2],
                "starts_at": appointment[3],
                "ends_at": appointment[4],
                "status": appointment[5],
            },
            "can_edit": appointment[5] == "scheduled",
            "notes": notes,
            "prescriptions": prescriptions,
            "saved": request.query_params.get("saved"),
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

    record_type = record_type.strip().lower()
    body = body.strip()
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
    if record_type == "note":
        cur.execute(
            """
            INSERT INTO visit_notes (appointment_id, doctor_id, patient_user_id, body)
            SELECT a.id, d.id, a.patient_user_id, %s
            FROM appointments a
            JOIN doctors d ON d.id = a.doctor_id
            WHERE a.id = %s
              AND d.user_id = %s
              AND a.status = 'scheduled'
              AND a.starts_at > CURRENT_TIMESTAMP - INTERVAL '12 months'
            """,
            (body, appointment_id, user["id"]),
        )
        action = "medical.note.save"
    else:
        cur.execute(
            """
            INSERT INTO prescriptions (appointment_id, doctor_id, patient_user_id, body)
            SELECT a.id, d.id, a.patient_user_id, %s
            FROM appointments a
            JOIN doctors d ON d.id = a.doctor_id
            WHERE a.id = %s
              AND d.user_id = %s
              AND a.status = 'scheduled'
              AND a.starts_at > CURRENT_TIMESTAMP - INTERVAL '12 months'
            """,
            (body, appointment_id, user["id"]),
        )
        action = "medical.prescription.add"

    if cur.rowcount != 1:
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


@router.get("/my/records")
def patient_records(request: Request):
    user, denied = require_user(request, "patient")
    if denied:
        return denied

    conn = db_as(user)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT record_type, body, doctor_name, starts_at, appointment_id
        FROM (
          SELECT 'Clinical note'::text AS record_type, n.body,
                 d.full_name AS doctor_name, s.starts_at, a.id AS appointment_id
          FROM visit_notes n
          JOIN appointments a ON a.id = n.appointment_id
          JOIN slots s ON s.id = a.slot_id
          JOIN doctors d ON d.id = a.doctor_id
          UNION ALL
          SELECT 'Prescription'::text AS record_type, p.body,
                 d.full_name AS doctor_name, s.starts_at, a.id AS appointment_id
          FROM prescriptions p
          JOIN appointments a ON a.id = p.appointment_id
          JOIN slots s ON s.id = a.slot_id
          JOIN doctors d ON d.id = a.doctor_id
        ) AS records
        ORDER BY starts_at DESC, appointment_id DESC, record_type
        """
    )
    records = [
        {
            "record_type": row[0],
            "body": row[1],
            "doctor_name": row[2],
            "starts_at": row[3],
            "appointment_id": row[4],
        }
        for row in cur.fetchall()
    ]
    record_audit_event(cur, "medical.records.view", "patient", user["id"])
    conn.commit()
    cur.close()
    conn.close()
    return templates.TemplateResponse(
        "my_records.html",
        {"request": request, "role": user["role"], "records": records},
    )
