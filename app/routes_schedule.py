from datetime import date, timedelta
from typing import Optional

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from db import MAX_TEXT_LENGTH, db_as, record_audit_event, templates, within_length
from routes_auth import require_user


router = APIRouter()


@router.get("/registrar/appointments")
def registrar_appointments(request: Request, day: Optional[date] = None):
    user, denied = require_user(request, "registrar")
    if denied:
        return denied
    selected_day = day or date.today()
    conn = db_as(user)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT a.id, d.full_name, s.starts_at, s.ends_at, u.email, a.status
        FROM appointments a
        JOIN slots s ON s.id = a.slot_id
        JOIN doctors d ON d.id = s.doctor_id
        JOIN users u ON u.id = a.patient_user_id
        WHERE s.starts_at >= %s
          AND s.starts_at < %s + INTERVAL '1 day'
        ORDER BY s.starts_at, d.full_name, u.email
        """,
        (selected_day, selected_day),
    )
    appointments = [
        {
            "id": row[0],
            "doctor_name": row[1],
            "starts_at": row[2],
            "ends_at": row[3],
            "patient_email": row[4],
            "status": row[5],
        }
        for row in cur.fetchall()
    ]
    cur.close()
    conn.close()
    return templates.TemplateResponse(
        "registrar_appointments.html",
        {
            "request": request,
            "role": user["role"],
            "day": selected_day,
            "appointments": appointments,
        },
    )


@router.get("/doctor/calendar")
def doctor_calendar(request: Request, day: Optional[date] = None):
    user, denied = require_user(request, "doctor")
    if denied:
        return denied
    selected_day = day or date.today()
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
        SELECT s.id, s.starts_at, s.ends_at,
               a.id, dp.email,
               EXISTS (
                   SELECT 1
                   FROM time_off t
                   WHERE t.doctor_id = s.doctor_id
                     AND s.starts_at::date BETWEEN t.starts_on AND t.ends_on
               )
               OR EXISTS (
                   SELECT 1 FROM holidays h WHERE h.day = s.starts_at::date
               ) AS closed
        FROM slots s
        LEFT JOIN appointments a
          ON a.slot_id = s.id AND a.status = 'scheduled'
        LEFT JOIN public.doctor_patients(%s) dp
          ON dp.id = a.patient_user_id
        WHERE s.doctor_id = %s
          AND s.starts_at::date = %s
        ORDER BY s.starts_at
        """,
        (user["id"], doctor[0], selected_day),
    )
    slots = [
        {
            "id": row[0],
            "starts_at": row[1],
            "ends_at": row[2],
            "appointment_id": row[3],
            "patient_email": row[4],
            "closed": row[5],
        }
        for row in cur.fetchall()
    ]
    cur.execute(
        """
        SELECT a.id, a.starts_at, a.ends_at, dp.email
        FROM appointments a
        JOIN slots s ON s.id = a.slot_id
        JOIN public.doctor_patients(%s) dp ON dp.id = a.patient_user_id
        WHERE s.doctor_id = %s
          AND s.starts_at::date = %s
          AND a.status = 'cancelled'
        ORDER BY a.starts_at
        """,
        (user["id"], doctor[0], selected_day),
    )
    cancelled = [
        {
            "id": row[0],
            "starts_at": row[1],
            "ends_at": row[2],
            "patient_email": row[3],
        }
        for row in cur.fetchall()
    ]
    cur.execute(
        """
        SELECT EXISTS (
                   SELECT 1 FROM time_off
                   WHERE doctor_id = %s AND %s BETWEEN starts_on AND ends_on
               ),
               (SELECT name FROM holidays WHERE day = %s)
        """,
        (doctor[0], selected_day, selected_day),
    )
    closure = cur.fetchone()
    cur.execute(
        """
        SELECT id, starts_on, ends_on, comment, status, created_at
        FROM time_off_requests
        ORDER BY created_at DESC, id DESC
        LIMIT 20
        """
    )
    requests = [
        {
            "id": row[0],
            "starts_on": row[1],
            "ends_on": row[2],
            "comment": row[3],
            "status": row[4],
            "created_at": row[5],
        }
        for row in cur.fetchall()
    ]
    cur.close()
    conn.close()

    closure_reasons = []
    if closure[0]:
        closure_reasons.append("doctor time off")
    if closure[1]:
        closure_reasons.append(f"holiday: {closure[1]}")
    return templates.TemplateResponse(
        "doctor_calendar.html",
        {
            "request": request,
            "role": user["role"],
            "doctor": {"id": doctor[0], "full_name": doctor[1]},
            "day": selected_day,
            "previous_day": selected_day - timedelta(days=1),
            "next_day": selected_day + timedelta(days=1),
            "slots": slots,
            "cancelled": cancelled,
            "closure_reasons": closure_reasons,
            "requests": requests,
            "request_submitted": request.query_params.get("request_submitted"),
            "error": request.query_params.get("error"),
        },
    )


@router.post("/doctor/time-off-requests")
def submit_time_off_request(
    request: Request,
    starts_on: date = Form(...),
    ends_on: date = Form(...),
    comment: str = Form(...),
):
    user, denied = require_user(request, "doctor")
    if denied:
        return denied
    note = comment.strip()
    redirect_url = f"/doctor/calendar?day={starts_on.isoformat()}"
    if starts_on < date.today():
        return RedirectResponse(
            f"{redirect_url}&error=request_date_past", status_code=303
        )
    if starts_on > ends_on:
        return RedirectResponse(
            f"{redirect_url}&error=invalid_request_range", status_code=303
        )
    if not note:
        return RedirectResponse(
            f"{redirect_url}&error=request_comment_required", status_code=303
        )
    if not within_length(note, MAX_TEXT_LENGTH):
        return RedirectResponse(
            f"{redirect_url}&error=request_comment_too_long", status_code=303
        )

    conn = db_as(user)
    cur = conn.cursor()
    cur.execute(
        "SELECT id FROM doctors WHERE user_id = %s",
        (user["id"],),
    )
    doctor = cur.fetchone()
    if doctor is None:
        cur.close()
        conn.close()
        return RedirectResponse("/me?error=doctor_profile_missing", status_code=303)
    cur.execute(
        """
        INSERT INTO time_off_requests (doctor_id, starts_on, ends_on, comment)
        VALUES (%s, %s, %s, %s)
        RETURNING id
        """,
        (doctor[0], starts_on, ends_on, note),
    )
    request_id = cur.fetchone()[0]
    record_audit_event(cur, "schedule.time_off_request.submit", "time_off_request", request_id)
    conn.commit()
    cur.close()
    conn.close()
    return RedirectResponse(
        f"{redirect_url}&request_submitted=1",
        status_code=303,
    )
