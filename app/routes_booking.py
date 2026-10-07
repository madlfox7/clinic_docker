import psycopg2
from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from db import (
    MAX_EMAIL_LENGTH,
    db_as,
    log,
    parse_strict_int,
    set_db_context,
    templates,
    within_length,
)
from routes_auth import require_user





router = APIRouter()


def _overlap_redirect(doctor_id, patient_id, conflict_id):
    if conflict_id:
        return RedirectResponse(
            f"/doctors/{doctor_id}/slots?error=overlap&conflict_appointment_id={conflict_id}&conflict_patient_id={patient_id}",
            status_code=303,
        )
    return RedirectResponse(
        f"/doctors/{doctor_id}/slots?error=overlap&conflict_patient_id={patient_id}",
        status_code=303,
    )


@router.get("/doctors/{doctor_id}/slots")
def doctor_slots(request: Request, doctor_id: str):
    user, denied = require_user(request, "patient", "registrar")
    if denied:
        return denied
    role = user["role"]
    doctor_id = parse_strict_int(doctor_id, min_value=1)
    if doctor_id is None:
        return RedirectResponse("/doctors", status_code=303)
    error = request.query_params.get("error")
    booked = request.query_params.get("booked")
    cancelled = request.query_params.get("cancelled")
    cancel_error = request.query_params.get("cancel_error")
    conflict = None
    conn = db_as(user)
    cur = conn.cursor()
    cur.execute("SELECT id, full_name FROM doctors WHERE id=%s", (doctor_id,))
    doc = cur.fetchone()
    conflict_appointment_id = request.query_params.get("conflict_appointment_id")
    conflict_patient_id = request.query_params.get("conflict_patient_id")
    if error == "overlap" and conflict_appointment_id and role == "patient":
        cur.execute(
            """
            SELECT d.full_name, s.starts_at, s.ends_at
            FROM appointments a
            JOIN slots s ON s.id = a.slot_id
            JOIN doctors d ON d.id = s.doctor_id
            WHERE a.id=%s AND a.patient_user_id=%s AND a.status='scheduled'
            """,
            (conflict_appointment_id, user["id"]),
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
        and parse_strict_int(conflict_patient_id, min_value=1) is not None
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
                 WHERE a.slot_id = s.id
                AND a.status = 'scheduled'
                AND a.patient_user_id = %s
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
         (user["id"], doctor_id),
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
            "role": role,
        },
    )


@router.post("/slots/{slot_id}/book")
def book_slot(request: Request, slot_id: str, patient_email: str = Form(None)):
    user, denied = require_user(request, "patient", "registrar")
    if denied:
        return denied
    email = user["email"]
    role = user["role"]
    slot_id = parse_strict_int(slot_id, min_value=1)
    if slot_id is None:
        return RedirectResponse("/doctors", status_code=303)
    conn = db_as(user)
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
        if not within_length(target_email, MAX_EMAIL_LENGTH):
            cur.close()
            conn.close()
            return RedirectResponse(
                f"/doctors/{doctor_id}/slots?error=patient_not_found", status_code=303
            )
    if role == "patient":
        patient_id = user["id"]
    else:
        cur.execute(
            "SELECT id, role, blocked FROM users WHERE email=%s",
            (target_email,),
        )
        target = cur.fetchone()
        if not target or target[1] != "patient":
            cur.close()
            conn.close()
            return RedirectResponse(
                f"/doctors/{doctor_id}/slots?error=patient_not_found", status_code=303
            )
        patient_id = target[0]
        if target[2]:
            cur.close()
            conn.close()
            return RedirectResponse(
                f"/doctors/{doctor_id}/slots?error=patient_blocked", status_code=303
            )
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
        return _overlap_redirect(doctor_id, patient_id, conflict_row[0])

    try:
        cur.execute(
            """
            INSERT INTO appointments (
                slot_id, patient_user_id, doctor_id, starts_at, ends_at
            )
            SELECT s.id, %s, s.doctor_id, s.starts_at, s.ends_at
            FROM slots s
            WHERE s.id = %s
              AND s.starts_at > CURRENT_TIMESTAMP
            """,
            (patient_id, slot_id),
        )
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        cur.close()
        conn.close()
        return RedirectResponse(f"/doctors/{doctor_id}/slots?error=unavailable", status_code=303)
    except psycopg2.errors.ExclusionViolation as exc:
        conn.rollback()
        set_db_context(conn, user)
        constraint = exc.diag.constraint_name if exc.diag is not None else None
        conflict_id = None
        if constraint == "appointments_no_overlap_per_patient":
            try:
                cur.execute(
                    """
                    SELECT a.id
                    FROM appointments a
                    WHERE a.patient_user_id = %s
                      AND a.status = 'scheduled'
                      AND a.starts_at < %s
                      AND a.ends_at > %s
                    """,
                    (patient_id, ends_at, starts_at),
                )
                row = cur.fetchone()
                conflict_id = row[0] if row else None
            except Exception:
                log.exception("could not load patient overlap for slot %s", slot_id)
                conn.rollback()
        cur.close()
        conn.close()
        if constraint == "appointments_no_overlap_per_patient":
            return _overlap_redirect(doctor_id, patient_id, conflict_id)
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


@router.post("/appointments/{appointment_id}/cancel")
def cancel_appointment(request: Request, appointment_id: str):
    user, denied = require_user(request, "patient", "registrar", "admin")
    if denied:
        return denied
    role = user["role"]
    appointment_id = parse_strict_int(appointment_id, min_value=1)
    if appointment_id is None:
        if role == "patient":
            return RedirectResponse("/my?cancel_error=1", status_code=303)
        return RedirectResponse("/doctors", status_code=303)
    conn = db_as(user)
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
                  SELECT 1 FROM slots s
                  WHERE s.id=a.slot_id AND s.starts_at > CURRENT_TIMESTAMP
              )
            """,
            (appointment_id, user["id"]),
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


@router.get("/my")
def my_appointments(request: Request):
    user, denied = require_user(request, "patient")
    if denied:
        return denied
    role = user["role"]
    cancelled = request.query_params.get("cancelled")
    cancel_error = request.query_params.get("cancel_error")
    conn = db_as(user)
    cur = conn.cursor()
    cur.execute(
        """
         SELECT a.id, d.full_name, s.starts_at, s.ends_at, a.status,
              s.starts_at > CURRENT_TIMESTAMP AS cancellable
         FROM appointments a
         JOIN slots s ON s.id=a.slot_id
         JOIN doctors d ON d.id=s.doctor_id
         WHERE a.patient_user_id=%s
         ORDER BY s.starts_at
         """,
         (user["id"],),
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
            "role": role,
            "cancelled": cancelled,
            "cancel_error": cancel_error,
        },
    )


@router.get("/doctor/appointments")
def doctor_appointments(request: Request):
    user, denied = require_user(request, "doctor")
    if denied:
        return denied
    role = user["role"]
    conn = db_as(user)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT dp.email, s.starts_at, s.ends_at, a.status, dp.blocked
        FROM appointments a
        JOIN slots s ON s.id=a.slot_id
        JOIN doctors d ON d.id=s.doctor_id
        JOIN public.doctor_patients(%s) dp ON dp.id=a.patient_user_id
        WHERE d.user_id=%s
        ORDER BY s.starts_at
        """,
        (user["id"], user["id"]),
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
        {"request": request, "items": items, "role": role},
    )
