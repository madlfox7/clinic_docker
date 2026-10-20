import psycopg2
from typing import Optional
from urllib.parse import quote

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from db import (
    MAX_EMAIL_LENGTH,
    contains_nul,
    db_as,
    load_appointment_notice,
    log,
    parse_strict_int,
    record_audit_event,
    templates,
    within_length,
)
from mailer import deliver_appointment_emails
from routes_auth import _normalize_registration_email, require_user





router = APIRouter()


def _patient_email_query(email):
    normalized = _normalize_registration_email(email or "")
    if normalized is None:
        return ""
    return f"&patient_email={quote(normalized, safe='')}"


def _overlap_redirect(doctor_id, service_id, patient_email_query=""):
    return RedirectResponse(
        f"/doctors/{doctor_id}/slots?error=overlap"
        f"&service_id={service_id}{patient_email_query}",
        status_code=303,
    )


@router.get("/doctors/{doctor_id}/slots")
def doctor_slots(request: Request, doctor_id: str):
    user, denied = require_user(request, "patient", "registrar", "admin")
    if denied:
        return denied
    role = user["role"]
    doctor_id = parse_strict_int(doctor_id, min_value=1)
    if doctor_id is None:
        return RedirectResponse("/doctors", status_code=303)
    error = request.query_params.get("error")
    booked = request.query_params.get("booked")
    booking_confirmation = None
    cancelled = request.query_params.get("cancelled")
    cancel_error = request.query_params.get("cancel_error")
    conflict = None
    conn = db_as(user)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT svc.id, svc.name, svc.duration_minutes, svc.buffer_minutes
        FROM services svc
        JOIN doctor_services ds ON ds.service_id = svc.id
        WHERE svc.active AND ds.doctor_id = %s
        ORDER BY name, id
        """,
        (doctor_id,),
    )
    services = [
        {
            "id": row[0],
            "name": row[1],
            "duration_minutes": row[2],
            "buffer_minutes": row[3],
        }
        for row in cur.fetchall()
    ]
    raw_service_id = request.query_params.get("service_id")
    requested_service_id = (
        parse_strict_int(raw_service_id, min_value=1)
        if raw_service_id is not None
        else (services[0]["id"] if services else None)
    )
    selected_service = next(
        (item for item in services if item["id"] == requested_service_id),
        None,
    )
    service_error = raw_service_id is not None and selected_service is None
    cur.execute("SELECT id, full_name FROM doctors WHERE id=%s", (doctor_id,))
    doc = cur.fetchone()
    cur.execute("SELECT public.doctor_is_active(%s)", (doctor_id,))
    doctor_active = cur.fetchone()[0]
    selected_patient = None
    if role == "registrar":
        requested_patient_email = _normalize_registration_email(
            request.query_params.get("patient_email", "")
        )
        if requested_patient_email:
            cur.execute(
                """
                SELECT email, blocked
                FROM users
                WHERE lower(email) = %s AND role = 'patient'
                """,
                (requested_patient_email,),
            )
            patient_row = cur.fetchone()
            if patient_row:
                selected_patient = {
                    "email": patient_row[0],
                    "blocked": patient_row[1],
                }
    if not doctor_active:
        cur.close()
        conn.close()
        return RedirectResponse("/doctors", status_code=303)
    conflict_candidates = []
    if error == "overlap" and role in ("patient", "registrar"):
        if role == "patient":
            conflict_patient_id = user["id"]
        elif selected_patient:
            cur.execute(
                "SELECT id FROM users WHERE email=%s AND role='patient'",
                (selected_patient["email"],),
            )
            found = cur.fetchone()
            conflict_patient_id = found[0] if found else None
        else:
            conflict_patient_id = None
        if conflict_patient_id is not None:
            cur.execute(
                """
                SELECT d.full_name, a.starts_at, a.ends_at
                FROM appointments a
                JOIN doctors d ON d.id = a.doctor_id
                WHERE a.patient_user_id=%s
                  AND a.status='scheduled'
                  AND a.ends_at > CURRENT_TIMESTAMP
                ORDER BY a.starts_at
                """,
                (conflict_patient_id,),
            )
            conflict_candidates = [
                {
                    "doctor_name": row[0],
                    "starts_at": row[1],
                    "ends_at": row[2],
                }
                for row in cur.fetchall()
            ]
    raw_confirmation_id = request.query_params.get("appointment_id")
    confirmation_id = (
        parse_strict_int(raw_confirmation_id, min_value=1)
        if raw_confirmation_id is not None
        else None
    )
    if role == "registrar" and booked == "1" and confirmation_id is not None:
        cur.execute(
            """
            SELECT d.full_name, u.email, svc.name, s.duration_minutes,
                   s.buffer_minutes, a.starts_at, a.ends_at
            FROM appointments a
            JOIN doctors d ON d.id = a.doctor_id
            JOIN users u ON u.id = a.patient_user_id
            JOIN slots s ON s.id = a.slot_id
            JOIN services svc ON svc.id = s.service_id
            WHERE a.id = %s
              AND a.doctor_id = %s
              AND a.status = 'scheduled'
            """,
            (confirmation_id, doctor_id),
        )
        row = cur.fetchone()
        if row:
            booking_confirmation = {
                "doctor_name": row[0],
                "patient_email": row[1],
                "service_name": row[2],
                "duration_minutes": row[3],
                "buffer_minutes": row[4],
                "starts_at": row[5],
                "ends_at": row[6],
            }
    if selected_service is None:
        rows = []
    else:
        cur.execute(
            """
            SELECT s.id, s.starts_at,
                   s.starts_at + make_interval(mins => s.duration_minutes),
                   svc.name, s.duration_minutes, s.buffer_minutes,
                   public.scheduled_slot_is_taken(s.id) AS taken,
                   EXISTS (
                       SELECT 1
                       FROM appointments a
                       WHERE a.doctor_id = s.doctor_id
                         AND a.status = 'scheduled'
                         AND a.patient_user_id = %s
                         AND a.starts_at < s.starts_at
                               + make_interval(mins => s.duration_minutes)
                         AND a.ends_at > s.starts_at
                   ) AS mine,
                   (
                       SELECT a.id
                       FROM appointments a
                       WHERE a.doctor_id = s.doctor_id
                         AND a.status = 'scheduled'
                         AND a.starts_at < s.ends_at
                         AND a.reserved_ends_at > s.starts_at
                       ORDER BY a.starts_at
                       LIMIT 1
                   ) AS appointment_id,
                   (
                       EXISTS (
                           SELECT 1 FROM time_off t
                           WHERE t.doctor_id = s.doctor_id
                             AND s.starts_at::date BETWEEN t.starts_on AND t.ends_on
                       )
                       OR EXISTS (
                           SELECT 1 FROM holidays h WHERE h.day = s.starts_at::date
                       )
                   ) AS closed,
                   s.starts_at <= CURRENT_TIMESTAMP AS is_past
            FROM slots s
            JOIN services svc ON svc.id = s.service_id AND svc.active
            JOIN doctor_services ds
              ON ds.doctor_id = s.doctor_id AND ds.service_id = s.service_id
            WHERE s.doctor_id = %s
              AND s.service_id = %s
            ORDER BY s.starts_at
            """,
            (user["id"], doctor_id, selected_service["id"]),
        )
        rows = cur.fetchall()
        if role == "patient":
            rows = [row for row in rows if not row[9] and not row[10]]
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
            "service_name": row[3],
            "duration_minutes": row[4],
            "buffer_minutes": row[5],
            "taken": row[6],
            "mine": row[7],
            "appointment_id": row[8],
            "closed": row[9],
            "past": row[10],
        }
        slots_by_day.setdefault(row[1].date(), []).append(slot)
    days = [
        {
            "label": day.strftime("%A, %Y-%m-%d"),
            "slots": day_slots,
        }
        for day, day_slots in sorted(slots_by_day.items())
    ]
    if conflict_candidates:
        visible_slots = [
            slot
            for day_slots in slots_by_day.values()
            for slot in day_slots
        ]
        for candidate in conflict_candidates:
            if any(
                candidate["starts_at"] < slot["ends_at"]
                and candidate["ends_at"] > slot["starts_at"]
                for slot in visible_slots
            ):
                conflict = candidate
                break
        if conflict is None:
            conflict = conflict_candidates[0]
    return templates.TemplateResponse(
        "slots.html",
        {
            "request": request,
            "doctor": {"id": doc[0], "full_name": doc[1]},
            "days": days,
            "services": services,
            "selected_service": selected_service,
            "service_error": service_error,
            "error": error,
            "booked": booked,
            "booking_confirmation": booking_confirmation,
            "cancelled": cancelled,
            "cancel_error": cancel_error,
            "conflict": conflict,
            "selected_patient": selected_patient,
            "role": role,
        },
    )


@router.post("/slots/{slot_id}/book")
def book_slot(
    request: Request,
    slot_id: str,
    patient_email: str = Form(None),
    service_id: Optional[str] = Form(None),
):
    user, denied = require_user(request, "patient", "registrar")
    if denied:
        return denied
    email = user["email"]
    role = user["role"]
    patient_email_query = (
        _patient_email_query(patient_email) if role == "registrar" else ""
    )
    slot_id = parse_strict_int(slot_id, min_value=1)
    if slot_id is None:
        return RedirectResponse("/doctors", status_code=303)
    raw_service_id = service_id
    requested_service_id = (
        parse_strict_int(raw_service_id, min_value=1)
        if raw_service_id is not None
        else None
    )
    conn = db_as(user)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT s.doctor_id, s.service_id, s.starts_at,
               s.starts_at + make_interval(mins => s.duration_minutes),
               s.ends_at,
               s.starts_at <= CURRENT_TIMESTAMP AS is_past,
               public.doctor_is_active(s.doctor_id) AS doctor_active,
               EXISTS (
                   SELECT 1 FROM services svc
                   WHERE svc.id = s.service_id AND svc.active
               ) AS service_active,
               EXISTS (
                   SELECT 1 FROM doctor_services ds
                   WHERE ds.doctor_id = s.doctor_id
                     AND ds.service_id = s.service_id
               ) AS service_assigned,
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
    (
        doctor_id,
        service_id,
        starts_at,
        visit_ends_at,
        ends_at,
        is_past,
        doctor_active,
        service_active,
        service_assigned,
        is_closed,
    ) = slot
    if raw_service_id is not None and requested_service_id != service_id:
        cur.close()
        conn.close()
        return RedirectResponse(
            f"/doctors/{doctor_id}/slots?error=service_mismatch"
            f"&service_id={service_id}{patient_email_query}",
            status_code=303,
        )
    if not doctor_active:
        cur.close()
        conn.close()
        return RedirectResponse(
            f"/doctors/{doctor_id}/slots?error=unavailable"
            f"&service_id={service_id}{patient_email_query}",
            status_code=303,
        )
    if not service_active or not service_assigned:
        cur.close()
        conn.close()
        return RedirectResponse(
            f"/doctors/{doctor_id}/slots?error=service_unavailable"
            f"&service_id={service_id}{patient_email_query}",
            status_code=303,
        )
    if is_past:
        cur.close()
        conn.close()
        return RedirectResponse(
            f"/doctors/{doctor_id}/slots?error=past"
            f"&service_id={service_id}{patient_email_query}",
            status_code=303,
        )
    if is_closed:
        cur.close()
        conn.close()
        return RedirectResponse(
            f"/doctors/{doctor_id}/slots?error=closed"
            f"&service_id={service_id}{patient_email_query}",
            status_code=303,
        )
    if role == "patient":
        target_email = email
    else:
        supplied_email = patient_email or ""
        target_email = _normalize_registration_email(supplied_email) or ""
        if not supplied_email.strip():
            cur.close()
            conn.close()
            return RedirectResponse(
                f"/doctors/{doctor_id}/slots?error=patient_required"
                f"&service_id={service_id}{patient_email_query}",
                status_code=303,
            )
        if not target_email:
            cur.close()
            conn.close()
            return RedirectResponse(
                f"/doctors/{doctor_id}/slots?error=patient_not_found"
                f"&service_id={service_id}{patient_email_query}",
                status_code=303,
            )
    if role == "patient":
        patient_id = user["id"]
    else:
        cur.execute(
            "SELECT id, role, blocked FROM users WHERE lower(email)=%s",
            (target_email,),
        )
        target = cur.fetchone()
        if not target or target[1] != "patient":
            cur.close()
            conn.close()
            return RedirectResponse(
                f"/doctors/{doctor_id}/slots?error=patient_not_found"
                f"&service_id={service_id}{patient_email_query}",
                status_code=303,
            )
        patient_id = target[0]
        if target[2]:
            cur.close()
            conn.close()
            return RedirectResponse(
                f"/doctors/{doctor_id}/slots?error=patient_blocked"
                f"&service_id={service_id}{patient_email_query}",
                status_code=303,
            )
    cur.execute("SELECT pg_advisory_xact_lock(%s)", (patient_id,))

    cur.execute("SELECT public.scheduled_slot_is_taken(%s)", (slot_id,))
    if cur.fetchone()[0]:
        cur.close()
        conn.close()
        return RedirectResponse(
            f"/doctors/{doctor_id}/slots?error=unavailable"
            f"&service_id={service_id}{patient_email_query}",
            status_code=303,
        )

    cur.execute(
        """
        SELECT a.id
        FROM appointments a
        WHERE a.patient_user_id = %s
          AND a.status = 'scheduled'
          AND a.starts_at < %s
          AND a.ends_at > %s
        """,
        (patient_id, visit_ends_at, starts_at),
    )
    conflict_row = cur.fetchone()
    if conflict_row:
        cur.close()
        conn.close()
        return _overlap_redirect(doctor_id, service_id, patient_email_query)

    try:
        cur.execute(
            """
            INSERT INTO appointments (
                slot_id, patient_user_id, doctor_id, starts_at, ends_at,
                reserved_ends_at
            )
            SELECT s.id, %s, s.doctor_id, s.starts_at,
                   s.starts_at + make_interval(mins => s.duration_minutes),
                   s.ends_at
            FROM slots s
            WHERE s.id = %s
              AND s.starts_at > CURRENT_TIMESTAMP
            RETURNING id
            """,
            (patient_id, slot_id),
        )
        appointment_row = cur.fetchone()
        if not appointment_row:
            conn.rollback()
            cur.close()
            conn.close()
            return RedirectResponse(
                f"/doctors/{doctor_id}/slots?error=unavailable"
                f"&service_id={service_id}{patient_email_query}",
                status_code=303,
            )
        record_audit_event(cur, "appointment.book", "appointment", appointment_row[0])
        notice = None
        try:
            notice = load_appointment_notice(cur, appointment_row[0])
        except Exception:
            log.exception("could not prepare appointment email")
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        cur.close()
        conn.close()
        return RedirectResponse(
            f"/doctors/{doctor_id}/slots?error=unavailable"
            f"&service_id={service_id}{patient_email_query}",
            status_code=303,
        )
    except psycopg2.errors.ExclusionViolation as exc:
        conn.rollback()
        constraint = exc.diag.constraint_name if exc.diag is not None else None
        cur.close()
        conn.close()
        if constraint == "appointments_no_overlap_per_patient":
            return _overlap_redirect(doctor_id, service_id, patient_email_query)
        return RedirectResponse(
            f"/doctors/{doctor_id}/slots?error=unavailable"
            f"&service_id={service_id}{patient_email_query}",
            status_code=303,
        )
    except Exception:
        log.exception("could not book slot %s", slot_id)
        conn.rollback()
        cur.close()
        conn.close()
        return RedirectResponse(
            f"/doctors/{doctor_id}/slots?error=could_not_book"
            f"&service_id={service_id}{patient_email_query}",
            status_code=303,
        )
    cur.close()
    conn.close()
    deliver_appointment_emails(notice, "confirmed")
    if role == "registrar":
        return RedirectResponse(
            f"/doctors/{doctor_id}/slots?booked=1&service_id={service_id}"
            f"&appointment_id={appointment_row[0]}{patient_email_query}",
            status_code=303,
        )
    return RedirectResponse(
        f"/my?booked=1&appointment_id={appointment_row[0]}",
        status_code=303,
    )


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
         SELECT s.doctor_id, s.service_id, a.patient_user_id,
              s.starts_at > CURRENT_TIMESTAMP AS is_future, a.status
        FROM appointments a
        JOIN slots s ON s.id=a.slot_id
         WHERE a.id=%s
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

    doctor_id, service_id, patient_user_id, is_future, appointment_status = appointment
    if appointment_status != "scheduled":
        cur.close()
        conn.close()
        if role == "patient":
            return RedirectResponse("/my?cancel_error=1", status_code=303)
        if role == "registrar":
            return RedirectResponse(
                f"/doctors/{doctor_id}/slots?cancel_error=1&service_id={service_id}",
                status_code=303,
            )
        return RedirectResponse("/doctors", status_code=303)

    if role == "registrar" and not is_future:
        cur.close()
        conn.close()
        return RedirectResponse(
            f"/doctors/{doctor_id}/slots?cancel_error=past&service_id={service_id}",
            status_code=303,
        )

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
    elif role == "registrar":
        cur.execute(
            """
            UPDATE appointments a
            SET status='cancelled'
            WHERE a.id=%s
              AND a.status='scheduled'
              AND EXISTS (
                  SELECT 1 FROM slots s
                  WHERE s.id=a.slot_id AND s.starts_at > CURRENT_TIMESTAMP
              )
            """,
            (appointment_id,),
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
    notice = None
    if updated:
        record_audit_event(cur, "appointment.cancel", "appointment", appointment_id)
        try:
            notice = load_appointment_notice(cur, appointment_id)
        except Exception:
            log.exception("could not prepare appointment email")
    conn.commit()
    cur.close()
    conn.close()
    if updated:
        deliver_appointment_emails(notice, "cancelled")
    if role == "patient":
        if updated:
            return RedirectResponse("/my?cancelled=1", status_code=303)
        return RedirectResponse("/my?cancel_error=1", status_code=303)
    if role == "admin":
        return RedirectResponse("/admin/schedule?visit_cancelled=1", status_code=303)
    if updated:
        return RedirectResponse(
            f"/doctors/{doctor_id}/slots?cancelled=1&service_id={service_id}",
            status_code=303,
        )
    return RedirectResponse(
        f"/doctors/{doctor_id}/slots?cancel_error=1&service_id={service_id}",
        status_code=303,
    )


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
         SELECT a.id, d.full_name, svc.name, a.starts_at, a.ends_at, a.status,
              a.starts_at > CURRENT_TIMESTAMP AS cancellable,
              s.duration_minutes, s.buffer_minutes
         FROM appointments a
         JOIN slots s ON s.id=a.slot_id
         JOIN doctors d ON d.id=s.doctor_id
          JOIN services svc ON svc.id=s.service_id
         WHERE a.patient_user_id=%s
         ORDER BY
              CASE
                WHEN a.status = 'scheduled'
                 AND a.starts_at > CURRENT_TIMESTAMP THEN 0
                ELSE 1
              END,
              CASE
                WHEN a.status = 'scheduled'
                 AND a.starts_at > CURRENT_TIMESTAMP THEN a.starts_at
              END ASC,
              CASE
                WHEN a.status != 'scheduled'
                  OR a.starts_at <= CURRENT_TIMESTAMP THEN a.starts_at
              END DESC,
              a.id DESC
         """,
         (user["id"],),
    )
    items = [
        {
            "id": r[0],
            "doctor_name": r[1],
            "service_name": r[2],
            "starts_at": r[3],
            "ends_at": r[4],
            "status": r[5],
            "cancellable": r[6],
            "duration_minutes": r[7],
            "buffer_minutes": r[8],
        }
        for r in cur.fetchall()
    ]
    booking_confirmation = None
    raw_confirmation_id = request.query_params.get("appointment_id")
    confirmation_id = (
        parse_strict_int(raw_confirmation_id, min_value=1)
        if raw_confirmation_id is not None
        else None
    )
    if request.query_params.get("booked") == "1" and confirmation_id is not None:
        booking_confirmation = next(
            (
                item
                for item in items
                if item["id"] == confirmation_id and item["status"] == "scheduled"
            ),
            None,
        )
    cur.close()
    conn.close()
    return templates.TemplateResponse(
        "my_appointments.html",
        {
            "request": request,
            "items": items,
            "role": role,
            "booking_confirmation": booking_confirmation,
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
        SELECT a.id, dp.email, svc.name, a.starts_at, a.ends_at, a.status, dp.blocked
        FROM appointments a
        JOIN slots s ON s.id=a.slot_id
        JOIN services svc ON svc.id=s.service_id
        JOIN doctors d ON d.id=s.doctor_id
        JOIN public.doctor_patients(%s) dp ON dp.id=a.patient_user_id
        WHERE d.user_id=%s
        ORDER BY a.starts_at
        """,
        (user["id"], user["id"]),
    )
    items = [
        {
            "id": r[0],
            "patient_email": r[1],
            "service_name": r[2],
            "starts_at": r[3],
            "ends_at": r[4],
            "status": r[5],
            "patient_blocked": r[6],
        }
        for r in cur.fetchall()
    ]
    cur.close()
    conn.close()
    return templates.TemplateResponse(
        "doctor_appointments.html",
        {"request": request, "items": items, "role": role},
    )
