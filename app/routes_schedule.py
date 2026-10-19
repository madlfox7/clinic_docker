from datetime import date, timedelta
from urllib.parse import urlencode

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import RedirectResponse

from db import (
    MAX_EMAIL_LENGTH,
    MAX_TEXT_LENGTH,
    db_as,
    parse_strict_int,
    record_audit_event,
    templates,
    within_length,
)
from routes_auth import require_user


router = APIRouter()


@router.get("/registrar/patients")
def registrar_patients(request: Request):
    user, denied = require_user(request, "registrar")
    if denied:
        return denied
    query = request.query_params.get("q", "").strip()
    if len(query) > MAX_EMAIL_LENGTH:
        return templates.TemplateResponse(
            "registrar_patients.html",
            {
                "request": request,
                "role": user["role"],
                "patients": [],
                "query": query,
                "error": "query_too_long",
            },
        )
    conn = db_as(user)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT u.id, u.email, u.blocked, count(s.id) AS future_count
        FROM users u
        LEFT JOIN appointments a
          ON a.patient_user_id = u.id AND a.status = 'scheduled'
        LEFT JOIN slots s
          ON s.id = a.slot_id AND s.starts_at > CURRENT_TIMESTAMP
        WHERE u.role = 'patient'
          AND (%s = '' OR u.email ILIKE %s)
        GROUP BY u.id, u.email, u.blocked
        ORDER BY u.email
        LIMIT 100
        """,
        (query, f"%{query}%"),
    )
    patients = [
        {
            "id": row[0],
            "email": row[1],
            "blocked": row[2],
            "future_count": row[3],
            "book_url": (
                f"/registrar/patients/{row[0]}/book"
                if not row[2]
                else None
            ),
        }
        for row in cur.fetchall()
    ]
    cur.close()
    conn.close()
    return templates.TemplateResponse(
        "registrar_patients.html",
        {
            "request": request,
            "role": user["role"],
            "patients": patients,
            "query": query,
            "error": request.query_params.get("error"),
        },
    )


@router.get("/registrar/patients/search")
def registrar_patient_search(request: Request):
    user, denied = require_user(request, "registrar")
    if denied:
        return denied
    query = request.query_params.get("q", "").strip()
    if len(query) > MAX_EMAIL_LENGTH:
        raise HTTPException(status_code=400, detail="Search query is too long.")
    if len(query) < 2:
        return []
    conn = db_as(user)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT email, blocked
        FROM users
        WHERE role = 'patient' AND email ILIKE %s
        ORDER BY email
        LIMIT 15
        """,
        (f"%{query}%",),
    )
    results = [
        {"email": row[0], "blocked": row[1]}
        for row in cur.fetchall()
    ]
    cur.close()
    conn.close()
    return results


@router.get("/registrar/patients/{patient_id}/book")
def registrar_start_booking(request: Request, patient_id: str):
    user, denied = require_user(request, "registrar")
    if denied:
        return denied
    patient_id = parse_strict_int(patient_id, min_value=1)
    if patient_id is None:
        return RedirectResponse("/registrar/patients?error=patient_not_found", status_code=303)
    conn = db_as(user)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT email, blocked
        FROM users
        WHERE id = %s AND role = 'patient'
        """,
        (patient_id,),
    )
    patient = cur.fetchone()
    cur.close()
    conn.close()
    if patient is None:
        return RedirectResponse("/registrar/patients?error=patient_not_found", status_code=303)
    if patient[1]:
        return RedirectResponse("/registrar/patients?error=patient_blocked", status_code=303)
    return RedirectResponse(
        f"/doctors?{urlencode({'patient_email': patient[0]})}",
        status_code=303,
    )


def _calendar_state(request: Request):
    errors = []
    raw_day = request.query_params.get("day")
    selected_day = date.today()
    if raw_day is not None:
        try:
            parsed_day = date.fromisoformat(raw_day)
            if parsed_day.isoformat() != raw_day:
                raise ValueError
            selected_day = parsed_day
        except ValueError:
            errors.append("invalid_day")

    raw_view = request.query_params.get("view", "day")
    if raw_view not in ("day", "week"):
        errors.append("invalid_view")
        view = "day"
    else:
        view = raw_view
    return selected_day, view, errors


def _calendar_url(path, view, day, doctor_id=None):
    params = {"view": view, "day": day.isoformat()}
    if doctor_id is not None:
        params["doctor_id"] = str(doctor_id)
    return f"{path}?{urlencode(params)}"


def _calendar_navigation(path, view, selected_day, doctor_id=None):
    if view == "week":
        week_start = selected_day - timedelta(days=selected_day.weekday())
        previous_day = week_start - timedelta(days=7)
        next_day = week_start + timedelta(days=7)
    else:
        previous_day = selected_day - timedelta(days=1)
        next_day = selected_day + timedelta(days=1)
    return {
        "previous_url": _calendar_url(path, view, previous_day, doctor_id),
        "today_url": _calendar_url(path, view, date.today(), doctor_id),
        "next_url": _calendar_url(path, view, next_day, doctor_id),
        "day_view_url": _calendar_url(path, "day", selected_day, doctor_id),
        "week_view_url": _calendar_url(path, "week", selected_day, doctor_id),
    }


def _load_calendar(cur, start_day, day_count, doctor_id, role):
    cur.execute(
        """
        WITH calendar_days AS (
            SELECT %s::date + offsets.day_offset AS day
            FROM generate_series(0, %s::integer) AS offsets(day_offset)
        )
        SELECT cd.day,
               CASE
                   WHEN %s::integer IS NULL THEN
                       NOT EXISTS (
                           SELECT 1 FROM work_hours wh
                           WHERE wh.weekday = EXTRACT(ISODOW FROM cd.day)::integer - 1
                       )
                   ELSE NOT EXISTS (
                       SELECT 1 FROM work_hours wh
                       WHERE wh.doctor_id = %s
                         AND wh.weekday = EXTRACT(ISODOW FROM cd.day)::integer - 1
                   )
               END AS day_off,
               h.name AS holiday_name,
               EXISTS (
                   SELECT 1 FROM time_off t
                   WHERE t.doctor_id = %s
                     AND cd.day BETWEEN t.starts_on AND t.ends_on
               ) AS selected_doctor_time_off,
               s.id, s.doctor_id, d.full_name, svc.name,
               s.starts_at,
               s.starts_at + make_interval(mins => s.duration_minutes),
               s.starts_at > CURRENT_TIMESTAMP AS slot_future,
               EXISTS (
                   SELECT 1 FROM time_off t
                   WHERE t.doctor_id = s.doctor_id
                     AND cd.day BETWEEN t.starts_on AND t.ends_on
               ) AS slot_time_off,
               a.id, a.starts_at, a.ends_at, a.status,
               booked_service.name,
               public.calendar_patient_email(a.patient_user_id, a.doctor_id)
        FROM calendar_days cd
        LEFT JOIN holidays h ON h.day = cd.day
        LEFT JOIN slots s
          ON s.starts_at >= cd.day::timestamp
         AND s.starts_at < (cd.day + 1)::timestamp
         AND (%s::integer IS NULL OR s.doctor_id = %s)
        LEFT JOIN doctors d ON d.id = s.doctor_id
        LEFT JOIN services svc ON svc.id = s.service_id
        LEFT JOIN appointments a
          ON a.doctor_id = s.doctor_id
         AND a.status = 'scheduled'
         AND a.starts_at < s.ends_at
         AND a.reserved_ends_at > s.starts_at
        LEFT JOIN slots booked_slot ON booked_slot.id = a.slot_id
        LEFT JOIN services booked_service ON booked_service.id = booked_slot.service_id
        ORDER BY cd.day, s.starts_at, d.full_name, a.starts_at, a.id
        """,
        (
            start_day,
            day_count - 1,
            doctor_id,
            doctor_id,
            doctor_id,
            doctor_id,
            doctor_id,
        ),
    )
    rows = cur.fetchall()
    calendar_days = {}
    for day_offset in range(day_count):
        day = start_day + timedelta(days=day_offset)
        calendar_days[day] = {
            "day": day,
            "is_day_off": False,
            "holiday_name": None,
            "selected_doctor_time_off": False,
            "slots": {},
            "appointments": {},
        }

    for row in rows:
        day_state = calendar_days[row[0]]
        day_state["is_day_off"] = row[1]
        day_state["holiday_name"] = row[2]
        day_state["selected_doctor_time_off"] = row[3]
        if row[4] is None:
            continue

        slot = day_state["slots"].setdefault(
            row[4],
            {
                "id": row[4],
                "doctor_name": row[6],
                "service_name": row[7],
                "starts_at": row[8],
                "ends_at": row[9],
                "future": row[10],
                "time_off": row[11],
                "has_appointment": False,
            },
        )
        if row[12] is not None:
            slot["has_appointment"] = True
            appointment = day_state["appointments"].setdefault(
                row[12],
                {
                    "id": row[12],
                    "doctor_name": row[6],
                    "service_name": row[16],
                    "patient_email": row[17],
                    "starts_at": row[13],
                    "ends_at": row[14],
                    "status": row[15],
                    "time_off": row[11],
                },
            )
            appointment["time_off"] = appointment["time_off"] or row[11]

    result_days = []
    time_rows = set()
    for day_state in calendar_days.values():
        closed_reasons = []
        if day_state["is_day_off"]:
            closed_reasons.append("day off")
        if day_state["holiday_name"]:
            closed_reasons.append(f"holiday: {day_state['holiday_name']}")
        if day_state["selected_doctor_time_off"]:
            closed_reasons.append("doctor time off")
        events_by_time = {}

        def add_event(event):
            time_label = event["starts_at"].strftime("%H:%M")
            time_rows.add(time_label)
            events_by_time.setdefault(time_label, []).append(event)

        for appointment in day_state["appointments"].values():
            appointment_reasons = list(closed_reasons)
            if appointment["time_off"] and "doctor time off" not in appointment_reasons:
                appointment_reasons.append("doctor time off")
            appointment["closed_reasons"] = appointment_reasons
            add_event(appointment)

        if role == "doctor":
            for slot in day_state["slots"].values():
                if not slot["service_name"] or slot["has_appointment"]:
                    continue
                slot_reasons = list(closed_reasons)
                if slot["time_off"] and "doctor time off" not in slot_reasons:
                    slot_reasons.append("doctor time off")
                if slot_reasons:
                    status = "closed"
                elif slot["future"]:
                    status = "available"
                else:
                    status = "past"
                add_event(
                    {
                        "doctor_name": slot["doctor_name"],
                        "service_name": slot["service_name"],
                        "patient_email": None,
                        "starts_at": slot["starts_at"],
                        "ends_at": slot["ends_at"],
                        "status": status,
                        "closed_reasons": slot_reasons,
                    }
                )

        for events in events_by_time.values():
            events.sort(key=lambda event: (event["starts_at"], event["doctor_name"] or ""))
        result_days.append(
            {
                "day": day_state["day"],
                "closed_reasons": closed_reasons,
                "closed": bool(closed_reasons),
                "cells": events_by_time,
            }
        )
    return result_days, sorted(time_rows)


@router.get("/registrar/appointments")
def registrar_appointments(request: Request):
    user, denied = require_user(request, "registrar")
    if denied:
        return denied

    selected_day, view, errors = _calendar_state(request)
    raw_doctor_id = request.query_params.get("doctor_id")
    doctor_id = parse_strict_int(raw_doctor_id) if raw_doctor_id else None
    if raw_doctor_id and doctor_id is None:
        errors.append("invalid_doctor")

    conn = db_as(user)
    cur = conn.cursor()
    cur.execute("SELECT id, full_name FROM doctors ORDER BY full_name")
    doctors = [{"id": row[0], "full_name": row[1]} for row in cur.fetchall()]
    doctor_ids = {doctor["id"] for doctor in doctors}
    if doctor_id not in doctor_ids:
        if doctor_id is not None:
            errors.append("invalid_doctor")
        doctor_id = None

    day_count = 7 if view == "week" else 1
    start_day = (
        selected_day - timedelta(days=selected_day.weekday())
        if view == "week"
        else selected_day
    )
    calendar_days, time_rows = _load_calendar(
        cur, start_day, day_count, doctor_id, "registrar"
    )
    cur.close()
    conn.close()
    return templates.TemplateResponse(
        "calendar.html",
        {
            "request": request,
            "role": user["role"],
            "calendar_title": "Appointments by day" if view == "day" else "Appointments by week",
            "calendar_path": "/registrar/appointments",
            "selected_day": selected_day,
            "view": view,
            "day_count": day_count,
            "days": calendar_days,
            "time_rows": time_rows,
            "doctors": doctors,
            "doctor_id": doctor_id,
            "errors": errors,
            "navigation": _calendar_navigation(
                "/registrar/appointments", view, selected_day, doctor_id
            ),
            "requests": [],
            "doctor": None,
        },
    )


@router.get("/doctor/calendar")
def doctor_calendar(request: Request):
    user, denied = require_user(request, "doctor")
    if denied:
        return denied
    selected_day, view, errors = _calendar_state(request)
    doctor_id = None
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

    doctor_id = doctor[0]
    day_count = 7 if view == "week" else 1
    start_day = (
        selected_day - timedelta(days=selected_day.weekday())
        if view == "week"
        else selected_day
    )
    calendar_days, time_rows = _load_calendar(
        cur, start_day, day_count, doctor_id, "doctor"
    )
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

    return templates.TemplateResponse(
        "calendar.html",
        {
            "request": request,
            "role": user["role"],
            "doctor": {"id": doctor[0], "full_name": doctor[1]},
            "calendar_title": f"Calendar: {doctor[1]}",
            "calendar_path": "/doctor/calendar",
            "selected_day": selected_day,
            "view": view,
            "day_count": day_count,
            "days": calendar_days,
            "time_rows": time_rows,
            "doctors": [],
            "doctor_id": doctor_id,
            "errors": errors,
            "navigation": _calendar_navigation(
                "/doctor/calendar", view, selected_day
            ),
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
