from datetime import date, datetime, timedelta
from datetime import time as datetime_time
from typing import List

import psycopg2
from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from db import (
    MAX_SLOT_MINUTES,
    MAX_TEXT_LENGTH,
    db_as,
    parse_strict_int,
    templates,
    within_length,
)
from routes_auth import require_user





router = APIRouter()

@router.get("/admin/users")
def admin_users(request: Request):
    admin_user, denied = require_user(request, "admin")
    if denied:
        return denied
    conn = db_as(admin_user)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT p.id, p.email, p.blocked,
               (
                   SELECT count(*)
                   FROM appointments a
                   JOIN slots s ON s.id = a.slot_id
                   WHERE a.patient_user_id = p.id
                     AND a.status = 'scheduled'
                     AND s.starts_at > CURRENT_TIMESTAMP
               ) AS future_scheduled
        FROM users p
        WHERE p.role='patient'
        ORDER BY p.email
        """
    )
    users = [
        {
            "id": row[0],
            "email": row[1],
            "blocked": row[2],
            "future_scheduled": row[3],
        }
        for row in cur.fetchall()
    ]
    cur.close()
    conn.close()
    return templates.TemplateResponse(
        "admin_users.html",
        {
            "request": request,
            "users": users,
            "role": "admin",
            "future_cancelled": request.query_params.get("future_cancelled"),
        },
    )


def _purge_slots_without_scheduled(cur, where_sql, params):
   #cancelled 
    cur.execute(
        f"""
        DELETE FROM appointments a
        WHERE a.status <> 'scheduled'
          AND a.slot_id IN (
              SELECT s.id
              FROM slots s
              WHERE {where_sql}
                AND NOT EXISTS (
                    SELECT 1 FROM appointments live
                    WHERE live.slot_id = s.id AND live.status = 'scheduled'
                )
          )
        """,
        params,
    )
    cur.execute(
        f"""
        DELETE FROM slots s
        WHERE {where_sql}
          AND NOT EXISTS (
              SELECT 1 FROM appointments a
              WHERE a.slot_id = s.id AND a.status = 'scheduled'
          )
        """,
        params,
    )
    return cur.rowcount


def _outside_hours_sql(alias="s"):
    # work_hours.weekday 
    return f"""
        NOT EXISTS (
            SELECT 1 FROM work_hours w
            WHERE w.doctor_id = {alias}.doctor_id
              AND w.weekday = ((EXTRACT(DOW FROM {alias}.starts_at)::int + 6) %% 7)
              AND {alias}.starts_at::date = {alias}.ends_at::date
              AND {alias}.starts_at::time >= w.start_time
              AND {alias}.ends_at::time <= w.end_time
        )
    """


def _scheduled_visit_rows(cur, where_sql, params):
    cur.execute(
        f"""
        SELECT a.id, u.email, d.full_name, s.starts_at, s.ends_at
        FROM appointments a
        JOIN users u ON u.id = a.patient_user_id
        JOIN slots s ON s.id = a.slot_id
        JOIN doctors d ON d.id = s.doctor_id
        WHERE a.status = 'scheduled'
          AND {where_sql}
        ORDER BY s.starts_at
        """,
        params,
    )
    return [
        {
            "appointment_id": row[0],
            "patient_email": row[1],
            "doctor_name": row[2],
            "starts_at": row[3],
            "ends_at": row[4],
        }
        for row in cur.fetchall()
    ]


def _close_slots_for_period(cur, starts_on: date, ends_on: date, doctor_id=None):
    if doctor_id is None:
        where_sql = "s.starts_at::date BETWEEN %s AND %s"
        params = (starts_on, ends_on)
    else:
        where_sql = "s.doctor_id=%s AND s.starts_at::date BETWEEN %s AND %s"
        params = (doctor_id, starts_on, ends_on)
    scheduled_visits = _scheduled_visit_rows(cur, where_sql, params)
    removed = _purge_slots_without_scheduled(cur, where_sql, params)
    return removed, scheduled_visits


@router.get("/admin/schedule")
def admin_schedule(request: Request):
    admin_user, denied = require_user(request, "admin")
    if denied:
        return denied
    conn = db_as(admin_user)
    cur = conn.cursor()
    cur.execute("SELECT id, full_name FROM doctors ORDER BY full_name")
    doctors = [{"id": row[0], "full_name": row[1]} for row in cur.fetchall()]
    cur.execute(
        """
        SELECT d.full_name, w.weekday, w.start_time, w.end_time, w.slot_minutes
        FROM work_hours w
        JOIN doctors d ON d.id=w.doctor_id
        ORDER BY d.full_name, w.weekday
        """
    )
    work_hours = [
        {
            "doctor_name": row[0],
            "weekday": row[1],
            "start_time": row[2],
            "end_time": row[3],
            "slot_minutes": row[4],
        }
        for row in cur.fetchall()
    ]
    cur.execute(
        """
        SELECT d.full_name, t.starts_on, t.ends_on
        FROM time_off t
        JOIN doctors d ON d.id=t.doctor_id
        ORDER BY d.full_name, t.starts_on
        """
    )
    time_off = [
        {"doctor_name": row[0], "starts_on": row[1], "ends_on": row[2]}
        for row in cur.fetchall()
    ]
    cur.execute("SELECT day, name FROM holidays ORDER BY day")
    holidays = [{"day": row[0], "name": row[1]} for row in cur.fetchall()]
    closure_report = request.session.pop("closure_report", None)
    hours_report = request.session.pop("hours_report", None)
    manual_cancel_visits = _scheduled_visit_rows(
        cur,
        """
        (
            EXISTS (SELECT 1 FROM holidays h WHERE h.day = s.starts_at::date)
            OR EXISTS (
                SELECT 1 FROM time_off t
                WHERE t.doctor_id = s.doctor_id
                  AND s.starts_at::date BETWEEN t.starts_on AND t.ends_on
            )
        )
        """,
        (),
    )
    outside_hours_visits = _scheduled_visit_rows(cur, _outside_hours_sql("s"), ())
    cur.close()
    conn.close()
    return templates.TemplateResponse(
        "admin_schedule.html",
        {
            "request": request,
            "role": admin_user["role"],
            "doctors": doctors,
            "work_hours": work_hours,
            "time_off": time_off,
            "holidays": holidays,
            "closure_report": closure_report,
            "hours_report": hours_report,
            "manual_cancel_visits": manual_cancel_visits,
            "outside_hours_visits": outside_hours_visits,
            "visit_cancelled": request.query_params.get("visit_cancelled"),
            "weekdays": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"],
            "saved": request.query_params.get("saved"),
            "error": request.query_params.get("error"),
            "generated": request.query_params.get("generated"),
            "skipped": request.query_params.get("skipped"),
        },
    )


@router.post("/admin/work-hours-bulk")
def admin_save_work_hours_bulk(
    request: Request,
    doctor_id: str = Form(...),
    weekdays: List[str] = Form(default=[]),
    start_time: datetime_time = Form(...),
    end_time: datetime_time = Form(...),
    slot_minutes: str = Form(...),
):
    admin_user, denied = require_user(request, "admin")
    if denied:
        return denied
    parsed_doctor_id = parse_strict_int(doctor_id, min_value=1)
    parsed_slot_minutes = parse_strict_int(slot_minutes, min_value=1, max_value=MAX_SLOT_MINUTES)
    if parsed_doctor_id is None or parsed_slot_minutes is None:
        return RedirectResponse("/admin/schedule?error=invalid_id", status_code=303)
    doctor_id = parsed_doctor_id
    slot_minutes = parsed_slot_minutes
    if start_time >= end_time:
        return RedirectResponse("/admin/schedule?error=invalid_work_hours", status_code=303)
    selected = sorted({day for day in (parse_strict_int(raw, min_value=0, max_value=6) for raw in weekdays) if day is not None})
    if not selected:
        return RedirectResponse("/admin/schedule?error=no_weekdays", status_code=303)

    conn = db_as(admin_user)
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM doctors WHERE id=%s", (doctor_id,))
    if cur.fetchone() is None:
        cur.close()
        conn.close()
        return RedirectResponse("/admin/schedule?error=doctor_not_found", status_code=303)

    for weekday in selected:
        cur.execute(
            """
            INSERT INTO work_hours (doctor_id, weekday, start_time, end_time, slot_minutes)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (doctor_id, weekday) DO UPDATE
            SET start_time=EXCLUDED.start_time,
                end_time=EXCLUDED.end_time,
                slot_minutes=EXCLUDED.slot_minutes
            """,
            (doctor_id, weekday, start_time, end_time, slot_minutes),
        )
    conn.commit()
    cur.close()
    conn.close()
    return RedirectResponse("/admin/schedule?saved=work-hours-bulk", status_code=303)


@router.post("/admin/doctors/{doctor_id}/apply-hours")
def admin_apply_hours(request: Request, doctor_id: str):
    admin_user, denied = require_user(request, "admin")
    if denied:
        return denied
    doctor_id = parse_strict_int(doctor_id, min_value=1)
    if doctor_id is None:
        return RedirectResponse("/admin/schedule?error=doctor_not_found", status_code=303)
    conn = db_as(admin_user)
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM doctors WHERE id=%s", (doctor_id,))
    if cur.fetchone() is None:
        cur.close()
        conn.close()
        return RedirectResponse("/admin/schedule?error=doctor_not_found", status_code=303)
    where_sql = f"s.doctor_id=%s AND {_outside_hours_sql('s')}"
    removed = _purge_slots_without_scheduled(cur, where_sql, (doctor_id,))
    conn.commit()
    cur.close()
    conn.close()
    request.session["hours_report"] = {
        "doctor_id": doctor_id,
        "removed_slots": removed,
    }
    return RedirectResponse("/admin/schedule?saved=apply-hours", status_code=303)


@router.post("/admin/time-off")
def admin_add_time_off(
    request: Request,
    doctor_id: str = Form(...),
    starts_on: date = Form(...),
    ends_on: date = Form(...),
):
    admin_user, denied = require_user(request, "admin")
    if denied:
        return denied
    doctor_id = parse_strict_int(doctor_id, min_value=1)
    if doctor_id is None:
        return RedirectResponse("/admin/schedule?error=doctor_not_found", status_code=303)
    if starts_on > ends_on:
        return RedirectResponse("/admin/schedule?error=invalid_time_off", status_code=303)
    conn = db_as(admin_user)
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM doctors WHERE id=%s", (doctor_id,))
    if cur.fetchone() is None:
        cur.close()
        conn.close()
        return RedirectResponse("/admin/schedule?error=doctor_not_found", status_code=303)
    cur.execute(
        """
        INSERT INTO time_off (doctor_id, starts_on, ends_on)
        VALUES (%s, %s, %s)
        ON CONFLICT (doctor_id, starts_on, ends_on) DO NOTHING
        """,
        (doctor_id, starts_on, ends_on),
    )
    removed_slots, _ = _close_slots_for_period(cur, starts_on, ends_on, doctor_id)
    conn.commit()
    cur.close()
    conn.close()
    request.session["closure_report"] = {
        "kind": "time-off",
        "starts_on": starts_on.isoformat(),
        "ends_on": ends_on.isoformat(),
        "doctor_id": doctor_id,
        "removed_slots": removed_slots,
    }
    return RedirectResponse("/admin/schedule?saved=time-off", status_code=303)


@router.post("/admin/holidays")
def admin_save_holiday(
    request: Request,
    holiday_day: date = Form(...),
    name: str = Form(...),
):
    admin_user, denied = require_user(request, "admin")
    if denied:
        return denied
    holiday_name = name.strip()
    if not holiday_name:
        return RedirectResponse("/admin/schedule?error=holiday_name_required", status_code=303)
    if not within_length(holiday_name, MAX_TEXT_LENGTH):
        return RedirectResponse("/admin/schedule?error=text_too_long", status_code=303)
    conn = db_as(admin_user)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO holidays (day, name)
        VALUES (%s, %s)
        ON CONFLICT (day) DO UPDATE SET name=EXCLUDED.name
        """,
        (holiday_day, holiday_name),
    )
    removed_slots, _ = _close_slots_for_period(cur, holiday_day, holiday_day)
    conn.commit()
    cur.close()
    conn.close()
    request.session["closure_report"] = {
        "kind": "holiday",
        "starts_on": holiday_day.isoformat(),
        "ends_on": holiday_day.isoformat(),
        "doctor_id": None,
        "removed_slots": removed_slots,
    }
    return RedirectResponse("/admin/schedule?saved=holiday", status_code=303)


@router.post("/admin/doctors/{doctor_id}/generate")
def generate_doctor_slots(
    request: Request,
    doctor_id: str,
    from_date: date = Form(...),
    to_date: date = Form(...),
):
    admin_user, denied = require_user(request, "admin")
    if denied:
        return denied
    doctor_id = parse_strict_int(doctor_id, min_value=1)
    if doctor_id is None:
        return RedirectResponse("/admin/schedule?error=doctor_not_found", status_code=303)
    if from_date > to_date or (to_date - from_date).days > 90:
        return RedirectResponse("/admin/schedule?error=invalid_range", status_code=303)

    conn = db_as(admin_user)
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM doctors WHERE id=%s", (doctor_id,))
    if cur.fetchone() is None:
        cur.close()
        conn.close()
        return RedirectResponse("/admin/schedule?error=doctor_not_found", status_code=303)

    cur.execute(
        """
        SELECT weekday, start_time, end_time, slot_minutes
        FROM work_hours
        WHERE doctor_id=%s
        ORDER BY weekday
        """,
        (doctor_id,),
    )
    work_hours = cur.fetchall()
    cur.execute(
        """
        SELECT starts_on, ends_on
        FROM time_off
        WHERE doctor_id=%s AND starts_on <= %s AND ends_on >= %s
        """,
        (doctor_id, to_date, from_date),
    )
    time_off = cur.fetchall()
    cur.execute(
        "SELECT day FROM holidays WHERE day BETWEEN %s AND %s",
        (from_date, to_date),
    )
    holidays = {row[0] for row in cur.fetchall()}

    created = 0
    skipped = 0
    cur.execute("SELECT CURRENT_TIMESTAMP::timestamp")
    now = cur.fetchone()[0]
    today = now.date()
    current_date = from_date
    while current_date <= to_date:
        day_hours = [row for row in work_hours if row[0] == current_date.weekday()]
        is_day_off = (
            current_date in holidays
            or any(start <= current_date <= end for start, end in time_off)
        )
        for _, start_time, end_time, slot_minutes in day_hours:
            slot_duration = timedelta(minutes=slot_minutes)
            start_at = datetime.combine(current_date, start_time)
            day_end = datetime.combine(current_date, end_time)
            if is_day_off:
                while start_at + slot_duration <= day_end:
                    skipped += 1
                    start_at += slot_duration
                continue
            while start_at + slot_duration <= day_end:
                if current_date < today or start_at <= now:
                    skipped += 1
                    start_at += slot_duration
                    continue
                cur.execute("SAVEPOINT generate_slot")
                try:
                    cur.execute(
                        """
                        INSERT INTO slots (doctor_id, starts_at, ends_at)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (doctor_id, starts_at) DO NOTHING
                        """,
                        (doctor_id, start_at, start_at + slot_duration),
                    )
                    if cur.rowcount:
                        created += 1
                    else:
                        skipped += 1
                except psycopg2.errors.ExclusionViolation:
                    cur.execute("ROLLBACK TO SAVEPOINT generate_slot")
                    skipped += 1
                finally:
                    cur.execute("RELEASE SAVEPOINT generate_slot")
                start_at += slot_duration

        current_date += timedelta(days=1)

    conn.commit()
    cur.close()
    conn.close()
    return RedirectResponse(
        f"/admin/schedule?generated={created}&skipped={skipped}",
        status_code=303,
    )


@router.post("/admin/users/{user_id}/block")
def block_user(request: Request, user_id: str):
    admin_user, denied = require_user(request, "admin")
    if denied:
        return denied
    user_id = parse_strict_int(user_id, min_value=1)
    if user_id is None:
        return RedirectResponse("/admin/users", status_code=303)
    conn = db_as(admin_user)
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET blocked=TRUE WHERE id=%s AND role='patient'",
        (user_id,),
    )
    conn.commit()
    cur.close()
    conn.close()
    return RedirectResponse("/admin/users", status_code=303)


@router.post("/admin/users/{user_id}/unblock")
def unblock_user(request: Request, user_id: str):
    admin_user, denied = require_user(request, "admin")
    if denied:
        return denied
    user_id = parse_strict_int(user_id, min_value=1)
    if user_id is None:
        return RedirectResponse("/admin/users", status_code=303)
    conn = db_as(admin_user)
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET blocked=FALSE WHERE id=%s AND role='patient'",
        (user_id,),
    )
    conn.commit()
    cur.close()
    conn.close()
    return RedirectResponse("/admin/users", status_code=303)


@router.post("/admin/users/{user_id}/cancel-future-appointments")
def cancel_future_appointments(request: Request, user_id: str):
    admin_user, denied = require_user(request, "admin")
    if denied:
        return denied
    user_id = parse_strict_int(user_id, min_value=1)
    if user_id is None:
        return RedirectResponse("/admin/users", status_code=303)
    conn = db_as(admin_user)
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE appointments a
        SET status='cancelled'
        FROM slots s, users u
        WHERE a.slot_id=s.id
          AND a.patient_user_id=u.id
          AND u.id=%s
          AND u.role='patient'
          AND a.status='scheduled'
          AND s.starts_at > CURRENT_TIMESTAMP
        """,
        (user_id,),
    )
    cancelled_count = cur.rowcount
    conn.commit()
    cur.close()
    conn.close()
    return RedirectResponse(
        f"/admin/users?future_cancelled={cancelled_count}", status_code=303
    )
