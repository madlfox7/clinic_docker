from datetime import date, datetime, timedelta
from datetime import time as datetime_time
from typing import List

import psycopg2
from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from urllib.parse import urlencode

from db import (
    ADDRESS_MAX_LENGTH,
    EXPERIENCE_MAX_YEARS,
    MAX_CLOSURE_DAYS,
    MAX_FUTURE_DAYS,
    MAX_PASSWORD_LENGTH,
    MAX_SLOT_MINUTES,
    NAME_MAX_LENGTH,
    SERVICE_BUFFER_MAX,
    SERVICE_DURATION_MAX,
    SERVICE_DURATION_MIN,
    SLOT_MINUTES_MAX,
    SLOT_MINUTES_MIN,
    clean_label,
    clean_optional_text,
    clean_phone,
    contains_nul,
    has_control_char,
    db,
    db_as,
    load_appointment_notice,
    log,
    parse_strict_int,
    record_audit_event,
    templates,
    within_length,
)
from mailer import deliver_appointment_emails, smtp_ready
from routes_auth import (
    _normalize_registration_email,
    deliver_password_reset,
    require_user,
)





router = APIRouter()

def _discard_invite(token: str) -> None:
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT public.discard_undelivered_invite(%s)",
                (token,),
            )
        conn.commit()
    finally:
        conn.close()

@router.get("/admin/audit")
def admin_audit(request: Request):
    admin_user, denied = require_user(request, "admin")
    if denied:
        return denied
    conn = db_as(admin_user)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT e.created_at, u.email, e.actor_role, e.action,
               e.target_type, e.target_id
        FROM audit_events e
        JOIN users u ON u.id = e.actor_user_id
        ORDER BY e.created_at DESC, e.id DESC
        LIMIT 100
        """
    )
    events = [
        {
            "created_at": row[0],
            "actor_email": row[1],
            "actor_role": row[2],
            "action": row[3],
            "target_type": row[4],
            "target_id": row[5],
        }
        for row in cur.fetchall()
    ]
    cur.close()
    conn.close()
    return templates.TemplateResponse(
        "admin_audit.html",
        {"request": request, "role": admin_user["role"], "events": events},
    )


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
    cur.execute(
        """
        SELECT id, email, role, blocked
        FROM users
        WHERE role IN ('admin', 'registrar')
        ORDER BY role, email
        """
    )
    staff_users = [
        {"id": row[0], "email": row[1], "role": row[2], "blocked": row[3]}
        for row in cur.fetchall()
    ]
    cur.close()
    conn.close()
    return templates.TemplateResponse(
        "admin_users.html",
        {
            "request": request,
            "users": users,
            "staff_users": staff_users,
            "role": "admin",
            "current_admin_id": admin_user["id"],
            "future_cancelled": request.query_params.get("future_cancelled"),
            "error": request.query_params.get("error"),
            "staff_email": request.query_params.get("email", ""),
            "staff_role": request.query_params.get("role", ""),
            "created": request.query_params.get("created"),
            "password_reset": request.query_params.get("password_reset"),
            "password_link": request.query_params.get("password_link"),
        },
    )


@router.post("/admin/users")
def create_staff_user(
    request: Request,
    email: str = Form(...),
    role: str = Form(...),
    current_password: str = Form(""),
):
    admin_user, denied = require_user(request, "admin")
    if denied:
        return denied
    normalized_email = _normalize_registration_email(email)
    role = role.strip().lower()
    def staff_error(code):
        params = {"error": code, "role": role}
        if normalized_email:
            params["email"] = normalized_email
        return RedirectResponse(
            "/admin/users?" + urlencode(params), status_code=303
        )

    if contains_nul(email, role, current_password):
        return staff_error("invalid_email")
    if normalized_email is None:
        return RedirectResponse("/admin/users?error=invalid_email", status_code=303)
    if role not in ("registrar", "admin"):
        return RedirectResponse("/admin/users?error=invalid_role", status_code=303)
    if role == "admin" and (
        current_password == ""
        or not within_length(current_password, MAX_PASSWORD_LENGTH)
    ):
        return staff_error("password_required")
    if not smtp_ready():
        return staff_error("password_link_failed")

    conn = db_as(admin_user)
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT status, invited_user_id, recipient, reset_token
                    FROM public.admin_invite_staff(%s, %s, %s)
                    """,
                    (
                        normalized_email,
                        role,
                        current_password if role == "admin" else None,
                    ),
                )
                row = cur.fetchone()
    except psycopg2.errors.UniqueViolation:
        return staff_error("email_exists")
    finally:
        conn.close()
    status, _user_id, recipient, token = row if row else ("invalid", None, None, None)
    if status != "issued" or not recipient or not token:
        error = {
            "rate_limited": "password_link_rate_limited",
            "password_required": "password_required",
            "password_denied": "password_denied",
        }.get(status, "invalid_email")
        return staff_error(error)
    if not deliver_password_reset(recipient, token):
        _discard_invite(token)
        return staff_error("password_link_failed")
    return RedirectResponse("/admin/users?created=1", status_code=303)


def _admin_page(next_page: str) -> str:
    return "/admin/doctors" if next_page == "doctors" else "/admin/users"


@router.post("/admin/users/{user_id}/password")
def reset_user_password(request: Request, user_id: str):
    admin_user, denied = require_user(request, "admin")
    if denied:
        return denied
    return RedirectResponse(
        "/admin/users?error=password_reset_not_allowed", status_code=303
    )


@router.post("/admin/users/{user_id}/reset-link")
def send_user_password_reset_link(
    request: Request,
    user_id: str,
    next_page: str = Form("users"),
):
    admin_user, denied = require_user(request, "admin")
    if denied:
        return denied
    page = _admin_page(next_page)
    parsed_user_id = parse_strict_int(user_id, min_value=1)
    if parsed_user_id is None:
        return RedirectResponse(f"{page}?error=user_not_found", status_code=303)
    if not smtp_ready():
        return RedirectResponse(f"{page}?error=password_link_failed", status_code=303)

    conn = db_as(admin_user)
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT status, recipient, reset_token, target_role
                    FROM public.admin_request_password_reset(%s)
                    """,
                    (parsed_user_id,),
                )
                row = cur.fetchone()
    finally:
        conn.close()
    status, recipient, token, target_role = row if row else (
        "not_allowed",
        None,
        None,
        None,
    )
    if status == "self":
        return RedirectResponse(f"{page}?error=password_link_self", status_code=303)
    if status == "last_admin":
        return RedirectResponse(f"{page}?error=last_admin", status_code=303)
    if status == "rate_limited":
        return RedirectResponse(
            f"{page}?error=password_link_rate_limited", status_code=303
        )
    if status != "issued" or not recipient or not token:
        return RedirectResponse(
            f"{page}?error=password_link_not_allowed", status_code=303
        )
    if not deliver_password_reset(recipient, token):
        return RedirectResponse(f"{page}?error=password_link_failed", status_code=303)

    conn = db_as(admin_user)
    try:
        with conn:
            with conn.cursor() as cur:
                record_audit_event(
                    cur, "user.password_link", target_role or "user", parsed_user_id
                )
    finally:
        conn.close()
    return RedirectResponse(f"{page}?password_link=1", status_code=303)


@router.get("/admin/services")
def admin_services(request: Request):
    admin_user, denied = require_user(request, "admin")
    if denied:
        return denied
    conn = db_as(admin_user)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT svc.id, svc.name, svc.duration_minutes, svc.buffer_minutes,
               svc.active, count(s.id)
        FROM services svc
        LEFT JOIN slots s ON s.service_id = svc.id
        GROUP BY svc.id
        ORDER BY svc.name, svc.id
        """
    )
    services = [
        {
            "id": row[0],
            "name": row[1],
            "duration_minutes": row[2],
            "buffer_minutes": row[3],
            "active": row[4],
            "slot_count": row[5],
        }
        for row in cur.fetchall()
    ]
    cur.execute(
        """
        SELECT d.id, d.full_name
        FROM doctors d
        ORDER BY d.full_name, d.id
        """
    )
    doctors = [{"id": row[0], "full_name": row[1]} for row in cur.fetchall()]
    cur.execute("SELECT doctor_id, service_id FROM doctor_services")
    assigned_doctors = {}
    for doctor_id, service_id in cur.fetchall():
        assigned_doctors.setdefault(service_id, []).append(doctor_id)
    for service in services:
        service["doctor_ids"] = assigned_doctors.get(service["id"], [])
    cur.close()
    conn.close()
    return templates.TemplateResponse(
        "admin_services.html",
        {
            "request": request,
            "role": admin_user["role"],
            "services": services,
            "doctors": doctors,
            "created": request.query_params.get("created"),
            "updated": request.query_params.get("updated"),
            "activation": request.query_params.get("activation"),
            "deleted": request.query_params.get("deleted"),
            "error": request.query_params.get("error"),
        },
    )


def _validate_service_details(name: str, duration: str, buffer: str):
    cleaned_name = clean_label(name, max_length=NAME_MAX_LENGTH)
    duration_minutes = parse_strict_int(
        duration, min_value=SERVICE_DURATION_MIN, max_value=SERVICE_DURATION_MAX
    )
    buffer_minutes = parse_strict_int(
        buffer, min_value=0, max_value=SERVICE_BUFFER_MAX
    )
    if (
        cleaned_name is None
        or duration_minutes is None
        or buffer_minutes is None
        or duration_minutes + buffer_minutes > MAX_SLOT_MINUTES
    ):
        return None
    return cleaned_name, duration_minutes, buffer_minutes


def _parse_doctor_ids(raw_ids: List[str]):
    doctor_ids = []
    for raw_id in raw_ids:
        doctor_id = parse_strict_int(raw_id, min_value=1)
        if doctor_id is None or doctor_id in doctor_ids:
            return None
        doctor_ids.append(doctor_id)
    return doctor_ids


def _valid_service_doctors(cur, doctor_ids):
    if not doctor_ids:
        return True
    cur.execute(
        "SELECT count(*) FROM doctors WHERE id = ANY(%s)",
        (doctor_ids,),
    )
    return cur.fetchone()[0] == len(doctor_ids)


def _replace_service_doctors(cur, service_id, doctor_ids):
    cur.execute("DELETE FROM doctor_services WHERE service_id = %s", (service_id,))
    for doctor_id in doctor_ids:
        cur.execute(
            """
            INSERT INTO doctor_services (doctor_id, service_id)
            VALUES (%s, %s)
            """,
            (doctor_id, service_id),
        )


def _future_appointments_for_removed_service_doctors(cur, service_id, doctor_ids):
    cur.execute(
        """
        SELECT d.full_name, count(a.id)
        FROM doctor_services ds
        JOIN doctors d ON d.id = ds.doctor_id
        JOIN slots s
          ON s.doctor_id = ds.doctor_id AND s.service_id = ds.service_id
        JOIN appointments a
          ON a.slot_id = s.id
         AND a.status = 'scheduled'
         AND a.starts_at > CURRENT_TIMESTAMP
        WHERE ds.service_id = %s
          AND NOT (ds.doctor_id = ANY(%s::int[]))
        GROUP BY d.id, d.full_name
        ORDER BY d.full_name
        """,
        (service_id, doctor_ids),
    )
    return cur.fetchall()


@router.post("/admin/services")
def create_service(
    request: Request,
    name: str = Form(...),
    duration_minutes: str = Form(...),
    buffer_minutes: str = Form("0"),
    doctor_ids: List[str] = Form([]),
):
    admin_user, denied = require_user(request, "admin")
    if denied:
        return denied
    service = _validate_service_details(name, duration_minutes, buffer_minutes)
    parsed_doctor_ids = _parse_doctor_ids(doctor_ids)
    if service is None or parsed_doctor_ids is None:
        return RedirectResponse("/admin/services?error=invalid_service", status_code=303)
    conn = db_as(admin_user)
    try:
        with conn:
            with conn.cursor() as cur:
                if not _valid_service_doctors(cur, parsed_doctor_ids):
                    return RedirectResponse(
                        "/admin/services?error=invalid_doctor", status_code=303
                    )
                cur.execute(
                    """
                    INSERT INTO services (name, duration_minutes, buffer_minutes)
                    VALUES (%s, %s, %s)
                    RETURNING id
                    """,
                    service,
                )
                service_id = cur.fetchone()[0]
                _replace_service_doctors(cur, service_id, parsed_doctor_ids)
                record_audit_event(cur, "service.create", "service", service_id)
    except psycopg2.errors.UniqueViolation:
        return RedirectResponse("/admin/services?error=name_exists", status_code=303)
    except psycopg2.errors.CheckViolation:
        return RedirectResponse("/admin/services?error=invalid_service", status_code=303)
    finally:
        conn.close()
    return RedirectResponse("/admin/services?created=1", status_code=303)


@router.post("/admin/services/{service_id}")
def update_service(
    request: Request,
    service_id: str,
    name: str = Form(...),
    duration_minutes: str = Form(...),
    buffer_minutes: str = Form("0"),
    doctor_ids: List[str] = Form([]),
):
    admin_user, denied = require_user(request, "admin")
    if denied:
        return denied
    parsed_service_id = parse_strict_int(service_id, min_value=1)
    service = _validate_service_details(name, duration_minutes, buffer_minutes)
    parsed_doctor_ids = _parse_doctor_ids(doctor_ids)
    if parsed_service_id is None:
        return RedirectResponse("/admin/services?error=service_not_found", status_code=303)
    if service is None or parsed_doctor_ids is None:
        return RedirectResponse("/admin/services?error=invalid_service", status_code=303)
    conn = db_as(admin_user)
    try:
        with conn:
            with conn.cursor() as cur:
                if not _valid_service_doctors(cur, parsed_doctor_ids):
                    return RedirectResponse(
                        "/admin/services?error=invalid_doctor", status_code=303
                    )
                cur.execute(
                    "SELECT id FROM services WHERE id = %s",
                    (parsed_service_id,),
                )
                if cur.fetchone() is None:
                    return RedirectResponse(
                        "/admin/services?error=service_not_found", status_code=303
                    )
                affected_appointments = _future_appointments_for_removed_service_doctors(
                    cur, parsed_service_id, parsed_doctor_ids
                )
                if affected_appointments:
                    count = sum(row[1] for row in affected_appointments)
                    return RedirectResponse(
                        f"/admin/services?error=future_appointments&count={count}",
                        status_code=303,
                    )
                cur.execute(
                    """
                    UPDATE services
                    SET name = %s, duration_minutes = %s, buffer_minutes = %s
                    WHERE id = %s
                    """,
                    (*service, parsed_service_id),
                )
                if cur.rowcount == 0:
                    return RedirectResponse(
                        "/admin/services?error=service_not_found", status_code=303
                    )
                _replace_service_doctors(cur, parsed_service_id, parsed_doctor_ids)
                record_audit_event(
                    cur, "service.update", "service", parsed_service_id
                )
    except psycopg2.errors.UniqueViolation:
        return RedirectResponse("/admin/services?error=name_exists", status_code=303)
    except psycopg2.errors.CheckViolation:
        return RedirectResponse("/admin/services?error=invalid_service", status_code=303)
    finally:
        conn.close()
    return RedirectResponse("/admin/services?updated=1", status_code=303)


def _set_service_active(request: Request, service_id: str, active: bool):
    admin_user, denied = require_user(request, "admin")
    if denied:
        return denied
    parsed_service_id = parse_strict_int(service_id, min_value=1)
    if parsed_service_id is None:
        return RedirectResponse("/admin/services?error=service_not_found", status_code=303)
    conn = db_as(admin_user)
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE services SET active = %s WHERE id = %s",
                    (active, parsed_service_id),
                )
                if cur.rowcount == 0:
                    return RedirectResponse(
                        "/admin/services?error=service_not_found", status_code=303
                    )
                record_audit_event(
                    cur,
                    "service.activate" if active else "service.deactivate",
                    "service",
                    parsed_service_id,
                )
    finally:
        conn.close()
    return RedirectResponse(
        f"/admin/services?activation={'activated' if active else 'deactivated'}",
        status_code=303,
    )


@router.post("/admin/services/{service_id}/deactivate")
def deactivate_service(request: Request, service_id: str):
    return _set_service_active(request, service_id, False)


@router.post("/admin/services/{service_id}/activate")
def activate_service(request: Request, service_id: str):
    return _set_service_active(request, service_id, True)


@router.post("/admin/services/{service_id}/delete")
def delete_service(request: Request, service_id: str):
    admin_user, denied = require_user(request, "admin")
    if denied:
        return denied
    parsed_service_id = parse_strict_int(service_id, min_value=1)
    if parsed_service_id is None:
        return RedirectResponse("/admin/services?error=service_not_found", status_code=303)
    conn = db_as(admin_user)
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    DELETE FROM services svc
                    WHERE svc.id = %s
                      AND NOT EXISTS (
                          SELECT 1 FROM slots s WHERE s.service_id = svc.id
                      )
                    """,
                    (parsed_service_id,),
                )
                if cur.rowcount == 0:
                    return RedirectResponse(
                        "/admin/services?error=service_in_use", status_code=303
                    )
                record_audit_event(
                    cur, "service.delete", "service", parsed_service_id
                )
    finally:
        conn.close()
    return RedirectResponse("/admin/services?deleted=1", status_code=303)


@router.get("/admin/doctors")
def admin_doctors(request: Request):
    admin_user, denied = require_user(request, "admin")
    if denied:
        return denied
    conn = db_as(admin_user)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT d.id, d.user_id, u.email, u.blocked, d.full_name,
               d.specialty, d.experience_years,
               count(a.id) FILTER (
                 WHERE a.status = 'scheduled'
                   AND a.starts_at > CURRENT_TIMESTAMP
               ) AS future_appointments
        FROM doctors d
        JOIN users u ON u.id = d.user_id
        LEFT JOIN appointments a ON a.doctor_id = d.id
        GROUP BY d.id, d.user_id, u.email, u.blocked, d.full_name,
                 d.specialty, d.experience_years
        ORDER BY d.full_name, d.id
        """
    )
    doctors = [
        {
            "id": row[0],
            "user_id": row[1],
            "email": row[2],
            "blocked": row[3],
            "full_name": row[4],
            "specialty": row[5],
            "experience_years": row[6],
            "future_appointments": row[7],
        }
        for row in cur.fetchall()
    ]
    cur.close()
    conn.close()
    return templates.TemplateResponse(
        "admin_doctors.html",
        {
            "request": request,
            "role": "admin",
            "doctors": doctors,
            "created": request.query_params.get("created"),
            "updated": request.query_params.get("updated"),
            "activation": request.query_params.get("activation"),
            "future_appointments": parse_strict_int(
                request.query_params.get("future_appointments"), min_value=0
            ),
            "error": request.query_params.get("error"),
            "password_link": request.query_params.get("password_link"),
        },
    )


@router.get("/admin/doctors/new")
def admin_new_doctor_form(request: Request):
    admin_user, denied = require_user(request, "admin")
    if denied:
        return denied
    return templates.TemplateResponse(
        "admin_doctor_form.html",
        {
            "request": request,
            "role": admin_user["role"],
            "error": request.query_params.get("error"),
        },
    )


@router.post("/admin/doctors")
def create_doctor(
    request: Request,
    email: str = Form(...),
    full_name: str = Form(...),
    specialty: str = Form(...),
    experience_years: str = Form(...),
):
    admin_user, denied = require_user(request, "admin")
    if denied:
        return denied
    normalized_email = _normalize_registration_email(email)
    full_name = clean_label(full_name)
    specialty = clean_label(specialty)
    parsed_experience = parse_strict_int(
        experience_years, min_value=0, max_value=EXPERIENCE_MAX_YEARS
    )
    if normalized_email is None:
        return RedirectResponse(
            "/admin/doctors/new?error=invalid_email", status_code=303
        )
    if full_name is None or specialty is None or parsed_experience is None:
        return RedirectResponse(
            "/admin/doctors/new?error=invalid_details", status_code=303
        )
    if not smtp_ready():
        return RedirectResponse("/admin/doctors/new?error=password_link_failed", status_code=303)

    conn = db_as(admin_user)
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT status, invited_user_id, invited_doctor_id, recipient, reset_token
                    FROM public.admin_invite_doctor(%s, %s, %s, %s)
                    """,
                    (normalized_email, full_name, specialty, parsed_experience),
                )
                row = cur.fetchone()
    except psycopg2.errors.UniqueViolation:
        return RedirectResponse(
            "/admin/doctors/new?error=email_exists", status_code=303
        )
    finally:
        conn.close()
    status, _user_id, _doctor_id, recipient, token = row if row else (
        "invalid", None, None, None, None
    )
    if status != "issued" or not recipient or not token:
        error = "password_link_failed" if status == "rate_limited" else "invalid_details"
        return RedirectResponse(f"/admin/doctors/new?error={error}", status_code=303)
    if not deliver_password_reset(recipient, token):
        _discard_invite(token)
        return RedirectResponse("/admin/doctors/new?error=password_link_failed", status_code=303)
    return RedirectResponse("/admin/doctors?created=1", status_code=303)


@router.post("/admin/doctors/{doctor_id}")
def update_doctor(
    request: Request,
    doctor_id: str,
    full_name: str = Form(...),
    specialty: str = Form(...),
    experience_years: str = Form(...),
):
    admin_user, denied = require_user(request, "admin")
    if denied:
        return denied
    parsed_doctor_id = parse_strict_int(doctor_id, min_value=1)
    full_name = clean_label(full_name)
    specialty = clean_label(specialty)
    parsed_experience = parse_strict_int(
        experience_years, min_value=0, max_value=EXPERIENCE_MAX_YEARS
    )
    if parsed_doctor_id is None:
        return RedirectResponse("/admin/doctors?error=doctor_not_found", status_code=303)
    if full_name is None or specialty is None or parsed_experience is None:
        return RedirectResponse("/admin/doctors?error=invalid_details", status_code=303)

    conn = db_as(admin_user)
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE doctors
                    SET full_name = %s, specialty = %s, experience_years = %s
                    WHERE id = %s
                    """,
                    (full_name, specialty, parsed_experience, parsed_doctor_id),
                )
                if cur.rowcount == 0:
                    return RedirectResponse(
                        "/admin/doctors?error=doctor_not_found", status_code=303
                    )
                record_audit_event(
                    cur, "doctor.update", "doctor", parsed_doctor_id
                )
    finally:
        conn.close()
    return RedirectResponse("/admin/doctors?updated=1", status_code=303)


def _set_doctor_blocked(request: Request, doctor_id: str, blocked: bool):
    admin_user, denied = require_user(request, "admin")
    if denied:
        return denied
    parsed_doctor_id = parse_strict_int(doctor_id, min_value=1)
    if parsed_doctor_id is None:
        return RedirectResponse("/admin/doctors?error=doctor_not_found", status_code=303)
    conn = db_as(admin_user)
    try:
        with conn:
            with conn.cursor() as cur:
                future_appointments = 0
                if blocked:
                    cur.execute(
                        """
                        SELECT count(*)
                        FROM appointments
                        WHERE doctor_id = %s
                          AND status = 'scheduled'
                          AND starts_at > CURRENT_TIMESTAMP
                        """,
                        (parsed_doctor_id,),
                    )
                    future_appointments = cur.fetchone()[0]
                cur.execute(
                    """
                    UPDATE users u
                    SET blocked = %s
                    FROM doctors d
                    WHERE d.id = %s AND u.id = d.user_id AND u.role = 'doctor'
                    """,
                    (blocked, parsed_doctor_id),
                )
                if cur.rowcount == 0:
                    return RedirectResponse(
                        "/admin/doctors?error=doctor_not_found", status_code=303
                    )
                record_audit_event(
                    cur,
                    "doctor.deactivate" if blocked else "doctor.activate",
                    "doctor",
                    parsed_doctor_id,
                )
    finally:
        conn.close()
    return RedirectResponse(
        f"/admin/doctors?activation={'deactivated' if blocked else 'activated'}"
        f"&future_appointments={future_appointments}",
        status_code=303,
    )


@router.post("/admin/doctors/{doctor_id}/deactivate")
def deactivate_doctor(request: Request, doctor_id: str):
    return _set_doctor_blocked(request, doctor_id, True)


@router.post("/admin/doctors/{doctor_id}/activate")
def activate_doctor(request: Request, doctor_id: str):
    return _set_doctor_blocked(request, doctor_id, False)


@router.get("/admin/settings")
def admin_settings(request: Request):
    admin_user, denied = require_user(request, "admin")
    if denied:
        return denied
    conn = db_as(admin_user)
    cur = conn.cursor()
    cur.execute("SELECT address, phone FROM clinic_settings WHERE id = 1")
    row = cur.fetchone()
    cur.close()
    conn.close()
    if row is None:
        raise RuntimeError("Clinic settings row is missing")
    return templates.TemplateResponse(
        "admin_settings.html",
        {
            "request": request,
            "role": admin_user["role"],
            "address": row[0],
            "phone": row[1],
            "saved": request.query_params.get("saved"),
            "error": request.query_params.get("error"),
        },
    )


@router.post("/admin/settings")
def update_admin_settings(
    request: Request,
    address: str = Form(...),
    phone: str = Form(...),
):
    admin_user, denied = require_user(request, "admin")
    if denied:
        return denied
    if contains_nul(address, phone):
        return RedirectResponse("/admin/settings?error=invalid_text", status_code=303)
    address = clean_optional_text(address, ADDRESS_MAX_LENGTH)
    phone = clean_phone(phone)
    if address is None:
        return RedirectResponse("/admin/settings?error=invalid_address", status_code=303)
    if phone is None:
        return RedirectResponse("/admin/settings?error=invalid_phone", status_code=303)

    conn = db_as(admin_user)
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE clinic_settings
                    SET address = %s, phone = %s
                    WHERE id = 1
                    """,
                    (address, phone),
                )
                if cur.rowcount != 1:
                    raise RuntimeError("Clinic settings row is missing")
                record_audit_event(cur, "clinic.settings.update", "clinic", 1)
    except psycopg2.errors.CheckViolation:
        return RedirectResponse("/admin/settings?error=invalid_address", status_code=303)
    finally:
        conn.close()
    return RedirectResponse("/admin/settings?saved=1", status_code=303)


def _purge_slots_without_scheduled(cur, where_sql, params):
   #cancelled 
    cur.execute(
        f"""
        DELETE FROM appointments a
        WHERE a.status = 'cancelled'
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
              WHERE a.slot_id = s.id
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
        SELECT a.id, u.email, d.full_name, svc.name, a.starts_at, a.ends_at
        FROM appointments a
        JOIN users u ON u.id = a.patient_user_id
        JOIN slots s ON s.id = a.slot_id
        JOIN doctors d ON d.id = s.doctor_id
        JOIN services svc ON svc.id = s.service_id
        WHERE a.status = 'scheduled'
          AND {where_sql}
        ORDER BY a.starts_at
        """,
        params,
    )
    return [
        {
            "appointment_id": row[0],
            "patient_email": row[1],
            "doctor_name": row[2],
            "service_name": row[3],
            "starts_at": row[4],
            "ends_at": row[5],
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
    cur.execute(
        """
        SELECT d.id, d.full_name
        FROM doctors d
        JOIN users u ON u.id = d.user_id
        WHERE u.role = 'doctor' AND NOT u.blocked
        ORDER BY d.full_name
        """
    )
    doctors = [{"id": row[0], "full_name": row[1]} for row in cur.fetchall()]
    cur.execute(
        """
        SELECT id, name, duration_minutes, buffer_minutes
        FROM services
        WHERE active
        ORDER BY name, id
        """
    )
    active_services = [
        {
            "id": row[0],
            "name": row[1],
            "duration_minutes": row[2],
            "buffer_minutes": row[3],
        }
        for row in cur.fetchall()
    ]
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
        SELECT d.full_name, w.weekday, w.start_time, w.end_time,
               svc.name, svc.duration_minutes + svc.buffer_minutes
        FROM work_hours w
        JOIN doctors d ON d.id = w.doctor_id
        JOIN doctor_services ds ON ds.doctor_id = d.id
        JOIN services svc ON svc.id = ds.service_id AND svc.active
        ORDER BY d.full_name, w.weekday, svc.name
        """
    )
    generation_warnings = []
    for doctor_name, weekday, start_time, end_time, service_name, total_minutes in cur.fetchall():
        work_window_minutes = int(
            (
                datetime.combine(date.min, end_time)
                - datetime.combine(date.min, start_time)
            ).total_seconds()
            // 60
        )
        if total_minutes > work_window_minutes:
            generation_warnings.append(
                {
                    "doctor_name": doctor_name,
                    "weekday": weekday,
                    "service_name": service_name,
                    "total_minutes": total_minutes,
                    "work_window_minutes": work_window_minutes,
                }
            )
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
    cur.execute(
        """
        SELECT r.id, d.full_name, u.email, r.starts_on, r.ends_on,
               r.comment, r.status, r.created_at
        FROM time_off_requests r
        JOIN doctors d ON d.id = r.doctor_id
        JOIN users u ON u.id = d.user_id
        ORDER BY (r.status = 'pending') DESC, r.created_at DESC, r.id DESC
        LIMIT 100
        """
    )
    time_off_requests = [
        {
            "id": row[0],
            "doctor_name": row[1],
            "doctor_email": row[2],
            "starts_on": row[3],
            "ends_on": row[4],
            "comment": row[5],
            "status": row[6],
            "created_at": row[7],
        }
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
    upcoming_visits = _scheduled_visit_rows(
        cur,
        "s.starts_at > CURRENT_TIMESTAMP",
        (),
    )
    cur.close()
    conn.close()
    return templates.TemplateResponse(
        "admin_schedule.html",
        {
            "request": request,
            "role": admin_user["role"],
            "doctors": doctors,
            "active_services": active_services,
            "work_hours": work_hours,
            "generation_warnings": generation_warnings,
            "default_from_date": date.today().isoformat(),
            "default_to_date": (date.today() + timedelta(days=14)).isoformat(),
            "time_off": time_off,
            "time_off_requests": time_off_requests,
            "holidays": holidays,
            "closure_report": closure_report,
            "hours_report": hours_report,
            "manual_cancel_visits": manual_cancel_visits,
            "outside_hours_visits": outside_hours_visits,
            "upcoming_visits": upcoming_visits,
            "visit_cancelled": request.query_params.get("visit_cancelled"),
            "time_off_request_decision": request.query_params.get(
                "time_off_request_decision"
            ),
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
    parsed_slot_minutes = parse_strict_int(
        slot_minutes, min_value=SLOT_MINUTES_MIN, max_value=SLOT_MINUTES_MAX
    )
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
    cur.execute(
        """
        SELECT 1
        FROM doctors d
        JOIN users u ON u.id = d.user_id
        WHERE d.id = %s AND u.role = 'doctor' AND NOT u.blocked
        """,
        (doctor_id,),
    )
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
    record_audit_event(cur, "schedule.work_hours.save", "doctor", doctor_id)
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
    cur.execute(
        """
        SELECT 1
        FROM doctors d
        JOIN users u ON u.id = d.user_id
        WHERE d.id = %s AND u.role = 'doctor' AND NOT u.blocked
        """,
        (doctor_id,),
    )
    if cur.fetchone() is None:
        cur.close()
        conn.close()
        return RedirectResponse("/admin/schedule?error=doctor_not_found", status_code=303)
    where_sql = f"s.doctor_id=%s AND {_outside_hours_sql('s')}"
    removed = _purge_slots_without_scheduled(cur, where_sql, (doctor_id,))
    record_audit_event(cur, "schedule.work_hours.apply", "doctor", doctor_id)
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
    if starts_on < date.today():
        return RedirectResponse("/admin/schedule?error=time_off_past", status_code=303)
    if (
        (ends_on - starts_on).days > MAX_CLOSURE_DAYS
        or ends_on > date.today() + timedelta(days=MAX_FUTURE_DAYS)
    ):
        return RedirectResponse("/admin/schedule?error=time_off_too_long", status_code=303)
    conn = db_as(admin_user)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT 1
        FROM doctors d
        JOIN users u ON u.id = d.user_id
        WHERE d.id = %s AND u.role = 'doctor' AND NOT u.blocked
        """,
        (doctor_id,),
    )
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
    record_audit_event(cur, "schedule.time_off.add", "doctor", doctor_id)
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


@router.post("/admin/time-off-requests/{request_id}/decision")
def admin_decide_time_off_request(
    request: Request,
    request_id: str,
    decision: str = Form(...),
):
    admin_user, denied = require_user(request, "admin")
    if denied:
        return denied
    request_id = parse_strict_int(request_id, min_value=1)
    decision = decision.strip().lower()
    if request_id is None or decision not in ("approve", "reject"):
        return RedirectResponse(
            "/admin/schedule?error=invalid_time_off_request",
            status_code=303,
        )

    conn = db_as(admin_user)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT doctor_id, starts_on, ends_on
        FROM time_off_requests
        WHERE id = %s AND status = 'pending'
        FOR UPDATE
        """,
        (request_id,),
    )
    time_off_request = cur.fetchone()
    if time_off_request is None:
        conn.rollback()
        cur.close()
        conn.close()
        return RedirectResponse(
            "/admin/schedule?error=time_off_request_not_pending",
            status_code=303,
        )

    if decision == "approve" and (
        time_off_request[1] < date.today()
        or (time_off_request[2] - time_off_request[1]).days > MAX_CLOSURE_DAYS
        or time_off_request[2] > date.today() + timedelta(days=MAX_FUTURE_DAYS)
    ):
        conn.rollback()
        cur.close()
        conn.close()
        error = (
            "time_off_past"
            if time_off_request[1] < date.today()
            else "time_off_too_long"
        )
        return RedirectResponse(
            f"/admin/schedule?error={error}",
            status_code=303,
        )

    new_status = "approved" if decision == "approve" else "rejected"
    cur.execute(
        """
        UPDATE time_off_requests
        SET status = %s, decided_by = %s, decided_at = CURRENT_TIMESTAMP
        WHERE id = %s AND status = 'pending'
        """,
        (new_status, admin_user["id"], request_id),
    )
    if cur.rowcount != 1:
        conn.rollback()
        cur.close()
        conn.close()
        return RedirectResponse(
            "/admin/schedule?error=time_off_request_not_pending",
            status_code=303,
        )

    removed_slots = 0
    if decision == "approve":
        doctor_id, starts_on, ends_on = time_off_request
        cur.execute(
            """
            INSERT INTO time_off (doctor_id, starts_on, ends_on)
            VALUES (%s, %s, %s)
            ON CONFLICT (doctor_id, starts_on, ends_on) DO NOTHING
            """,
            (doctor_id, starts_on, ends_on),
        )
        removed_slots, _ = _close_slots_for_period(
            cur, starts_on, ends_on, doctor_id
        )
    record_audit_event(
        cur,
        f"schedule.time_off_request.{new_status}",
        "time_off_request",
        request_id,
    )
    conn.commit()
    cur.close()
    conn.close()
    if decision == "approve":
        request.session["closure_report"] = {
            "kind": "time-off-request",
            "starts_on": starts_on.isoformat(),
            "ends_on": ends_on.isoformat(),
            "doctor_id": doctor_id,
            "removed_slots": removed_slots,
        }
    return RedirectResponse(
        f"/admin/schedule?time_off_request_decision={new_status}",
        status_code=303,
    )


@router.post("/admin/holidays")
def admin_save_holiday(
    request: Request,
    holiday_day: date = Form(...),
    name: str = Form(...),
):
    admin_user, denied = require_user(request, "admin")
    if denied:
        return denied
    if contains_nul(name) or has_control_char(name):
        return RedirectResponse(
            "/admin/schedule?error=holiday_name_invalid", status_code=303
        )
    if not isinstance(name, str) or not name.strip():
        return RedirectResponse(
            "/admin/schedule?error=holiday_name_required", status_code=303
        )
    holiday_name = clean_label(name)
    if holiday_name is None:
        return RedirectResponse(
            "/admin/schedule?error=holiday_name_invalid", status_code=303
        )
    if holiday_day > date.today() + timedelta(days=MAX_FUTURE_DAYS):
        return RedirectResponse("/admin/schedule?error=holiday_too_far", status_code=303)
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
    record_audit_event(cur, "schedule.holiday.save", "holiday")
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
    return _generate_slots_for_doctors(
        admin_user, [doctor_id], from_date, to_date
    )


@router.post("/admin/schedule/generate")
def generate_selected_doctor_slots(
    request: Request,
    doctor_ids: List[str] = Form(default=[]),
    from_date: date = Form(...),
    to_date: date = Form(...),
):
    admin_user, denied = require_user(request, "admin")
    if denied:
        return denied
    parsed_doctor_ids = [
        parse_strict_int(raw, min_value=1) for raw in doctor_ids
    ]
    if not parsed_doctor_ids or any(doctor_id is None for doctor_id in parsed_doctor_ids):
        return RedirectResponse("/admin/schedule?error=no_doctors_selected", status_code=303)
    return _generate_slots_for_doctors(
        admin_user, sorted(set(parsed_doctor_ids)), from_date, to_date
    )


def _generate_slots_for_doctors(
    admin_user: dict, doctor_ids: List[int], from_date: date, to_date: date
):
    if from_date > to_date:
        return RedirectResponse("/admin/schedule?error=range_order", status_code=303)
    if from_date < date.today():
        return RedirectResponse("/admin/schedule?error=range_in_past", status_code=303)
    if (to_date - from_date).days + 1 > 90:
        return RedirectResponse("/admin/schedule?error=range_too_long", status_code=303)

    conn = db_as(admin_user)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT 1
        FROM doctors d
        JOIN users u ON u.id = d.user_id
        WHERE d.id = ANY(%s::int[]) AND u.role = 'doctor' AND NOT u.blocked
        """,
        (doctor_ids,),
    )
    if cur.rowcount != len(doctor_ids):
        cur.close()
        conn.close()
        return RedirectResponse("/admin/schedule?error=doctor_not_found", status_code=303)
    cur.execute(
        """
        SELECT d.id
        FROM doctors d
        WHERE d.id = ANY(%s::int[])
          AND NOT EXISTS (
              SELECT 1
              FROM doctor_services ds
              JOIN services svc ON svc.id = ds.service_id AND svc.active
              WHERE ds.doctor_id = d.id
          )
        """,
        (doctor_ids,),
    )
    if cur.fetchone() is not None:
        cur.close()
        conn.close()
        return RedirectResponse(
            "/admin/schedule?error=no_assigned_services", status_code=303
        )
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
    for doctor_id in doctor_ids:
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
            SELECT svc.id, svc.duration_minutes, svc.buffer_minutes
            FROM services svc
            JOIN doctor_services ds ON ds.service_id = svc.id
            WHERE svc.active AND ds.doctor_id = %s
            ORDER BY svc.id
            """,
            (doctor_id,),
        )
        services = cur.fetchall()
        cur.execute(
            """
            SELECT starts_on, ends_on
            FROM time_off
            WHERE doctor_id=%s AND starts_on <= %s AND ends_on >= %s
            """,
            (doctor_id, to_date, from_date),
        )
        time_off = cur.fetchall()

        current_date = from_date
        while current_date <= to_date:
            day_hours = [
                row for row in work_hours if row[0] == current_date.weekday()
            ]
            is_day_off = (
                current_date in holidays
                or any(start <= current_date <= end for start, end in time_off)
            )
            for _, start_time, end_time, work_step_minutes in day_hours:
                day_end = datetime.combine(current_date, end_time)
                for service_id, duration_minutes, buffer_minutes in services:
                    occupied_minutes = duration_minutes + buffer_minutes
                    step_minutes = max(work_step_minutes, occupied_minutes)
                    slot_duration = timedelta(minutes=occupied_minutes)
                    step_duration = timedelta(minutes=step_minutes)
                    start_at = datetime.combine(current_date, start_time)
                    if is_day_off:
                        while start_at + slot_duration <= day_end:
                            skipped += 1
                            start_at += step_duration
                        continue
                    while start_at + slot_duration <= day_end:
                        if current_date < today or start_at <= now:
                            skipped += 1
                            start_at += step_duration
                            continue
                        cur.execute("SAVEPOINT generate_slot")
                        try:
                            cur.execute(
                                """
                                INSERT INTO slots (
                                    doctor_id, service_id, starts_at, ends_at,
                                    duration_minutes, buffer_minutes
                                )
                                VALUES (%s, %s, %s, %s, %s, %s)
                                ON CONFLICT (doctor_id, service_id, starts_at)
                                DO NOTHING
                                """,
                                (
                                    doctor_id,
                                    service_id,
                                    start_at,
                                    start_at + slot_duration,
                                    duration_minutes,
                                    buffer_minutes,
                                ),
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
                        start_at += step_duration

            current_date += timedelta(days=1)
        record_audit_event(cur, "schedule.slots.generate", "doctor", doctor_id)

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
    if user_id == admin_user["id"]:
        return RedirectResponse("/admin/users?error=self_block", status_code=303)
    conn = db_as(admin_user)
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE users
        SET blocked = TRUE
        WHERE id = %s
          AND (role = 'patient' OR (role = 'admin' AND id <> %s))
        RETURNING role
        """,
        (user_id, admin_user["id"]),
    )
    row = cur.fetchone()
    if row:
        record_audit_event(cur, "user.block", row[0], user_id)
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
    if user_id == admin_user["id"]:
        return RedirectResponse("/admin/users?error=self_block", status_code=303)
    conn = db_as(admin_user)
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE users
        SET blocked = FALSE
        WHERE id = %s
          AND (role = 'patient' OR (role = 'admin' AND id <> %s))
        RETURNING role
        """,
        (user_id, admin_user["id"]),
    )
    row = cur.fetchone()
    if row:
        record_audit_event(cur, "user.unblock", row[0], user_id)
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
        RETURNING a.id
        """,
        (user_id,),
    )
    cancelled_ids = [row[0] for row in cur.fetchall()]
    cancelled_count = len(cancelled_ids)
    notices = []
    if cancelled_count:
        record_audit_event(cur, "appointment.cancel_future", "patient", user_id)
        for appointment_id in cancelled_ids:
            try:
                notices.append(load_appointment_notice(cur, appointment_id))
            except Exception:
                log.exception("could not prepare appointment email")
    conn.commit()
    cur.close()
    conn.close()
    for notice in notices:
        deliver_appointment_emails(notice, "cancelled")
    return RedirectResponse(
        f"/admin/users?future_cancelled={cancelled_count}", status_code=303
    )
