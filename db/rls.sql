BEGIN;

CREATE OR REPLACE FUNCTION public.is_own_patient(doc_id int, pat_id int)
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = pg_catalog, public
AS $function$
  SELECT EXISTS (
    SELECT 1
    FROM public.appointments AS a
    WHERE a.doctor_id = doc_id
      AND a.patient_user_id = pat_id
      AND a.status = 'scheduled'
      AND a.starts_at > CURRENT_TIMESTAMP - INTERVAL '12 months'
  );
$function$;

REVOKE ALL ON FUNCTION public.is_own_patient(integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.is_own_patient(integer, integer) TO app_doctor;

CREATE OR REPLACE FUNCTION public.doctor_can_view_medical_record(
  target_appointment_id int,
  target_doctor_id int,
  target_patient_user_id int
)
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = pg_catalog, public
AS $function$
  SELECT EXISTS (
    SELECT 1
    FROM public.appointments AS a
    WHERE a.id = target_appointment_id
      AND a.doctor_id = target_doctor_id
      AND a.patient_user_id = target_patient_user_id
      AND a.status IN ('scheduled', 'cancelled')
      AND a.starts_at > CURRENT_TIMESTAMP - INTERVAL '12 months'
  );
$function$;

REVOKE ALL ON FUNCTION public.doctor_can_view_medical_record(integer, integer, integer)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.doctor_can_view_medical_record(integer, integer, integer)
  TO app_doctor;

CREATE OR REPLACE FUNCTION public.doctor_patients(doc_user_id int)
RETURNS TABLE (id int, email text, blocked boolean)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
  SELECT u.id, u.email, u.blocked
  FROM public.users AS u 
  JOIN public.doctors AS d ON d.user_id = doc_user_id
  WHERE doc_user_id = NULLIF(current_setting('app.user_id', true), '')::int
    AND EXISTS (
      SELECT 1
      FROM public.appointments AS a
      WHERE a.doctor_id = d.id
        AND a.patient_user_id = u.id
        AND a.status IN ('scheduled', 'cancelled')
        AND a.starts_at > CURRENT_TIMESTAMP - INTERVAL '12 months'
    );
$function$;

REVOKE ALL ON FUNCTION public.doctor_patients(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.doctor_patients(integer) TO app_doctor;

CREATE OR REPLACE FUNCTION public.current_patient_is_active()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
  SELECT EXISTS (
    SELECT 1
    FROM public.users AS u
    WHERE u.id = NULLIF(current_setting('app.user_id', true), '')::int
      AND u.role = 'patient'
      AND NOT u.blocked
  );
$function$;

CREATE OR REPLACE FUNCTION public.scheduled_slot_is_taken(target_slot_id int)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
  SELECT EXISTS (
    SELECT 1
    FROM public.appointments AS a
    WHERE a.slot_id = target_slot_id
      AND a.status = 'scheduled'
  );
$function$;

CREATE OR REPLACE FUNCTION public.doctor_is_active(target_doctor_id int)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
  SELECT EXISTS (
    SELECT 1
    FROM public.doctors AS d
    JOIN public.users AS u ON u.id = d.user_id
    WHERE d.id = target_doctor_id
      AND u.role = 'doctor'
      AND NOT u.blocked
  );
$function$;

CREATE OR REPLACE FUNCTION public.is_valid_free_slot(
  target_slot_id int,
  target_doctor_id int,
  target_starts_at timestamp,
  target_ends_at timestamp
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
  SELECT EXISTS (
    SELECT 1
    FROM public.slots AS s
    WHERE s.id = target_slot_id
      AND s.doctor_id = target_doctor_id
      AND s.starts_at = target_starts_at
      AND s.ends_at = target_ends_at
      AND s.starts_at > CURRENT_TIMESTAMP
      AND public.doctor_is_active(target_doctor_id)
      AND NOT EXISTS (
        SELECT 1
        FROM public.appointments AS a
        WHERE a.slot_id = s.id
          AND a.status = 'scheduled'
      )
      AND NOT EXISTS (
        SELECT 1
        FROM public.time_off AS t
        WHERE t.doctor_id = s.doctor_id
          AND s.starts_at::date BETWEEN t.starts_on AND t.ends_on
      )
      AND NOT EXISTS (
        SELECT 1
        FROM public.holidays AS h
        WHERE h.day = s.starts_at::date
      )
  );
$function$;

CREATE OR REPLACE FUNCTION public.record_audit_event(
  event_action text,
  target_type text,
  target_id integer
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
DECLARE
  actor_id integer := NULLIF(current_setting('app.user_id', true), '')::integer;
  app_role text := current_setting('role', true);
  actor_role text;
BEGIN
  SELECT u.role INTO actor_role
  FROM public.users AS u
  WHERE u.id = actor_id;

  IF actor_role IS NULL
     OR app_role IS DISTINCT FROM ('app_' || actor_role)
     OR event_action IS NULL
     OR length(event_action) NOT BETWEEN 1 AND 80
     OR target_type IS NULL
     OR length(target_type) NOT BETWEEN 1 AND 80 THEN
    RAISE EXCEPTION 'invalid audit context or event'
      USING ERRCODE = '42501';
  END IF;

  INSERT INTO public.audit_events (
    actor_user_id, actor_role, action, target_type, target_id
  )
  VALUES (actor_id, actor_role, event_action, target_type, target_id);
END;
$function$;

CREATE OR REPLACE FUNCTION public.admin_reset_user_password(
  target_user_id integer,
  replacement_hash text
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
DECLARE
  actor_id integer := NULLIF(current_setting('app.user_id', true), '')::integer;
  target_role text;
BEGIN
  IF current_setting('role', true) IS DISTINCT FROM 'app_admin'
     OR replacement_hash IS NULL
     OR length(replacement_hash) = 0
     OR NOT EXISTS (
       SELECT 1
       FROM public.users
       WHERE id = actor_id AND role = 'admin' AND NOT blocked
     ) THEN
    RAISE EXCEPTION 'invalid admin password-reset context'
      USING ERRCODE = '42501';
  END IF;

  UPDATE public.users
  SET password_hash = replacement_hash
  WHERE id = target_user_id
  RETURNING role INTO target_role;

  RETURN target_role;
END;
$function$;

REVOKE ALL ON FUNCTION public.current_patient_is_active() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.scheduled_slot_is_taken(integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.doctor_is_active(integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.is_valid_free_slot(integer, integer, timestamp, timestamp) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.record_audit_event(text, text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.admin_reset_user_password(integer, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.current_patient_is_active() TO app_patient;
GRANT EXECUTE ON FUNCTION public.scheduled_slot_is_taken(integer)
  TO app_patient, app_registrar, app_admin;
GRANT EXECUTE ON FUNCTION public.doctor_is_active(integer)
  TO app_patient, app_registrar, app_admin;
GRANT EXECUTE ON FUNCTION public.is_valid_free_slot(integer, integer, timestamp, timestamp)
  TO app_patient;
GRANT EXECUTE ON FUNCTION public.record_audit_event(text, text, integer)
  TO app_patient, app_doctor, app_registrar, app_admin;
GRANT EXECUTE ON FUNCTION public.admin_reset_user_password(integer, text)
  TO app_admin;

GRANT USAGE ON SCHEMA public
  TO app_guest, app_patient, app_doctor, app_registrar, app_admin;

GRANT SELECT ON public.doctors TO app_guest, app_patient, app_doctor, app_registrar, app_admin;
GRANT INSERT (user_id, full_name, specialty, experience_years),
  UPDATE (full_name, specialty, experience_years)
  ON public.doctors TO app_admin;
GRANT USAGE, SELECT ON SEQUENCE public.doctors_id_seq TO app_admin;
GRANT SELECT ON public.clinic_settings
  TO app_guest, app_patient, app_doctor, app_registrar, app_admin;
GRANT UPDATE (address, phone) ON public.clinic_settings TO app_admin;
GRANT INSERT (email, password_hash, role, blocked) ON public.users TO app_guest;
GRANT USAGE, SELECT ON SEQUENCE public.users_id_seq TO app_guest;
GRANT SELECT ON public.slots, public.work_hours, public.time_off, public.holidays
  TO app_patient, app_registrar;
GRANT SELECT ON public.slots TO app_doctor, app_admin;
GRANT SELECT ON public.work_hours, public.time_off, public.holidays TO app_doctor;

GRANT SELECT, UPDATE (status) ON public.appointments TO app_patient, app_registrar;
GRANT INSERT (slot_id, patient_user_id, doctor_id, starts_at, ends_at)
  ON public.appointments TO app_patient, app_registrar;
GRANT SELECT ON public.appointments TO app_doctor, app_admin;
GRANT UPDATE (status), DELETE ON public.appointments TO app_admin;
GRANT USAGE, SELECT ON SEQUENCE public.appointments_id_seq TO app_patient, app_registrar;

GRANT SELECT ON public.visit_notes, public.prescriptions TO app_patient;
GRANT SELECT, INSERT, UPDATE ON public.visit_notes, public.prescriptions TO app_doctor;
GRANT USAGE, SELECT ON SEQUENCE public.visit_notes_id_seq, public.prescriptions_id_seq
  TO app_doctor;
GRANT SELECT, INSERT ON public.time_off_requests TO app_doctor;
GRANT USAGE, SELECT ON SEQUENCE public.time_off_requests_id_seq TO app_doctor;

GRANT SELECT (id, email, role, blocked) ON public.users TO app_registrar;
GRANT SELECT (id, email, role, blocked) ON public.users TO app_admin;
GRANT INSERT (email, password_hash, role, blocked) ON public.users TO app_admin;
GRANT UPDATE (blocked) ON public.users TO app_admin;
GRANT USAGE, SELECT ON SEQUENCE public.users_id_seq TO app_admin;
GRANT SELECT ON public.audit_events TO app_admin;
GRANT SELECT ON public.time_off_requests TO app_admin;
GRANT UPDATE (status, decided_by, decided_at)
  ON public.time_off_requests TO app_admin;

GRANT SELECT ON public.work_hours, public.time_off, public.holidays TO app_admin;
GRANT INSERT, UPDATE ON public.work_hours TO app_admin;
GRANT INSERT ON public.time_off TO app_admin;
GRANT INSERT, UPDATE ON public.holidays TO app_admin;
GRANT INSERT (doctor_id, starts_at, ends_at), DELETE ON public.slots TO app_admin;
GRANT USAGE, SELECT ON SEQUENCE public.slots_id_seq, public.work_hours_id_seq,
  public.time_off_id_seq TO app_admin;

DROP POLICY IF EXISTS patient_appointments ON public.appointments;
DROP POLICY IF EXISTS doctor_appointments ON public.appointments;
DROP POLICY IF EXISTS registrar_appointments ON public.appointments;
DROP POLICY IF EXISTS admin_appointments ON public.appointments;
DROP POLICY IF EXISTS admin_cancel ON public.appointments;
DROP POLICY IF EXISTS appointments_patient ON public.appointments;
DROP POLICY IF EXISTS appointments_doctor ON public.appointments;
DROP POLICY IF EXISTS appointments_registrar ON public.appointments;
DROP POLICY IF EXISTS appointments_admin_cancel ON public.appointments;
DROP POLICY IF EXISTS appointments_admin_update ON public.appointments;
DROP POLICY IF EXISTS appointments_admin_delete ON public.appointments;
DROP POLICY IF EXISTS appointments_patient_select ON public.appointments;
DROP POLICY IF EXISTS appointments_patient_insert ON public.appointments;
DROP POLICY IF EXISTS appointments_patient_update ON public.appointments;
DROP POLICY IF EXISTS appointments_registrar_select ON public.appointments;
DROP POLICY IF EXISTS appointments_registrar_insert ON public.appointments;
DROP POLICY IF EXISTS appointments_registrar_update ON public.appointments;

CREATE POLICY appointments_patient_select ON public.appointments
  FOR SELECT TO app_patient
  USING (
    patient_user_id = current_setting('app.user_id', true)::int
    AND public.current_patient_is_active()
  );

CREATE POLICY appointments_patient_insert ON public.appointments
  FOR INSERT TO app_patient
  WITH CHECK (
    patient_user_id = current_setting('app.user_id', true)::int
    AND status = 'scheduled'
    AND public.current_patient_is_active()
    AND public.is_valid_free_slot(slot_id, doctor_id, starts_at, ends_at)
  );

CREATE POLICY appointments_patient_update ON public.appointments
  FOR UPDATE TO app_patient
  USING (
    patient_user_id = current_setting('app.user_id', true)::int
    AND status = 'scheduled'
    AND public.current_patient_is_active()
  )
  WITH CHECK (
    patient_user_id = current_setting('app.user_id', true)::int
    AND status = 'cancelled'
    AND public.current_patient_is_active()
  );

CREATE POLICY appointments_doctor ON public.appointments
  FOR SELECT TO app_doctor
  USING (
    doctor_id IN (
      SELECT id
      FROM public.doctors
      WHERE user_id = current_setting('app.user_id', true)::int
    )
  );

CREATE POLICY appointments_registrar_select ON public.appointments
  FOR SELECT TO app_registrar
  USING (true);

CREATE POLICY appointments_registrar_insert ON public.appointments
  FOR INSERT TO app_registrar
  WITH CHECK (
    public.doctor_is_active(doctor_id)
    AND
    EXISTS (
      SELECT 1
      FROM public.users AS u
      WHERE u.id = patient_user_id
        AND u.role = 'patient'
        AND NOT u.blocked
    )
  );

CREATE POLICY appointments_registrar_update ON public.appointments
  FOR UPDATE TO app_registrar
  USING (true)
  WITH CHECK (true);

CREATE POLICY appointments_admin_cancel ON public.appointments
  FOR SELECT TO app_admin
  USING (true);

CREATE POLICY appointments_admin_update ON public.appointments
  FOR UPDATE TO app_admin
  USING (true)
  WITH CHECK (true);
CREATE POLICY appointments_admin_delete ON public.appointments
  FOR DELETE TO app_admin
  USING (status = 'cancelled');

DROP POLICY IF EXISTS patient_notes ON public.visit_notes;
DROP POLICY IF EXISTS doctor_notes ON public.visit_notes;
DROP POLICY IF EXISTS doctor_notes_select ON public.visit_notes;
DROP POLICY IF EXISTS doctor_notes_insert ON public.visit_notes;
DROP POLICY IF EXISTS doctor_notes_update ON public.visit_notes;
CREATE POLICY patient_notes ON public.visit_notes
  FOR SELECT TO app_patient
  USING (
    patient_user_id = current_setting('app.user_id', true)::int
    AND public.current_patient_is_active()
  );
  CREATE POLICY doctor_notes_select ON public.visit_notes
    FOR SELECT TO app_doctor
  USING (
    doctor_id = (
      SELECT id
      FROM public.doctors
      WHERE user_id = current_setting('app.user_id', true)::int
    )
      AND public.doctor_can_view_medical_record(
        appointment_id, doctor_id, patient_user_id
      )
    );
  CREATE POLICY doctor_notes_insert ON public.visit_notes
    FOR INSERT TO app_doctor
    WITH CHECK (
      doctor_id = (
        SELECT id
      FROM public.doctors
      WHERE user_id = current_setting('app.user_id', true)::int
    )
    AND public.is_own_patient(doctor_id, patient_user_id)
  );
CREATE POLICY doctor_notes_update ON public.visit_notes
  FOR UPDATE TO app_doctor
  USING (
    doctor_id = (
      SELECT id
      FROM public.doctors
      WHERE user_id = current_setting('app.user_id', true)::int
    )
    AND public.is_own_patient(doctor_id, patient_user_id)
  )
  WITH CHECK (
    doctor_id = (
      SELECT id
      FROM public.doctors
      WHERE user_id = current_setting('app.user_id', true)::int
    )
    AND public.is_own_patient(doctor_id, patient_user_id)
  );

DROP POLICY IF EXISTS patient_prescriptions ON public.prescriptions;
DROP POLICY IF EXISTS doctor_prescriptions ON public.prescriptions;
DROP POLICY IF EXISTS doctor_prescriptions_select ON public.prescriptions;
DROP POLICY IF EXISTS doctor_prescriptions_insert ON public.prescriptions;
DROP POLICY IF EXISTS doctor_prescriptions_update ON public.prescriptions;
CREATE POLICY patient_prescriptions ON public.prescriptions
  FOR SELECT TO app_patient
  USING (
    patient_user_id = current_setting('app.user_id', true)::int
    AND public.current_patient_is_active()
  );
  CREATE POLICY doctor_prescriptions_select ON public.prescriptions
    FOR SELECT TO app_doctor
  USING (
    doctor_id = (
      SELECT id
      FROM public.doctors
      WHERE user_id = current_setting('app.user_id', true)::int
    )
      AND public.doctor_can_view_medical_record(
        appointment_id, doctor_id, patient_user_id
      )
    );
  CREATE POLICY doctor_prescriptions_insert ON public.prescriptions
    FOR INSERT TO app_doctor
    WITH CHECK (
      doctor_id = (
        SELECT id
      FROM public.doctors
      WHERE user_id = current_setting('app.user_id', true)::int
    )
    AND public.is_own_patient(doctor_id, patient_user_id)
  );
CREATE POLICY doctor_prescriptions_update ON public.prescriptions
  FOR UPDATE TO app_doctor
  USING (
    doctor_id = (
      SELECT id
      FROM public.doctors
      WHERE user_id = current_setting('app.user_id', true)::int
    )
    AND public.is_own_patient(doctor_id, patient_user_id)
  )
  WITH CHECK (
    doctor_id = (
      SELECT id
      FROM public.doctors
      WHERE user_id = current_setting('app.user_id', true)::int
    )
    AND public.is_own_patient(doctor_id, patient_user_id)
  );

DROP POLICY IF EXISTS slots_patient_select ON public.slots;
DROP POLICY IF EXISTS slots_registrar_select ON public.slots;
DROP POLICY IF EXISTS slots_doctor_select ON public.slots;
DROP POLICY IF EXISTS slots_admin_select ON public.slots;
DROP POLICY IF EXISTS slots_admin_insert ON public.slots;
DROP POLICY IF EXISTS slots_admin_delete ON public.slots;
CREATE POLICY slots_patient_select ON public.slots
  FOR SELECT TO app_patient USING (true);
CREATE POLICY slots_registrar_select ON public.slots
  FOR SELECT TO app_registrar USING (true);
CREATE POLICY slots_doctor_select ON public.slots
  FOR SELECT TO app_doctor
  USING (
    doctor_id = (
      SELECT id
      FROM public.doctors
      WHERE user_id = current_setting('app.user_id', true)::int
    )
  );
CREATE POLICY slots_admin_select ON public.slots
  FOR SELECT TO app_admin USING (true);
CREATE POLICY slots_admin_insert ON public.slots
  FOR INSERT TO app_admin WITH CHECK (true);
CREATE POLICY slots_admin_delete ON public.slots
  FOR DELETE TO app_admin USING (true);

DROP POLICY IF EXISTS users_clinic_api_select ON public.users;
DROP POLICY IF EXISTS users_registrar_select ON public.users;
DROP POLICY IF EXISTS users_admin_select ON public.users;
DROP POLICY IF EXISTS users_admin_update ON public.users;
DROP POLICY IF EXISTS users_admin_insert ON public.users;
DROP POLICY IF EXISTS users_guest_insert ON public.users;
CREATE POLICY users_clinic_api_select ON public.users
  FOR SELECT TO clinic_api USING (true);
CREATE POLICY users_registrar_select ON public.users
  FOR SELECT TO app_registrar USING (role = 'patient');
CREATE POLICY users_admin_select ON public.users
  FOR SELECT TO app_admin USING (true);
CREATE POLICY users_admin_update ON public.users
  FOR UPDATE TO app_admin
  USING (role IN ('patient', 'doctor'))
  WITH CHECK (role IN ('patient', 'doctor'));
CREATE POLICY users_admin_insert ON public.users
  FOR INSERT TO app_admin
  WITH CHECK (role IN ('doctor', 'registrar', 'admin') AND NOT blocked);
CREATE POLICY users_guest_insert ON public.users
  FOR INSERT TO app_guest
  WITH CHECK (role = 'patient' AND NOT blocked);

DROP POLICY IF EXISTS clinic_settings_select ON public.clinic_settings;
DROP POLICY IF EXISTS clinic_settings_admin_update ON public.clinic_settings;
CREATE POLICY clinic_settings_select ON public.clinic_settings
  FOR SELECT TO app_guest, app_patient, app_doctor, app_registrar, app_admin
  USING (id = 1);
CREATE POLICY clinic_settings_admin_update ON public.clinic_settings
  FOR UPDATE TO app_admin
  USING (id = 1)
  WITH CHECK (id = 1);

DROP POLICY IF EXISTS work_hours_patient_select ON public.work_hours;
DROP POLICY IF EXISTS work_hours_registrar_select ON public.work_hours;
DROP POLICY IF EXISTS work_hours_doctor_select ON public.work_hours;
DROP POLICY IF EXISTS work_hours_admin_select ON public.work_hours;
DROP POLICY IF EXISTS work_hours_admin_insert ON public.work_hours;
DROP POLICY IF EXISTS work_hours_admin_update ON public.work_hours;
CREATE POLICY work_hours_patient_select ON public.work_hours
  FOR SELECT TO app_patient USING (true);
CREATE POLICY work_hours_registrar_select ON public.work_hours
  FOR SELECT TO app_registrar USING (true);
CREATE POLICY work_hours_doctor_select ON public.work_hours
  FOR SELECT TO app_doctor
  USING (
    doctor_id = (
      SELECT id
      FROM public.doctors
      WHERE user_id = current_setting('app.user_id', true)::int
    )
  );
CREATE POLICY work_hours_admin_select ON public.work_hours
  FOR SELECT TO app_admin USING (true);
CREATE POLICY work_hours_admin_insert ON public.work_hours
  FOR INSERT TO app_admin WITH CHECK (true);
CREATE POLICY work_hours_admin_update ON public.work_hours
  FOR UPDATE TO app_admin USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS time_off_patient_select ON public.time_off;
DROP POLICY IF EXISTS time_off_registrar_select ON public.time_off;
DROP POLICY IF EXISTS time_off_doctor_select ON public.time_off;
DROP POLICY IF EXISTS time_off_admin_select ON public.time_off;
DROP POLICY IF EXISTS time_off_admin_insert ON public.time_off;
CREATE POLICY time_off_patient_select ON public.time_off
  FOR SELECT TO app_patient USING (true);
CREATE POLICY time_off_registrar_select ON public.time_off
  FOR SELECT TO app_registrar USING (true);
CREATE POLICY time_off_doctor_select ON public.time_off
  FOR SELECT TO app_doctor
  USING (
    doctor_id = (
      SELECT id
      FROM public.doctors
      WHERE user_id = current_setting('app.user_id', true)::int
    )
  );
CREATE POLICY time_off_admin_select ON public.time_off
  FOR SELECT TO app_admin USING (true);
CREATE POLICY time_off_admin_insert ON public.time_off
  FOR INSERT TO app_admin WITH CHECK (true);

DROP POLICY IF EXISTS holidays_patient_select ON public.holidays;
DROP POLICY IF EXISTS holidays_registrar_select ON public.holidays;
DROP POLICY IF EXISTS holidays_doctor_select ON public.holidays;
DROP POLICY IF EXISTS holidays_admin_select ON public.holidays;
DROP POLICY IF EXISTS holidays_admin_insert ON public.holidays;
DROP POLICY IF EXISTS holidays_admin_update ON public.holidays;
CREATE POLICY holidays_patient_select ON public.holidays
  FOR SELECT TO app_patient USING (true);
CREATE POLICY holidays_registrar_select ON public.holidays
  FOR SELECT TO app_registrar USING (true);
CREATE POLICY holidays_doctor_select ON public.holidays
  FOR SELECT TO app_doctor USING (true);
CREATE POLICY holidays_admin_select ON public.holidays
  FOR SELECT TO app_admin USING (true);
CREATE POLICY holidays_admin_insert ON public.holidays
  FOR INSERT TO app_admin WITH CHECK (true);
CREATE POLICY holidays_admin_update ON public.holidays
  FOR UPDATE TO app_admin USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS time_off_requests_doctor_select ON public.time_off_requests;
DROP POLICY IF EXISTS time_off_requests_doctor_insert ON public.time_off_requests;
DROP POLICY IF EXISTS time_off_requests_admin_select ON public.time_off_requests;
DROP POLICY IF EXISTS time_off_requests_admin_update ON public.time_off_requests;
CREATE POLICY time_off_requests_doctor_select ON public.time_off_requests
  FOR SELECT TO app_doctor
  USING (
    doctor_id IN (
      SELECT id
      FROM public.doctors
      WHERE user_id = current_setting('app.user_id', true)::int
    )
  );
CREATE POLICY time_off_requests_doctor_insert ON public.time_off_requests
  FOR INSERT TO app_doctor
  WITH CHECK (
    status = 'pending'
    AND decided_by IS NULL
    AND decided_at IS NULL
    AND doctor_id IN (
      SELECT id
      FROM public.doctors
      WHERE user_id = current_setting('app.user_id', true)::int
    )
  );
CREATE POLICY time_off_requests_admin_select ON public.time_off_requests
  FOR SELECT TO app_admin USING (true);
CREATE POLICY time_off_requests_admin_update ON public.time_off_requests
  FOR UPDATE TO app_admin
  USING (status = 'pending')
  WITH CHECK (
    status IN ('approved', 'rejected')
    AND decided_by = current_setting('app.user_id', true)::int
    AND decided_at IS NOT NULL
  );

ALTER TABLE public.slots ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.clinic_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.work_hours ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.time_off ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.holidays ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.time_off_requests ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.appointments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.appointments FORCE ROW LEVEL SECURITY;
ALTER TABLE public.visit_notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.visit_notes FORCE ROW LEVEL SECURITY;
ALTER TABLE public.prescriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.prescriptions FORCE ROW LEVEL SECURITY;

COMMIT;
