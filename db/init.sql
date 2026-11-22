




CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','doctor','patient','registrar')),
  blocked BOOLEAN NOT NULL DEFAULT FALSE,
  email_notifications BOOLEAN NOT NULL DEFAULT TRUE,
  auth_version BIGINT NOT NULL DEFAULT 0 CHECK (auth_version >= 0)
);

CREATE TABLE IF NOT EXISTS login_attempts (
  email_fingerprint BYTEA NOT NULL,
  source_fingerprint BYTEA NOT NULL,
  failed_attempts INTEGER NOT NULL CHECK (failed_attempts > 0),
  window_started_at TIMESTAMPTZ NOT NULL,
  last_attempt_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (email_fingerprint, source_fingerprint)
);

CREATE INDEX IF NOT EXISTS login_attempts_source_recent_idx
  ON login_attempts (source_fingerprint, last_attempt_at);
CREATE INDEX IF NOT EXISTS login_attempts_cleanup_idx
  ON login_attempts (last_attempt_at);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id BIGSERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash BYTEA NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS password_reset_tokens_user_idx
  ON password_reset_tokens (user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS password_reset_attempts (
  email_fingerprint BYTEA NOT NULL,
  source_fingerprint BYTEA NOT NULL,
  request_count INTEGER NOT NULL CHECK (request_count > 0),
  window_started_at TIMESTAMPTZ NOT NULL,
  last_request_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (email_fingerprint, source_fingerprint)
);

CREATE INDEX IF NOT EXISTS password_reset_attempts_source_idx
  ON password_reset_attempts (source_fingerprint, window_started_at);

CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE users
ADD COLUMN IF NOT EXISTS blocked BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE users
ALTER COLUMN blocked SET DEFAULT FALSE;

ALTER TABLE users
ADD COLUMN IF NOT EXISTS auth_version BIGINT NOT NULL DEFAULT 0
CHECK (auth_version >= 0);

CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_unique
ON users (lower(email));

-- Backfill existing users once; keep future accounts unconfirmed.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'users'
      AND column_name = 'email_verified_at'
  ) THEN
    ALTER TABLE public.users ADD COLUMN email_verified_at TIMESTAMPTZ NULL;
    UPDATE public.users SET email_verified_at = now();
  END IF;
END
$$;

-- Store confirmation-token hashes only.
CREATE TABLE IF NOT EXISTS email_verification_tokens (
  id BIGSERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash BYTEA NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS email_verification_tokens_user_idx
  ON email_verification_tokens (user_id, created_at DESC);

-- Store resend-rate hashes for one day.
CREATE TABLE IF NOT EXISTS email_verification_attempts (
  id BIGSERIAL PRIMARY KEY,
  email_fingerprint BYTEA NOT NULL,
  source_fingerprint BYTEA NOT NULL,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS email_verification_attempts_email_idx
  ON email_verification_attempts (email_fingerprint, requested_at);
CREATE INDEX IF NOT EXISTS email_verification_attempts_source_idx
  ON email_verification_attempts (source_fingerprint, requested_at);

-- Rate-limit accepted registrations using hashes only.
CREATE TABLE IF NOT EXISTS registration_attempts (
  id BIGSERIAL PRIMARY KEY,
  email_fingerprint BYTEA NOT NULL,
  source_fingerprint BYTEA NOT NULL,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS registration_attempts_source_idx
  ON registration_attempts (source_fingerprint, requested_at);
CREATE INDEX IF NOT EXISTS registration_attempts_email_idx
  ON registration_attempts (email_fingerprint, requested_at);

-- Enforce checks on direct profile writes.
CREATE TABLE IF NOT EXISTS patient_profiles (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  full_name TEXT NOT NULL,
  phone TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CHECK (length(btrim(full_name)) BETWEEN 2 AND 100),
  CHECK (full_name !~ '[[:cntrl:]]'),
  CHECK (phone ~ '^[0-9+() -]{5,40}$')
);

CREATE TABLE IF NOT EXISTS email_change_requests (
  id BIGSERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  new_email TEXT NOT NULL,
  old_token_hash BYTEA NOT NULL UNIQUE,
  new_token_hash BYTEA NOT NULL UNIQUE,
  old_confirmed_at TIMESTAMPTZ,
  new_confirmed_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS clinic_settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  address TEXT NOT NULL CHECK (length(btrim(address)) BETWEEN 0 AND 300),
  phone TEXT NOT NULL CHECK (length(btrim(phone)) BETWEEN 1 AND 50)
);

INSERT INTO clinic_settings (id, address, phone)
VALUES (1, 'Educational stand', '000-00-00')
ON CONFLICT (id) DO NOTHING;

-- Admin-controlled idle timeout.
ALTER TABLE clinic_settings
  ADD COLUMN IF NOT EXISTS session_idle_minutes INTEGER NOT NULL DEFAULT 30;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'clinic_settings_session_idle_check'
      AND conrelid = 'public.clinic_settings'::regclass
  ) THEN
    ALTER TABLE public.clinic_settings
      ADD CONSTRAINT clinic_settings_session_idle_check
      CHECK (session_idle_minutes BETWEEN 5 AND 120);
  END IF;
END
$$;

-- Patient change deadline; staff are exempt.
ALTER TABLE clinic_settings
  ADD COLUMN IF NOT EXISTS patient_change_deadline_hours INTEGER NOT NULL DEFAULT 2;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'clinic_settings_change_deadline_check'
      AND conrelid = 'public.clinic_settings'::regclass
  ) THEN
    ALTER TABLE public.clinic_settings
      ADD CONSTRAINT clinic_settings_change_deadline_check
      CHECK (patient_change_deadline_hours BETWEEN 0 AND 48);
  END IF;
END
$$;


CREATE TABLE IF NOT EXISTS doctors (
  id SERIAL PRIMARY KEY,
  user_id INTEGER UNIQUE REFERENCES users(id),
  full_name TEXT NOT NULL,
  specialty TEXT NOT NULL,
  experience_years INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS services (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE CHECK (length(btrim(name)) BETWEEN 1 AND 120),
  duration_minutes INTEGER NOT NULL CHECK (duration_minutes > 0),
  buffer_minutes INTEGER NOT NULL DEFAULT 0 CHECK (buffer_minutes >= 0),
  active BOOLEAN NOT NULL DEFAULT TRUE,
  CHECK (duration_minutes + buffer_minutes <= 1440)
);

CREATE UNIQUE INDEX IF NOT EXISTS services_name_lower_unique
ON services (lower(name));

INSERT INTO services (name, duration_minutes, buffer_minutes, active)
VALUES ('General consultation', 30, 0, TRUE)
ON CONFLICT (name) DO NOTHING;

DO $$
BEGIN
  IF to_regclass('public.doctor_services') IS NULL THEN
    CREATE TABLE public.doctor_services (
      doctor_id INTEGER NOT NULL REFERENCES public.doctors(id) ON DELETE CASCADE,
      service_id INTEGER NOT NULL REFERENCES public.services(id) ON DELETE CASCADE,
      PRIMARY KEY (doctor_id, service_id)
    );

    INSERT INTO public.doctor_services (doctor_id, service_id)
    SELECT d.id, svc.id
    FROM public.doctors d
    CROSS JOIN public.services svc
    ON CONFLICT DO NOTHING;
  END IF;
END
$$;

CREATE TABLE IF NOT EXISTS slots (
  id SERIAL PRIMARY KEY,
  doctor_id INTEGER NOT NULL REFERENCES doctors(id),
  service_id INTEGER REFERENCES services(id),
  starts_at TIMESTAMP NOT NULL,
  ends_at TIMESTAMP NOT NULL,
  duration_minutes INTEGER,
  buffer_minutes INTEGER
);

ALTER TABLE slots
  ADD COLUMN IF NOT EXISTS service_id INTEGER REFERENCES services(id);

UPDATE slots
SET service_id = (SELECT id FROM services WHERE name = 'General consultation')
WHERE service_id IS NULL;

ALTER TABLE slots
  ALTER COLUMN service_id SET NOT NULL;

ALTER TABLE slots
  ADD COLUMN IF NOT EXISTS duration_minutes INTEGER,
  ADD COLUMN IF NOT EXISTS buffer_minutes INTEGER;

UPDATE slots s
SET duration_minutes = LEAST(
      svc.duration_minutes,
      GREATEST(1, FLOOR(EXTRACT(EPOCH FROM (s.ends_at - s.starts_at)) / 60)::integer)
    ),
    buffer_minutes = GREATEST(
      0,
      FLOOR(EXTRACT(EPOCH FROM (s.ends_at - s.starts_at)) / 60)::integer
      - LEAST(
          svc.duration_minutes,
          GREATEST(1, FLOOR(EXTRACT(EPOCH FROM (s.ends_at - s.starts_at)) / 60)::integer)
        )
    )
FROM services svc
WHERE svc.id = s.service_id
  AND (s.duration_minutes IS NULL OR s.buffer_minutes IS NULL);

ALTER TABLE slots
  ALTER COLUMN duration_minutes SET NOT NULL,
  ALTER COLUMN buffer_minutes SET NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'slots_duration_snapshot_check'
      AND conrelid = 'public.slots'::regclass
  ) THEN
    ALTER TABLE public.slots
      ADD CONSTRAINT slots_duration_snapshot_check
      CHECK (
        duration_minutes > 0
        AND buffer_minutes >= 0
        AND duration_minutes + buffer_minutes <= 1440
        AND ends_at = starts_at
          + make_interval(mins => duration_minutes + buffer_minutes)
      );
  END IF;
END
$$;

CREATE OR REPLACE FUNCTION public.set_slot_duration_snapshot()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $function$
DECLARE
  service_duration integer;
  total_minutes integer;
BEGIN
  IF NEW.duration_minutes IS NULL OR NEW.buffer_minutes IS NULL THEN
    SELECT svc.duration_minutes
    INTO service_duration
    FROM public.services svc
    WHERE svc.id = NEW.service_id;

    IF NOT FOUND THEN
      RAISE EXCEPTION 'slot service does not exist';
    END IF;

    total_minutes := FLOOR(
      EXTRACT(EPOCH FROM (NEW.ends_at - NEW.starts_at)) / 60
    )::integer;
    NEW.duration_minutes := LEAST(service_duration, GREATEST(1, total_minutes));
    NEW.buffer_minutes := GREATEST(0, total_minutes - NEW.duration_minutes);
  END IF;
  RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS slots_set_duration_snapshot ON public.slots;
CREATE TRIGGER slots_set_duration_snapshot
BEFORE INSERT ON public.slots
FOR EACH ROW
EXECUTE FUNCTION public.set_slot_duration_snapshot();

DO $$
DECLARE
  default_service_id INTEGER;
BEGIN
  SELECT id INTO default_service_id
  FROM services
  WHERE name = 'General consultation';

  IF default_service_id IS NULL THEN
    RAISE EXCEPTION 'default service is missing';
  END IF;

  EXECUTE format(
    'ALTER TABLE public.slots ALTER COLUMN service_id SET DEFAULT %s',
    default_service_id
  );
END
$$;

CREATE TABLE IF NOT EXISTS work_hours (
  id SERIAL PRIMARY KEY,
  doctor_id INTEGER NOT NULL REFERENCES doctors(id),
  weekday INTEGER NOT NULL CHECK (weekday BETWEEN 0 AND 6),
  start_time TIME NOT NULL,
  end_time TIME NOT NULL,
  slot_minutes INTEGER NOT NULL CHECK (slot_minutes > 0),
  UNIQUE (doctor_id, weekday)
);

CREATE TABLE IF NOT EXISTS time_off (
  id SERIAL PRIMARY KEY,
  doctor_id INTEGER NOT NULL REFERENCES doctors(id),
  starts_on DATE NOT NULL,
  ends_on DATE NOT NULL,
  CHECK (ends_on >= starts_on)
);

CREATE UNIQUE INDEX IF NOT EXISTS time_off_doctor_period
ON time_off (doctor_id, starts_on, ends_on);

CREATE TABLE IF NOT EXISTS time_off_requests (
  id SERIAL PRIMARY KEY,
  doctor_id INTEGER NOT NULL REFERENCES doctors(id),
  starts_on DATE NOT NULL,
  ends_on DATE NOT NULL,
  comment TEXT NOT NULL CHECK (
    length(btrim(comment)) BETWEEN 1 AND 200
  ),
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'approved', 'rejected')),
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  decided_by INTEGER REFERENCES users(id),
  decided_at TIMESTAMP,
  CHECK (ends_on >= starts_on),
  CHECK (
    (status = 'pending' AND decided_by IS NULL AND decided_at IS NULL)
    OR
    (status IN ('approved', 'rejected')
      AND decided_by IS NOT NULL AND decided_at IS NOT NULL)
  )
);

CREATE TABLE IF NOT EXISTS holidays (
  day DATE PRIMARY KEY,
  name TEXT NOT NULL
);


CREATE TABLE IF NOT EXISTS appointments (
  id SERIAL PRIMARY KEY,
  slot_id INTEGER NOT NULL REFERENCES slots(id),
  patient_user_id INTEGER NOT NULL REFERENCES users(id),
  status TEXT NOT NULL DEFAULT 'scheduled'
    CHECK (status IN ('scheduled', 'completed', 'cancelled'))
);

-- Extend status constraint for completed visits.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'appointments_status_check'
      AND conrelid = 'public.appointments'::regclass
      AND pg_get_constraintdef(oid) NOT LIKE '%completed%'
  ) THEN
    ALTER TABLE public.appointments DROP CONSTRAINT appointments_status_check;
  END IF;
END
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'appointments_status_check'
      AND conrelid = 'public.appointments'::regclass
  ) THEN
    ALTER TABLE public.appointments
      ADD CONSTRAINT appointments_status_check
      CHECK (status IN ('scheduled', 'completed', 'cancelled'));
  END IF;
END
$$;

ALTER TABLE appointments
DROP CONSTRAINT IF EXISTS appointments_slot_id_key;

DROP INDEX IF EXISTS appointments_slot_id_key;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_indexes
    WHERE indexname = 'appointments_one_scheduled_per_slot'
      AND indexdef NOT LIKE '%completed%'
  ) THEN
    DROP INDEX public.appointments_one_scheduled_per_slot;
  END IF;
END
$$;

-- Completed visits still reserve slots.
CREATE UNIQUE INDEX IF NOT EXISTS appointments_one_scheduled_per_slot
ON appointments (slot_id)
WHERE status IN ('scheduled', 'completed');

DROP INDEX IF EXISTS slots_doctor_start;
CREATE UNIQUE INDEX IF NOT EXISTS slots_doctor_service_start
ON slots (doctor_id, service_id, starts_at);
CREATE INDEX IF NOT EXISTS slots_starts_at
ON slots (starts_at);

CREATE EXTENSION IF NOT EXISTS btree_gist;

ALTER TABLE appointments
  ADD COLUMN IF NOT EXISTS doctor_id INTEGER REFERENCES doctors(id),
  ADD COLUMN IF NOT EXISTS starts_at TIMESTAMP,
  ADD COLUMN IF NOT EXISTS ends_at TIMESTAMP,
  ADD COLUMN IF NOT EXISTS reserved_ends_at TIMESTAMP;

UPDATE appointments a
SET
  doctor_id = s.doctor_id,
  starts_at = s.starts_at,
  ends_at = s.starts_at + make_interval(mins => s.duration_minutes),
  reserved_ends_at = s.ends_at
FROM slots s
WHERE s.id = a.slot_id
  AND (
    a.doctor_id IS NULL
    OR a.starts_at IS NULL
    OR a.ends_at IS NULL
    OR a.reserved_ends_at IS NULL
  );

ALTER TABLE appointments
  ALTER COLUMN doctor_id SET NOT NULL,
  ALTER COLUMN starts_at SET NOT NULL,
  ALTER COLUMN ends_at SET NOT NULL,
  ALTER COLUMN reserved_ends_at SET NOT NULL;

CREATE OR REPLACE FUNCTION public.set_appointment_reserved_end()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $function$
DECLARE
  slot_reserved_end timestamp;
BEGIN
  IF NEW.reserved_ends_at IS NULL THEN
    SELECT s.ends_at
    INTO slot_reserved_end
    FROM public.slots s
    WHERE s.id = NEW.slot_id;

    IF FOUND THEN
      NEW.reserved_ends_at := GREATEST(slot_reserved_end, NEW.ends_at);
    END IF;
  END IF;
  RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS appointments_set_reserved_end ON public.appointments;
CREATE TRIGGER appointments_set_reserved_end
BEFORE INSERT ON public.appointments
FOR EACH ROW
EXECUTE FUNCTION public.set_appointment_reserved_end();

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'appointments_reserved_end_check'
      AND conrelid = 'public.appointments'::regclass
  ) THEN
    ALTER TABLE public.appointments
      ADD CONSTRAINT appointments_reserved_end_check
      CHECK (reserved_ends_at >= ends_at);
  END IF;
END
$$;

CREATE INDEX IF NOT EXISTS appointments_doctor_starts_at
ON appointments (doctor_id, starts_at);

ALTER TABLE appointments
  ADD COLUMN IF NOT EXISTS doctor_period tsrange
  GENERATED ALWAYS AS (tsrange(starts_at, reserved_ends_at, '[)')) STORED;

ALTER TABLE appointments
  ADD COLUMN IF NOT EXISTS period tsrange
  GENERATED ALWAYS AS (tsrange(starts_at, ends_at, '[)')) STORED;

ALTER TABLE appointments
  DROP CONSTRAINT IF EXISTS appointments_no_overlap_per_doctor;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'appointments_no_overlap_per_doctor_reservation'
      AND conrelid = 'appointments'::regclass
      AND pg_get_constraintdef(oid) NOT LIKE '%completed%'
  ) THEN
    ALTER TABLE appointments DROP CONSTRAINT appointments_no_overlap_per_doctor_reservation;
  END IF;
END
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'appointments_no_overlap_per_doctor_reservation'
      AND conrelid = 'appointments'::regclass
      AND contype = 'x'
  ) THEN
    ALTER TABLE appointments
      ADD CONSTRAINT appointments_no_overlap_per_doctor_reservation
      EXCLUDE USING gist (
        doctor_id WITH =,
        doctor_period WITH &&
      )
      WHERE (status IN ('scheduled', 'completed'));
  END IF;
END
$$;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'appointments_no_overlap_per_patient'
      AND conrelid = 'appointments'::regclass
      AND pg_get_constraintdef(oid) NOT LIKE '%completed%'
  ) THEN
    ALTER TABLE appointments DROP CONSTRAINT appointments_no_overlap_per_patient;
  END IF;
END
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'appointments_no_overlap_per_patient'
      AND conrelid = 'appointments'::regclass
      AND contype = 'x'
  ) THEN
    ALTER TABLE appointments
      ADD CONSTRAINT appointments_no_overlap_per_patient
      EXCLUDE USING gist (
        patient_user_id WITH =,
        period WITH &&
      )
      WHERE (status IN ('scheduled', 'completed'));
  END IF;
END
$$;

ALTER TABLE slots
  ADD COLUMN IF NOT EXISTS time_range tsrange
  GENERATED ALWAYS AS (tsrange(starts_at, ends_at, '[)')) STORED;

ALTER TABLE slots
  DROP CONSTRAINT IF EXISTS slots_no_overlap_per_doctor;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'slots_no_overlap_per_doctor_service'
      AND conrelid = 'slots'::regclass
      AND contype = 'x'
  ) THEN
    ALTER TABLE slots
      ADD CONSTRAINT slots_no_overlap_per_doctor_service
      EXCLUDE USING gist (
        doctor_id WITH =,
        service_id WITH =,
        time_range WITH &&
      );
  END IF;
END
$$;
-- Policies: rls.sql.




CREATE TABLE IF NOT EXISTS visit_notes (
  id SERIAL PRIMARY KEY,
  appointment_id INTEGER NOT NULL REFERENCES appointments(id),
  doctor_id INTEGER NOT NULL REFERENCES doctors(id),
  patient_user_id INTEGER NOT NULL REFERENCES users(id),
  body TEXT NOT NULL
);

ALTER TABLE public.visit_notes
  DROP CONSTRAINT IF EXISTS visit_notes_appointment_id_key;
DROP INDEX IF EXISTS public.visit_notes_appointment_id_key;

CREATE TABLE IF NOT EXISTS prescriptions (
  id SERIAL PRIMARY KEY,
  appointment_id INTEGER NOT NULL REFERENCES appointments(id),
  doctor_id INTEGER NOT NULL REFERENCES doctors(id),
  patient_user_id INTEGER NOT NULL REFERENCES users(id),
  body TEXT NOT NULL
);

-- Require row-bound AES-GCM fe2 bodies.
-- Permit legacy conversion during startup migration.
ALTER TABLE public.visit_notes DROP CONSTRAINT IF EXISTS visit_notes_body_length_check;
ALTER TABLE public.prescriptions DROP CONSTRAINT IF EXISTS prescriptions_body_length_check;
ALTER TABLE public.visit_notes DROP CONSTRAINT IF EXISTS visit_notes_body_encrypted_check;
ALTER TABLE public.prescriptions DROP CONSTRAINT IF EXISTS prescriptions_body_encrypted_check;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'visit_notes_body_bound_check'
      AND conrelid = 'public.visit_notes'::regclass
  ) THEN
    ALTER TABLE public.visit_notes
      ADD CONSTRAINT visit_notes_body_bound_check
      CHECK (
        char_length(body) <= 24000
        AND body ~ '^fe2:[A-Za-z0-9_-]{1,32}:[A-Za-z0-9_-]{16}:[A-Za-z0-9_-]+:[A-Za-z0-9_-]{22}$'
      ) NOT VALID;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'prescriptions_body_bound_check'
      AND conrelid = 'public.prescriptions'::regclass
  ) THEN
    ALTER TABLE public.prescriptions
      ADD CONSTRAINT prescriptions_body_bound_check
      CHECK (
        char_length(body) <= 24000
        AND body ~ '^fe2:[A-Za-z0-9_-]{1,32}:[A-Za-z0-9_-]{16}:[A-Za-z0-9_-]+:[A-Za-z0-9_-]{22}$'
      ) NOT VALID;
  END IF;
END
$$;

CREATE TABLE IF NOT EXISTS audit_events (
  id BIGSERIAL PRIMARY KEY,
  actor_user_id INTEGER NOT NULL,
  actor_role TEXT NOT NULL CHECK (actor_role IN ('admin', 'doctor', 'patient', 'registrar')),
  action TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 80),
  target_type TEXT NOT NULL CHECK (length(target_type) BETWEEN 1 AND 80),
  target_id INTEGER,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS audit_events_created_at_idx
  ON audit_events (created_at DESC, id DESC);

-- Preserve anonymous auth privacy and deleted-user history.
DO $$
DECLARE
  fk record;
BEGIN
  FOR fk IN
    SELECT conname FROM pg_constraint
    WHERE conrelid = 'public.audit_events'::regclass
      AND contype = 'f'
      AND confrelid = 'public.users'::regclass
  LOOP
    EXECUTE format('ALTER TABLE public.audit_events DROP CONSTRAINT %I', fk.conname);
  END LOOP;
END
$$;
ALTER TABLE audit_events ALTER COLUMN actor_user_id DROP NOT NULL;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS reason TEXT;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS source TEXT;
-- Avoid repeated CHECK rebuilds.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'audit_events_actor_role_check'
      AND conrelid = 'public.audit_events'::regclass
      AND pg_get_constraintdef(oid) <> 'CHECK ((actor_role = ANY (ARRAY[''admin''::text, ''doctor''::text, ''patient''::text, ''registrar''::text, ''anonymous''::text])))'
  ) THEN
    ALTER TABLE public.audit_events DROP CONSTRAINT audit_events_actor_role_check;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'audit_events_actor_role_check'
      AND conrelid = 'public.audit_events'::regclass
  ) THEN
    ALTER TABLE public.audit_events ADD CONSTRAINT audit_events_actor_role_check
      CHECK (actor_role IN ('admin', 'doctor', 'patient', 'registrar', 'anonymous'));
  END IF;
END
$$;
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'audit_events_actor_check'
      AND conrelid = 'public.audit_events'::regclass
      AND pg_get_constraintdef(oid) <> 'CHECK ((((actor_user_id IS NOT NULL) AND (actor_role <> ''anonymous''::text)) OR ((actor_user_id IS NULL) AND (actor_role = ''anonymous''::text) AND (action = ANY (ARRAY[''auth.login.failure''::text, ''auth.rate_limited''::text])))))'
  ) THEN
    ALTER TABLE public.audit_events DROP CONSTRAINT audit_events_actor_check;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'audit_events_actor_check'
      AND conrelid = 'public.audit_events'::regclass
  ) THEN
    ALTER TABLE public.audit_events ADD CONSTRAINT audit_events_actor_check
      CHECK (
        (actor_user_id IS NOT NULL AND actor_role <> 'anonymous')
        OR (
          actor_user_id IS NULL
          AND actor_role = 'anonymous'
          AND action IN ('auth.login.failure', 'auth.rate_limited')
        )
      );
  END IF;
END
$$;
-- Add new journal reasons without rescanning current volumes.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'audit_events_reason_check'
      AND conrelid = 'public.audit_events'::regclass
      AND pg_get_constraintdef(oid) NOT LIKE '%''registration''%'
  ) THEN
    ALTER TABLE public.audit_events DROP CONSTRAINT audit_events_reason_check;
  END IF;
END
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'audit_events_reason_check'
      AND conrelid = 'public.audit_events'::regclass
  ) THEN
    ALTER TABLE public.audit_events
      ADD CONSTRAINT audit_events_reason_check
      CHECK (reason IS NULL OR reason IN (
        'bad_credentials', 'blocked', 'login', 'password_reset', 'email_change',
        'idle_timeout', 'absolute_timeout', 'unverified', 'email_verification',
        'registration'
      ));
  END IF;
END
$$;
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'audit_events_source_check'
      AND conrelid = 'public.audit_events'::regclass
      AND pg_get_constraintdef(oid) <> 'CHECK (((source IS NULL) OR (length(source) <= 64)))'
  ) THEN
    ALTER TABLE public.audit_events DROP CONSTRAINT audit_events_source_check;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'audit_events_source_check'
      AND conrelid = 'public.audit_events'::regclass
  ) THEN
    ALTER TABLE public.audit_events ADD CONSTRAINT audit_events_source_check
      CHECK (source IS NULL OR length(source) <= 64);
  END IF;
END
$$;

CREATE INDEX IF NOT EXISTS audit_events_rate_limited_idx
  ON audit_events (created_at)
  WHERE action = 'auth.rate_limited';

-- Audit settings and reschedule changes.
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS old_value INTEGER;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS new_value INTEGER;
-- Avoid scans unless the constraint changes.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'audit_events_change_values_check'
      AND conrelid = 'public.audit_events'::regclass
      AND pg_get_constraintdef(oid) NOT LIKE '%clinic.change_deadline.update%'
  ) THEN
    ALTER TABLE public.audit_events DROP CONSTRAINT audit_events_change_values_check;
  END IF;
END
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'audit_events_change_values_check'
      AND conrelid = 'public.audit_events'::regclass
  ) THEN
    ALTER TABLE public.audit_events
      ADD CONSTRAINT audit_events_change_values_check
      CHECK (
        (old_value IS NULL AND new_value IS NULL)
        OR action = 'clinic.session_idle.update'
        OR action = 'clinic.change_deadline.update'
        OR (
          action = 'appointment.reschedule'
          AND target_type = 'appointment'
          AND old_value IS NOT NULL
          AND new_value = target_id
        )
      );
  END IF;
END
$$;

-- Preserve startup when legacy duplicates exist.
-- BEGIN reschedule_unique
DO $$
BEGIN
  IF to_regclass('public.audit_events_reschedule_old_unique') IS NULL THEN
    IF EXISTS (SELECT old_value FROM public.audit_events
               WHERE action = 'appointment.reschedule'
               GROUP BY old_value HAVING count(*) > 1) THEN
      RAISE WARNING 'duplicate appointment.reschedule old_value, unique index skipped';
    ELSE
      CREATE UNIQUE INDEX audit_events_reschedule_old_unique
        ON public.audit_events (old_value) WHERE action = 'appointment.reschedule';
    END IF;
  END IF;
  IF to_regclass('public.audit_events_reschedule_new_unique') IS NULL THEN
    IF EXISTS (SELECT new_value FROM public.audit_events
               WHERE action = 'appointment.reschedule'
               GROUP BY new_value HAVING count(*) > 1) THEN
      RAISE WARNING 'duplicate appointment.reschedule new_value, unique index skipped';
    ELSE
      CREATE UNIQUE INDEX audit_events_reschedule_new_unique
        ON public.audit_events (new_value) WHERE action = 'appointment.reschedule';
    END IF;
  END IF;
END
$$;
-- END reschedule_unique

-- Support daily reschedule limits.
CREATE INDEX IF NOT EXISTS audit_events_reschedule_actor_idx
  ON audit_events (actor_user_id, created_at)
  WHERE action = 'appointment.reschedule';

-- Support audit-view deduplication.
CREATE INDEX IF NOT EXISTS audit_events_view_actor_idx
  ON audit_events (actor_user_id, target_id, created_at)
  WHERE action = 'audit.view';

-- Chain event hashes; external anchors reveal tampering.
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS seq bigint;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS prev_hash bytea;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS row_hash bytea;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS hash_version smallint;

CREATE TABLE IF NOT EXISTS audit_chain_head (
  id smallint PRIMARY KEY CHECK (id = 1),
  chain_id uuid NOT NULL,
  last_seq bigint NOT NULL,
  last_hash bytea NOT NULL CHECK (octet_length(last_hash) = 32),
  genesis_at timestamptz NOT NULL,
  genesis_rows bigint NOT NULL
);
REVOKE ALL ON TABLE public.audit_chain_head FROM PUBLIC;

-- Deterministic audit-field encoding.
CREATE OR REPLACE FUNCTION public.audit_canon_field(v text)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT CASE
    WHEN v IS NULL THEN '\x2d'::bytea
    ELSE convert_to(octet_length(convert_to(v, 'UTF8'))::text || ':', 'UTF8') || convert_to(v, 'UTF8')
  END
$$;

-- Keep audit hashes independent of timezone and locale.
CREATE OR REPLACE FUNCTION public.audit_canon_v1(
  p_seq bigint, p_id bigint, p_created_at timestamptz, p_actor_user_id integer,
  p_actor_role text, p_action text, p_target_type text, p_target_id integer,
  p_reason text, p_source text, p_old_value integer, p_new_value integer
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog, public, pg_temp
AS $$
  SELECT convert_to('clinic-audit-v1', 'UTF8')
    || public.audit_canon_field(p_seq::text)
    || public.audit_canon_field(p_id::text)
    || public.audit_canon_field(((extract(epoch FROM p_created_at) * 1000000)::bigint)::text)
    || public.audit_canon_field(p_actor_user_id::text)
    || public.audit_canon_field(p_actor_role)
    || public.audit_canon_field(p_action)
    || public.audit_canon_field(p_target_type)
    || public.audit_canon_field(p_target_id::text)
    || public.audit_canon_field(p_reason)
    || public.audit_canon_field(p_source)
    || public.audit_canon_field(p_old_value::text)
    || public.audit_canon_field(p_new_value::text)
$$;

CREATE OR REPLACE FUNCTION public.audit_row_hash_v1(p_prev bytea, p_canon bytea)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT sha256(p_prev || p_canon)
$$;

-- Seed the chain from its UUID.
CREATE OR REPLACE FUNCTION public.audit_genesis_hash_v1(p_chain uuid)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT sha256(uuid_send(p_chain))
$$;

-- Serialize inserts; avoid lock-order deadlocks.
CREATE OR REPLACE FUNCTION public.audit_chain_before_insert()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  h record;
BEGIN
  SELECT chain_id, last_seq, last_hash INTO h
    FROM public.audit_chain_head WHERE id = 1 FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'audit chain head missing' USING ERRCODE = '55000';
  END IF;
  NEW.created_at := CURRENT_TIMESTAMP;
  NEW.seq := h.last_seq + 1;
  NEW.prev_hash := h.last_hash;
  NEW.hash_version := 1;
  NEW.row_hash := public.audit_row_hash_v1(NEW.prev_hash, public.audit_canon_v1(
    NEW.seq, NEW.id, NEW.created_at, NEW.actor_user_id, NEW.actor_role, NEW.action,
    NEW.target_type, NEW.target_id, NEW.reason, NEW.source, NEW.old_value, NEW.new_value));
  UPDATE public.audit_chain_head SET last_seq = NEW.seq, last_hash = NEW.row_hash WHERE id = 1;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION public.audit_chain_before_insert() FROM PUBLIC;

-- Fail closed if the chain head is missing.
DO $$
DECLARE
  r record;
  chain uuid;
  prev bytea;
  n bigint := 0;
BEGIN
  PERFORM set_config('lock_timeout', '30s', true);
  LOCK TABLE public.audit_events IN ACCESS EXCLUSIVE MODE;
  IF NOT EXISTS (SELECT 1 FROM public.audit_chain_head WHERE id = 1) THEN
    IF EXISTS (SELECT 1 FROM public.audit_events WHERE seq IS NOT NULL) THEN
      RAISE EXCEPTION 'audit chain head missing, refusing to rebuild the chain'
        USING ERRCODE = '55000';
    END IF;
    chain := gen_random_uuid();
    prev := public.audit_genesis_hash_v1(chain);
    FOR r IN SELECT * FROM public.audit_events ORDER BY id LOOP
      n := n + 1;
      UPDATE public.audit_events
        SET seq = n, prev_hash = prev, hash_version = 1,
            row_hash = public.audit_row_hash_v1(prev, public.audit_canon_v1(
              n, r.id, r.created_at, r.actor_user_id, r.actor_role, r.action,
              r.target_type, r.target_id, r.reason, r.source, r.old_value, r.new_value))
        WHERE id = r.id
        RETURNING row_hash INTO prev;
    END LOOP;
    INSERT INTO public.audit_chain_head (id, chain_id, last_seq, last_hash, genesis_at, genesis_rows)
      VALUES (1, chain, n, prev, now(), n);
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_attribute
    WHERE attrelid = 'public.audit_events'::regclass
      AND attname IN ('seq', 'prev_hash', 'row_hash', 'hash_version')
      AND NOT attnotnull
  ) THEN
    ALTER TABLE public.audit_events
      ALTER COLUMN seq SET NOT NULL,
      ALTER COLUMN prev_hash SET NOT NULL,
      ALTER COLUMN row_hash SET NOT NULL,
      ALTER COLUMN hash_version SET NOT NULL;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'audit_events_seq_key' AND conrelid = 'public.audit_events'::regclass
  ) THEN
    ALTER TABLE public.audit_events ADD CONSTRAINT audit_events_seq_key UNIQUE (seq);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'audit_events_chain_check' AND conrelid = 'public.audit_events'::regclass
  ) THEN
    ALTER TABLE public.audit_events ADD CONSTRAINT audit_events_chain_check
      CHECK (octet_length(prev_hash) = 32 AND octet_length(row_hash) = 32
             AND hash_version = 1 AND seq >= 1);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid = 'public.audit_events'::regclass AND tgname = 'zz_audit_chain'
  ) THEN
    EXECUTE 'CREATE TRIGGER zz_audit_chain BEFORE INSERT ON public.audit_events
             FOR EACH ROW EXECUTE FUNCTION public.audit_chain_before_insert()';
  END IF;
END
$$;

-- Block owner writes; audit verifies trigger state.
CREATE OR REPLACE FUNCTION public.audit_append_only()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $function$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = '42501';
END;
$function$;
REVOKE ALL ON FUNCTION public.audit_append_only() FROM PUBLIC;

-- Restrict head updates to trigger-driven, one-step advances.
CREATE OR REPLACE FUNCTION public.audit_chain_head_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $function$
BEGIN
  IF pg_trigger_depth() <= 1
     OR NEW.id IS DISTINCT FROM OLD.id
     OR NEW.last_seq IS DISTINCT FROM OLD.last_seq + 1
     OR NEW.chain_id IS DISTINCT FROM OLD.chain_id
     OR NEW.genesis_at IS DISTINCT FROM OLD.genesis_at
     OR NEW.genesis_rows IS DISTINCT FROM OLD.genesis_rows THEN
    RAISE EXCEPTION 'audit_chain_head is updated only by the chain trigger'
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION public.audit_chain_head_guard() FROM PUBLIC;

DO $$
DECLARE
  spec record;
BEGIN
  FOR spec IN
    SELECT * FROM (VALUES
      ('public.audit_events', 'audit_events_no_update_delete',
       'BEFORE UPDATE OR DELETE ON public.audit_events FOR EACH ROW EXECUTE FUNCTION public.audit_append_only()'),
      ('public.audit_events', 'audit_events_no_truncate',
       'BEFORE TRUNCATE ON public.audit_events FOR EACH STATEMENT EXECUTE FUNCTION public.audit_append_only()'),
      ('public.audit_chain_head', 'audit_chain_head_guard',
       'BEFORE UPDATE ON public.audit_chain_head FOR EACH ROW EXECUTE FUNCTION public.audit_chain_head_guard()'),
      ('public.audit_chain_head', 'audit_chain_head_no_delete',
       'BEFORE DELETE ON public.audit_chain_head FOR EACH ROW EXECUTE FUNCTION public.audit_append_only()'),
      ('public.audit_chain_head', 'audit_chain_head_no_truncate',
       'BEFORE TRUNCATE ON public.audit_chain_head FOR EACH STATEMENT EXECUTE FUNCTION public.audit_append_only()')
    ) AS v(rel, name, body)
  LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_trigger
      WHERE tgrelid = spec.rel::regclass AND tgname = spec.name AND NOT tgisinternal
    ) THEN
      EXECUTE format('CREATE TRIGGER %I %s', spec.name, spec.body);
    END IF;
  END LOOP;
END
$$;

-- BEGIN audit_trigger_mode
-- Restore ALWAYS trigger mode on startup.
DO $$
DECLARE
  t record;
BEGIN
  FOR t IN
    SELECT tgrelid::regclass AS rel, tgname
    FROM pg_trigger
    WHERE tgrelid IN ('public.audit_events'::regclass, 'public.audit_chain_head'::regclass)
      AND NOT tgisinternal
      AND tgenabled <> 'A'
  LOOP
    EXECUTE format('ALTER TABLE %s ENABLE ALWAYS TRIGGER %I', t.rel, t.tgname);
  END LOOP;
END
$$;
-- END audit_trigger_mode
