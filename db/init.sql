




CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','doctor','patient','registrar')),
  blocked BOOLEAN NOT NULL DEFAULT FALSE,
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
  address TEXT NOT NULL CHECK (length(btrim(address)) BETWEEN 1 AND 300),
  phone TEXT NOT NULL CHECK (length(btrim(phone)) BETWEEN 1 AND 50)
);

INSERT INTO clinic_settings (id, address, phone)
VALUES (1, 'Educational stand', '000-00-00')
ON CONFLICT (id) DO NOTHING;


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


--this one for rls
CREATE TABLE IF NOT EXISTS appointments (
  id SERIAL PRIMARY KEY,
  slot_id INTEGER NOT NULL REFERENCES slots(id),
  patient_user_id INTEGER NOT NULL REFERENCES users(id),
  status TEXT NOT NULL DEFAULT 'scheduled'
    CHECK (status IN ('scheduled', 'cancelled'))
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'appointments_status_check'
      AND conrelid = 'public.appointments'::regclass
  ) THEN
    ALTER TABLE public.appointments
      ADD CONSTRAINT appointments_status_check
      CHECK (status IN ('scheduled', 'cancelled'));
  END IF;
END
$$;

ALTER TABLE appointments
DROP CONSTRAINT IF EXISTS appointments_slot_id_key;

DROP INDEX IF EXISTS appointments_slot_id_key;

CREATE UNIQUE INDEX IF NOT EXISTS appointments_one_scheduled_per_slot
ON appointments (slot_id)
WHERE status = 'scheduled';

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
      WHERE (status = 'scheduled');
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
      WHERE (status = 'scheduled');
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
----------------------------




---this one for rls

CREATE TABLE IF NOT EXISTS visit_notes (
  id SERIAL PRIMARY KEY,
  appointment_id INTEGER NOT NULL REFERENCES appointments(id),
  doctor_id INTEGER NOT NULL REFERENCES doctors(id),
  patient_user_id INTEGER NOT NULL REFERENCES users(id),
  body TEXT NOT NULL CONSTRAINT visit_notes_body_length_check
    CHECK (char_length(body) <= 4000)
);

ALTER TABLE public.visit_notes
  DROP CONSTRAINT IF EXISTS visit_notes_appointment_id_key;
DROP INDEX IF EXISTS public.visit_notes_appointment_id_key;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'visit_notes_body_length_check'
      AND conrelid = 'public.visit_notes'::regclass
  ) THEN
    ALTER TABLE public.visit_notes
      ADD CONSTRAINT visit_notes_body_length_check
      CHECK (char_length(body) <= 4000) NOT VALID;
  END IF;
END
$$;

--this one for rls
CREATE TABLE IF NOT EXISTS prescriptions (
  id SERIAL PRIMARY KEY,
  appointment_id INTEGER NOT NULL REFERENCES appointments(id),
  doctor_id INTEGER NOT NULL REFERENCES doctors(id),
  patient_user_id INTEGER NOT NULL REFERENCES users(id),
  body TEXT NOT NULL CONSTRAINT prescriptions_body_length_check
    CHECK (char_length(body) <= 4000)
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'prescriptions_body_length_check'
      AND conrelid = 'public.prescriptions'::regclass
  ) THEN
    ALTER TABLE public.prescriptions
      ADD CONSTRAINT prescriptions_body_length_check
      CHECK (char_length(body) <= 4000) NOT VALID;
  END IF;
END
$$;

CREATE TABLE IF NOT EXISTS audit_events (
  id BIGSERIAL PRIMARY KEY,
  actor_user_id INTEGER NOT NULL REFERENCES users(id),
  actor_role TEXT NOT NULL CHECK (actor_role IN ('admin', 'doctor', 'patient', 'registrar')),
  action TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 80),
  target_type TEXT NOT NULL CHECK (length(target_type) BETWEEN 1 AND 80),
  target_id INTEGER,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS audit_events_created_at_idx
  ON audit_events (created_at DESC, id DESC);
