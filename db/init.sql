




CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','doctor','patient','registrar')),
  blocked BOOLEAN NOT NULL DEFAULT FALSE
);


ALTER TABLE users
ADD COLUMN IF NOT EXISTS blocked BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE users
ALTER COLUMN blocked SET DEFAULT FALSE;

CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_unique
ON users (lower(email));

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

CREATE TABLE IF NOT EXISTS slots (
  id SERIAL PRIMARY KEY,
  doctor_id INTEGER NOT NULL REFERENCES doctors(id),
  service_id INTEGER REFERENCES services(id),
  starts_at TIMESTAMP NOT NULL,
  ends_at TIMESTAMP NOT NULL
);

ALTER TABLE slots
  ADD COLUMN IF NOT EXISTS service_id INTEGER REFERENCES services(id);

UPDATE slots
SET service_id = (SELECT id FROM services WHERE name = 'General consultation')
WHERE service_id IS NULL;

ALTER TABLE slots
  ALTER COLUMN service_id SET NOT NULL;

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
  ADD COLUMN IF NOT EXISTS ends_at TIMESTAMP;

UPDATE appointments a
SET
  doctor_id = s.doctor_id,
  starts_at = s.starts_at,
  ends_at = s.ends_at
FROM slots s
WHERE s.id = a.slot_id
  AND (a.doctor_id IS NULL OR a.starts_at IS NULL OR a.ends_at IS NULL);

ALTER TABLE appointments
  ALTER COLUMN doctor_id SET NOT NULL,
  ALTER COLUMN starts_at SET NOT NULL,
  ALTER COLUMN ends_at SET NOT NULL;
CREATE INDEX IF NOT EXISTS appointments_doctor_starts_at
ON appointments (doctor_id, starts_at);

ALTER TABLE appointments
  ADD COLUMN IF NOT EXISTS period tsrange
  GENERATED ALWAYS AS (tsrange(starts_at, ends_at, '[)')) STORED;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'appointments_no_overlap_per_doctor'
      AND conrelid = 'appointments'::regclass
      AND contype = 'x'
  ) THEN
    ALTER TABLE appointments
      ADD CONSTRAINT appointments_no_overlap_per_doctor
      EXCLUDE USING gist (
        doctor_id WITH =,
        period WITH &&
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
