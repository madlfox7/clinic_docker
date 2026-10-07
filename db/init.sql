




CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','doctor','patient','registrar')),
  blocked BOOLEAN NOT NULL DEFAULT FALSE
);


ALTER TABLE users
ADD COLUMN IF NOT EXISTS blocked BOOLEAN NOT NULL DEFAULT FALSE;



CREATE TABLE IF NOT EXISTS doctors (
  id SERIAL PRIMARY KEY,
  user_id INTEGER UNIQUE REFERENCES users(id),
  full_name TEXT NOT NULL,
  specialty TEXT NOT NULL,
  experience_years INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS slots (
  id SERIAL PRIMARY KEY,
  doctor_id INTEGER NOT NULL REFERENCES doctors(id),
  starts_at TIMESTAMP NOT NULL,
  ends_at TIMESTAMP NOT NULL
);

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
);

ALTER TABLE appointments
DROP CONSTRAINT IF EXISTS appointments_slot_id_key;

DROP INDEX IF EXISTS appointments_slot_id_key;

CREATE UNIQUE INDEX IF NOT EXISTS appointments_one_scheduled_per_slot
ON appointments (slot_id)
WHERE status = 'scheduled';

CREATE UNIQUE INDEX IF NOT EXISTS slots_doctor_start
ON slots (doctor_id, starts_at);

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

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'slots_no_overlap_per_doctor'
      AND conrelid = 'slots'::regclass
      AND contype = 'x'
  ) THEN
    ALTER TABLE slots
      ADD CONSTRAINT slots_no_overlap_per_doctor
      EXCLUDE USING gist (
        doctor_id WITH =,
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
  body TEXT NOT NULL,
  UNIQUE (appointment_id)
);


--this one for rls
CREATE TABLE IF NOT EXISTS prescriptions (
  id SERIAL PRIMARY KEY,
  appointment_id INTEGER NOT NULL REFERENCES appointments(id),
  doctor_id INTEGER NOT NULL REFERENCES doctors(id),
  patient_user_id INTEGER NOT NULL REFERENCES users(id),
  body TEXT NOT NULL
);

