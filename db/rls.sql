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
    FROM public.slots AS s
    JOIN public.appointments AS a
      ON a.doctor_id = s.doctor_id
     AND a.starts_at < s.ends_at
     AND a.reserved_ends_at > s.starts_at
    WHERE s.id = target_slot_id
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
  target_visit_ends_at timestamp,
  target_reserved_ends_at timestamp
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
      AND s.starts_at + make_interval(mins => s.duration_minutes)
          = target_visit_ends_at
      AND s.ends_at = target_reserved_ends_at
      AND s.starts_at > CURRENT_TIMESTAMP
      AND public.doctor_is_active(target_doctor_id)
      AND EXISTS (
        SELECT 1
        FROM public.doctor_services AS ds
        WHERE ds.doctor_id = s.doctor_id
          AND ds.service_id = s.service_id
      )
      AND EXISTS (
        SELECT 1
        FROM public.services AS svc
        WHERE svc.id = s.service_id
          AND svc.active
      )
      AND NOT EXISTS (
        SELECT 1
        FROM public.appointments AS a
        WHERE a.doctor_id = s.doctor_id
          AND a.starts_at < s.ends_at
          AND a.reserved_ends_at > s.starts_at
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

CREATE OR REPLACE FUNCTION public.doctor_can_write_medical_record(
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
      AND a.status = 'scheduled'
      AND a.starts_at > CURRENT_TIMESTAMP - INTERVAL '12 months'
  );
$function$;

REVOKE ALL ON FUNCTION public.doctor_can_write_medical_record(integer, integer, integer)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.doctor_can_write_medical_record(integer, integer, integer)
  TO app_doctor;

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
     OR replacement_hash !~ '^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$'
     OR NOT EXISTS (
       SELECT 1
       FROM public.users
       WHERE id = actor_id AND role = 'admin' AND NOT blocked
     ) THEN
    RAISE EXCEPTION 'invalid admin password-reset context'
      USING ERRCODE = '42501';
  END IF;

  UPDATE public.users
  SET password_hash = replacement_hash,
      auth_version = auth_version + 1
  WHERE id = target_user_id
    AND id <> actor_id
    AND role IN ('registrar', 'admin')
  RETURNING role INTO target_role;

  RETURN target_role;
END;
$function$;

CREATE OR REPLACE FUNCTION public.request_patient_password_reset(
  candidate_email text,
  candidate_source text
)
RETURNS TABLE (
  reset_token text,
  rate_limited boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
DECLARE
  normalized_email text := lower(btrim(coalesce(candidate_email, '')));
  email_key bytea := public.digest(normalized_email, 'sha256');
  source_key bytea := public.digest(coalesce(candidate_source, ''), 'sha256');
  attempt_count integer;
  attempt_window timestamptz;
  attempt_found boolean;
  source_count integer;
  target_id integer;
  raw_token text;
BEGIN
  PERFORM pg_advisory_xact_lock(
    hashtextextended(encode(email_key, 'hex') || ':' || encode(source_key, 'hex'), 0)
  );

  DELETE FROM public.password_reset_attempts
  WHERE last_request_at < CURRENT_TIMESTAMP - INTERVAL '1 day';
  DELETE FROM public.password_reset_tokens
  WHERE expires_at < CURRENT_TIMESTAMP - INTERVAL '1 day';

  SELECT request_count, window_started_at
  INTO attempt_count, attempt_window
  FROM public.password_reset_attempts
  WHERE email_fingerprint = email_key
    AND source_fingerprint = source_key
  FOR UPDATE;
  attempt_found := FOUND;

  IF attempt_found
     AND attempt_window > CURRENT_TIMESTAMP - INTERVAL '15 minutes'
     AND attempt_count >= 5 THEN
    RETURN QUERY SELECT NULL::text, TRUE;
    RETURN;
  END IF;

  SELECT coalesce(sum(request_count), 0)
  INTO source_count
  FROM public.password_reset_attempts
  WHERE source_fingerprint = source_key
    AND window_started_at > CURRENT_TIMESTAMP - INTERVAL '15 minutes';

  IF source_count >= 100 THEN
    RETURN QUERY SELECT NULL::text, TRUE;
    RETURN;
  END IF;

  IF attempt_found AND attempt_window > CURRENT_TIMESTAMP - INTERVAL '15 minutes' THEN
    UPDATE public.password_reset_attempts
    SET request_count = request_count + 1,
        last_request_at = CURRENT_TIMESTAMP
    WHERE email_fingerprint = email_key
      AND source_fingerprint = source_key;
  ELSIF attempt_found THEN
    UPDATE public.password_reset_attempts
    SET request_count = 1,
        window_started_at = CURRENT_TIMESTAMP,
        last_request_at = CURRENT_TIMESTAMP
    WHERE email_fingerprint = email_key
      AND source_fingerprint = source_key;
  ELSE
    INSERT INTO public.password_reset_attempts (
      email_fingerprint, source_fingerprint, request_count,
      window_started_at, last_request_at
    )
    VALUES (email_key, source_key, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
  END IF;

  IF candidate_email IS NULL
     OR length(normalized_email) NOT BETWEEN 3 AND 254
     OR position('@' IN normalized_email) = 0 THEN
    RETURN QUERY SELECT NULL::text, FALSE;
    RETURN;
  END IF;

  SELECT u.id
  INTO target_id
  FROM public.users AS u
  WHERE lower(u.email) = normalized_email
    AND u.role = 'patient'
    AND NOT u.blocked;

  IF target_id IS NULL THEN
    RETURN QUERY SELECT NULL::text, FALSE;
    RETURN;
  END IF;

  UPDATE public.password_reset_tokens
  SET used_at = CURRENT_TIMESTAMP
  WHERE user_id = target_id
    AND used_at IS NULL;

  raw_token := encode(public.gen_random_bytes(32), 'hex');
  INSERT INTO public.password_reset_tokens (user_id, token_hash, expires_at)
  VALUES (
    target_id,
    public.digest(raw_token, 'sha256'),
    CURRENT_TIMESTAMP + INTERVAL '15 minutes'
  );

  RETURN QUERY SELECT raw_token, FALSE;
END;
$function$;

DROP FUNCTION IF EXISTS public.consume_patient_password_reset(text, text);
CREATE OR REPLACE FUNCTION public.consume_patient_password_reset(
  raw_token text,
  candidate_password text,
  replacement_hash text
)
RETURNS TABLE (
  result text,
  resulting_auth_version bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
DECLARE
  token_id bigint;
  target_id integer;
  changed_auth_version bigint;
BEGIN
  IF raw_token IS NULL
     OR raw_token !~ '^[0-9a-f]{64}$'
     OR replacement_hash IS NULL
     OR replacement_hash !~ '^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$' THEN
    RETURN QUERY SELECT 'invalid'::text, NULL::bigint;
    RETURN;
  END IF;

  SELECT t.id, u.id
  INTO token_id, target_id
  FROM public.password_reset_tokens AS t
  JOIN public.users AS u ON u.id = t.user_id
  WHERE t.token_hash = public.digest(raw_token, 'sha256')
    AND t.used_at IS NULL
    AND t.expires_at > CURRENT_TIMESTAMP
    AND u.role = 'patient'
    AND NOT u.blocked
  FOR UPDATE OF t, u;

  IF NOT FOUND THEN
    RETURN QUERY SELECT 'invalid'::text, NULL::bigint;
    RETURN;
  END IF;

  IF candidate_password IS NOT NULL
     AND (
       lower(candidate_password) = (
         SELECT lower(email) FROM public.users WHERE id = target_id
       )
       OR lower(candidate_password) = split_part(
         (SELECT lower(email) FROM public.users WHERE id = target_id),
         '@',
         1
       )
     ) THEN
    RETURN QUERY SELECT 'weak'::text, NULL::bigint;
    RETURN;
  END IF;

  UPDATE public.users
  SET password_hash = replacement_hash,
      auth_version = public.users.auth_version + 1
  WHERE id = target_id
  RETURNING public.users.auth_version INTO changed_auth_version;

  UPDATE public.password_reset_tokens
  SET used_at = CURRENT_TIMESTAMP
  WHERE id = token_id
     OR (user_id = target_id AND used_at IS NULL);

  INSERT INTO public.audit_events (
    actor_user_id, actor_role, action, target_type, target_id
  )
  VALUES (
    target_id, 'patient', 'user.password_recovery', 'user', target_id
  );

  RETURN QUERY SELECT 'changed'::text, changed_auth_version;
END;
$function$;

DROP FUNCTION IF EXISTS public.authenticate_user(text, text);
DROP FUNCTION IF EXISTS public.authenticate_user(text, text, text);
CREATE FUNCTION public.authenticate_user(
  candidate_email text,
  candidate_password text,
  candidate_source text
)
RETURNS TABLE (
  id integer,
  email text,
  role text,
  blocked boolean,
  auth_version bigint,
  rate_limited boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
DECLARE
  email_key bytea := public.digest(lower(coalesce(candidate_email, '')), 'sha256');
  source_key bytea := public.digest(coalesce(candidate_source, ''), 'sha256');
  pair_failed_attempts integer := 0;
  pair_window_started_at timestamptz;
  source_failed_attempts bigint := 0;
  dummy_hash constant text := '$2a$12$vDAC/mONY1XhFCXLJzJKEeuU11gysuOWcZeEh61E/Bys6htguv6eC';
  matched_id integer;
  matched_email text;
  matched_role text;
  matched_blocked boolean;
  matched_auth_version bigint;
  stored_hash text;
  password_to_check text;
  password_matches boolean := FALSE;
  user_found boolean := FALSE;
BEGIN
  PERFORM pg_advisory_xact_lock(
    hashtextextended(encode(email_key, 'hex') || ':' || encode(source_key, 'hex'), 0)
  );

  DELETE FROM public.login_attempts
  WHERE last_attempt_at < CURRENT_TIMESTAMP - INTERVAL '1 day';

  SELECT failed_attempts, window_started_at
  INTO pair_failed_attempts, pair_window_started_at
  FROM public.login_attempts
  WHERE email_fingerprint = email_key
    AND source_fingerprint = source_key;

  SELECT coalesce(sum(failed_attempts), 0)
  INTO source_failed_attempts
  FROM public.login_attempts
  WHERE source_fingerprint = source_key
    AND last_attempt_at > CURRENT_TIMESTAMP - INTERVAL '15 minutes';

  IF (
       pair_window_started_at > CURRENT_TIMESTAMP - INTERVAL '15 minutes'
       AND pair_failed_attempts >= 5
     )
     OR source_failed_attempts >= 100 THEN
    RETURN QUERY
    SELECT NULL::integer, NULL::text, NULL::text, NULL::boolean,
           NULL::bigint, TRUE;
    RETURN;
  END IF;

  -- One cost-12 crypt runs whether or not the email exists.
  SELECT u.id, u.email, u.role, u.blocked, u.auth_version, u.password_hash
  INTO matched_id, matched_email, matched_role, matched_blocked,
       matched_auth_version, stored_hash
  FROM public.users AS u
  WHERE candidate_email IS NOT NULL
    AND lower(u.email) = lower(candidate_email);
  user_found := FOUND;

  password_to_check := candidate_password;
  IF NOT user_found OR stored_hash IS NULL
     OR password_to_check IS NULL
     OR octet_length(password_to_check) > 72 THEN
    stored_hash := dummy_hash;
    IF password_to_check IS NULL OR octet_length(password_to_check) > 72 THEN
      password_to_check := 'invalid-password';
    END IF;
  ELSIF left(stored_hash, 4) = '$2b$' THEN
    stored_hash := '$2a$' || substring(stored_hash FROM 5);
  END IF;

  password_matches := public.crypt(password_to_check, stored_hash) = stored_hash;

  IF user_found AND password_matches AND stored_hash IS DISTINCT FROM dummy_hash THEN
    DELETE FROM public.login_attempts
    WHERE email_fingerprint = email_key
      AND source_fingerprint = source_key;
    RETURN QUERY
    SELECT matched_id, matched_email, matched_role, matched_blocked,
           matched_auth_version, FALSE;
    RETURN;
  END IF;

  INSERT INTO public.login_attempts (
    email_fingerprint, source_fingerprint, failed_attempts,
    window_started_at, last_attempt_at
  )
  VALUES (email_key, source_key, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
  ON CONFLICT (email_fingerprint, source_fingerprint)
  DO UPDATE SET
    failed_attempts = CASE
      WHEN public.login_attempts.window_started_at
           <= CURRENT_TIMESTAMP - INTERVAL '15 minutes'
        THEN 1
      ELSE public.login_attempts.failed_attempts + 1
    END,
    window_started_at = CASE
      WHEN public.login_attempts.window_started_at
           <= CURRENT_TIMESTAMP - INTERVAL '15 minutes'
        THEN CURRENT_TIMESTAMP
      ELSE public.login_attempts.window_started_at
    END,
    last_attempt_at = CURRENT_TIMESTAMP;
END;
$function$;

CREATE OR REPLACE FUNCTION public.bootstrap_seed_admin(
  seed_email text,
  replacement_hash text
)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
DECLARE
  existing_admin_id integer;
  created_admin_id integer;
BEGIN
  IF session_user IS DISTINCT FROM 'clinic_api'
     OR seed_email IS DISTINCT FROM 'admin@clinic.local'
     OR replacement_hash IS NULL
     OR replacement_hash !~ '^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$' THEN
    RAISE EXCEPTION 'invalid seed-admin context'
      USING ERRCODE = '42501';
  END IF;

  SELECT id INTO existing_admin_id
  FROM public.users
  WHERE email = seed_email AND role = 'admin';

  IF existing_admin_id IS NOT NULL THEN
    RETURN existing_admin_id;
  END IF;

  IF EXISTS (SELECT 1 FROM public.users) THEN
    RAISE EXCEPTION 'seed admin can only be bootstrapped into an empty users table'
      USING ERRCODE = '42501';
  END IF;

  INSERT INTO public.users (email, password_hash, role, blocked)
  VALUES (seed_email, replacement_hash, 'admin', FALSE)
  RETURNING id INTO created_admin_id;

  RETURN created_admin_id;
END;
$function$;

CREATE OR REPLACE FUNCTION public.calendar_patient_email(
  target_patient_id integer,
  target_doctor_id integer
)
RETURNS text
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
DECLARE
  actor_id integer := NULLIF(current_setting('app.user_id', true), '')::integer;
  actor_role text := current_setting('role', true);
  patient_email text;
BEGIN
  IF target_patient_id IS NULL OR target_doctor_id IS NULL THEN
    RETURN NULL;
  END IF;

  IF actor_role = 'app_registrar' THEN
    SELECT u.email INTO patient_email
    FROM public.users AS u
    WHERE u.id = target_patient_id AND u.role = 'patient';
    RETURN patient_email;
  END IF;

  IF actor_role = 'app_doctor'
     AND EXISTS (
       SELECT 1
       FROM public.doctors AS d
       WHERE d.id = target_doctor_id AND d.user_id = actor_id
     ) THEN
    SELECT dp.email INTO patient_email
    FROM public.doctor_patients(actor_id) AS dp
    WHERE dp.id = target_patient_id;
  END IF;

  RETURN patient_email;
END;
$function$;

DROP FUNCTION IF EXISTS public.current_patient_password_hash();
DROP FUNCTION IF EXISTS public.change_own_patient_password(text, text);

CREATE OR REPLACE FUNCTION public.change_own_patient_password(
  current_password text,
  new_password text,
  replacement_hash text
)
RETURNS TABLE (result text, resulting_auth_version bigint)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
DECLARE
  actor_id integer := NULLIF(current_setting('app.user_id', true), '')::integer;
  actor_role text := current_setting('role', true);
  target_user_role text;
  stored_hash text;
  crypt_hash text;
  changed_auth_version bigint;
BEGIN
  target_user_role := CASE actor_role
    WHEN 'app_patient' THEN 'patient'
    WHEN 'app_doctor' THEN 'doctor'
    WHEN 'app_registrar' THEN 'registrar'
    WHEN 'app_admin' THEN 'admin'
    ELSE NULL
  END;

  IF target_user_role IS NULL
     OR actor_id IS NULL
     OR current_password IS NULL
     OR new_password IS NULL
     OR octet_length(current_password) > 72
     OR octet_length(new_password) > 72
     OR replacement_hash IS NULL
     OR replacement_hash !~ '^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$' THEN
    RAISE EXCEPTION 'invalid password-change context'
      USING ERRCODE = '42501';
  END IF;

  SELECT u.password_hash INTO stored_hash
  FROM public.users AS u
  WHERE u.id = actor_id
    AND u.role = target_user_role
    AND NOT u.blocked
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN QUERY SELECT 'unavailable'::text, NULL::bigint;
    RETURN;
  END IF;

  crypt_hash := CASE
    WHEN left(stored_hash, 4) = '$2b$'
      THEN '$2a$' || substring(stored_hash FROM 5)
    ELSE stored_hash
  END;

  IF public.crypt(current_password, crypt_hash) IS DISTINCT FROM crypt_hash THEN
    RETURN QUERY SELECT 'current'::text, NULL::bigint;
    RETURN;
  END IF;

  IF public.crypt(new_password, crypt_hash) = crypt_hash THEN
    RETURN QUERY SELECT 'same'::text, NULL::bigint;
    RETURN;
  END IF;

  UPDATE public.users
  SET password_hash = replacement_hash,
      auth_version = public.users.auth_version + 1
  WHERE id = actor_id
    AND role = target_user_role
    AND NOT blocked
    AND password_hash = stored_hash
  RETURNING public.users.auth_version INTO changed_auth_version;

  IF NOT FOUND THEN
    RETURN QUERY SELECT 'stale'::text, NULL::bigint;
    RETURN;
  END IF;

  RETURN QUERY SELECT 'changed'::text, changed_auth_version;
END;
$function$;

REVOKE ALL ON FUNCTION public.current_patient_is_active() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.scheduled_slot_is_taken(integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.doctor_is_active(integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.is_valid_free_slot(integer, integer, timestamp, timestamp, timestamp) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.record_audit_event(text, text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.admin_reset_user_password(integer, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.authenticate_user(text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.bootstrap_seed_admin(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.calendar_patient_email(integer, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.change_own_patient_password(text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.current_patient_is_active() TO app_patient;
GRANT EXECUTE ON FUNCTION public.scheduled_slot_is_taken(integer)
  TO app_patient, app_registrar, app_admin;
GRANT EXECUTE ON FUNCTION public.doctor_is_active(integer)
  TO app_patient, app_registrar, app_admin;
GRANT EXECUTE ON FUNCTION public.is_valid_free_slot(
  integer, integer, timestamp, timestamp, timestamp
) TO app_patient, app_registrar;
GRANT EXECUTE ON FUNCTION public.record_audit_event(text, text, integer)
  TO app_patient, app_doctor, app_registrar, app_admin;
GRANT EXECUTE ON FUNCTION public.admin_reset_user_password(integer, text)
  TO app_admin;
CREATE OR REPLACE FUNCTION public.revoke_patient_password_reset(raw_token text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
BEGIN
  IF raw_token IS NULL OR raw_token !~ '^[0-9a-f]{64}$' THEN
    RETURN;
  END IF;

  UPDATE public.password_reset_tokens
  SET used_at = CURRENT_TIMESTAMP
  WHERE token_hash = public.digest(raw_token, 'sha256')
    AND used_at IS NULL;
END;
$function$;

REVOKE ALL ON FUNCTION public.request_patient_password_reset(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.consume_patient_password_reset(text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.revoke_patient_password_reset(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.request_patient_password_reset(text, text) TO clinic_api;
GRANT EXECUTE ON FUNCTION public.consume_patient_password_reset(text, text, text) TO clinic_api;
GRANT EXECUTE ON FUNCTION public.revoke_patient_password_reset(text) TO clinic_api;
REVOKE ALL ON TABLE public.password_reset_tokens, public.password_reset_attempts
  FROM PUBLIC, clinic_api, app_guest, app_patient, app_doctor, app_registrar, app_admin;
REVOKE ALL ON SEQUENCE public.password_reset_tokens_id_seq
  FROM PUBLIC, clinic_api, app_guest, app_patient, app_doctor, app_registrar, app_admin;
GRANT EXECUTE ON FUNCTION public.authenticate_user(text, text, text) TO clinic_api;
GRANT EXECUTE ON FUNCTION public.bootstrap_seed_admin(text, text) TO clinic_api;
GRANT EXECUTE ON FUNCTION public.calendar_patient_email(integer, integer)
  TO app_doctor, app_registrar;
GRANT EXECUTE ON FUNCTION public.change_own_patient_password(text, text, text)
  TO app_patient, app_doctor, app_registrar, app_admin;

GRANT USAGE ON SCHEMA public
  TO app_guest, app_patient, app_doctor, app_registrar, app_admin;

GRANT SELECT ON public.doctors TO app_guest, app_patient, app_doctor, app_registrar, app_admin;
GRANT SELECT ON public.services
  TO app_guest, app_patient, app_doctor, app_registrar, app_admin;
GRANT INSERT, UPDATE, DELETE ON public.services TO app_admin;
GRANT USAGE, SELECT ON SEQUENCE public.services_id_seq TO app_admin;
GRANT SELECT ON public.doctor_services
  TO app_patient, app_doctor, app_registrar, app_admin;
GRANT INSERT, DELETE ON public.doctor_services TO app_admin;
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
GRANT INSERT (
  slot_id, patient_user_id, doctor_id, starts_at, ends_at, reserved_ends_at
)
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
GRANT INSERT (
  doctor_id, service_id, starts_at, ends_at,
  duration_minutes, buffer_minutes
), DELETE
  ON public.slots TO app_admin;
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
    AND public.is_valid_free_slot(
      slot_id, doctor_id, starts_at, ends_at, reserved_ends_at
    )
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
    AND public.is_valid_free_slot(
      slot_id, doctor_id, starts_at, ends_at, reserved_ends_at
    )
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

DROP FUNCTION IF EXISTS public.is_valid_free_slot(integer, integer, timestamp, timestamp);

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
    AND public.doctor_can_write_medical_record(
      appointment_id, doctor_id, patient_user_id
    )
  );
CREATE POLICY doctor_notes_update ON public.visit_notes
  FOR UPDATE TO app_doctor
  USING (
    doctor_id = (
      SELECT id
      FROM public.doctors
      WHERE user_id = current_setting('app.user_id', true)::int
    )
    AND public.doctor_can_write_medical_record(
      appointment_id, doctor_id, patient_user_id
    )
  )
  WITH CHECK (
    doctor_id = (
      SELECT id
      FROM public.doctors
      WHERE user_id = current_setting('app.user_id', true)::int
    )
    AND public.doctor_can_write_medical_record(
      appointment_id, doctor_id, patient_user_id
    )
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
    AND public.doctor_can_write_medical_record(
      appointment_id, doctor_id, patient_user_id
    )
  );
CREATE POLICY doctor_prescriptions_update ON public.prescriptions
  FOR UPDATE TO app_doctor
  USING (
    doctor_id = (
      SELECT id
      FROM public.doctors
      WHERE user_id = current_setting('app.user_id', true)::int
    )
    AND public.doctor_can_write_medical_record(
      appointment_id, doctor_id, patient_user_id
    )
  )
  WITH CHECK (
    doctor_id = (
      SELECT id
      FROM public.doctors
      WHERE user_id = current_setting('app.user_id', true)::int
    )
    AND public.doctor_can_write_medical_record(
      appointment_id, doctor_id, patient_user_id
    )
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
  USING (
    role IN ('patient', 'doctor', 'admin')
    AND id <> current_setting('app.user_id', true)::integer
  )
  WITH CHECK (
    role IN ('patient', 'doctor', 'admin')
    AND id <> current_setting('app.user_id', true)::integer
  );
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

DROP POLICY IF EXISTS services_active_select ON public.services;
DROP POLICY IF EXISTS services_appointment_history_select ON public.services;
DROP POLICY IF EXISTS services_admin_select ON public.services;
DROP POLICY IF EXISTS services_admin_insert ON public.services;
DROP POLICY IF EXISTS services_admin_update ON public.services;
DROP POLICY IF EXISTS services_admin_delete ON public.services;
CREATE POLICY services_active_select ON public.services
  FOR SELECT TO app_guest, app_patient, app_doctor, app_registrar
  USING (active);
CREATE POLICY services_appointment_history_select ON public.services
  FOR SELECT TO app_patient, app_doctor, app_registrar
  USING (
    EXISTS (
      SELECT 1
      FROM public.slots s
      JOIN public.appointments a ON a.slot_id = s.id
      WHERE s.service_id = services.id
        AND (
          (
            current_setting('role', true) = 'app_patient'
            AND a.patient_user_id =
                current_setting('app.user_id', true)::integer
          )
          OR (
            current_setting('role', true) = 'app_doctor'
            AND a.doctor_id IN (
              SELECT d.id FROM public.doctors d
              WHERE d.user_id = current_setting('app.user_id', true)::integer
            )
          )
          OR current_setting('role', true) = 'app_registrar'
        )
    )
  );
CREATE POLICY services_admin_select ON public.services
  FOR SELECT TO app_admin USING (true);
CREATE POLICY services_admin_insert ON public.services
  FOR INSERT TO app_admin WITH CHECK (true);
CREATE POLICY services_admin_update ON public.services
  FOR UPDATE TO app_admin USING (true) WITH CHECK (true);
CREATE POLICY services_admin_delete ON public.services
  FOR DELETE TO app_admin
  USING (
    NOT EXISTS (
      SELECT 1 FROM public.slots s WHERE s.service_id = services.id
    )
  );

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
ALTER TABLE public.services ENABLE ROW LEVEL SECURITY;
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
