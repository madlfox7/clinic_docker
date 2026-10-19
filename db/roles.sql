DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'clinic_api') THEN
    CREATE ROLE clinic_api
      LOGIN
      NOSUPERUSER
      NOBYPASSRLS
      NOCREATEDB
      NOCREATEROLE;
  END IF;
END
$$;

ALTER ROLE clinic_api
  LOGIN
  NOSUPERUSER
  NOBYPASSRLS
  NOCREATEDB
  NOCREATEROLE
  NOINHERIT;

ALTER ROLE clinic_api SET timezone TO 'Asia/Yerevan';

DO $$
BEGIN
  EXECUTE format(
    'ALTER ROLE %I SET timezone TO %L',
    current_user,
    'Asia/Yerevan'
  );
END
$$;

DO $$
DECLARE
  role_name text;
BEGIN
  FOREACH role_name IN ARRAY ARRAY[
    'app_guest',
    'app_patient',
    'app_doctor',
    'app_registrar',
    'app_admin'
  ]
  LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
      EXECUTE format(
        'CREATE ROLE %I NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT',
        role_name
      );
    END IF;
    EXECUTE format(
      'ALTER ROLE %I NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT',
      role_name
    );
  END LOOP;
END
$$;

GRANT app_guest, app_patient, app_doctor, app_registrar, app_admin
  TO clinic_api
  WITH INHERIT FALSE, SET TRUE;

REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public
  FROM app_guest, app_patient, app_doctor, app_registrar, app_admin;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public
  FROM app_guest, app_patient, app_doctor, app_registrar, app_admin;
REVOKE ALL PRIVILEGES ON public.login_attempts
  FROM PUBLIC, clinic_api, app_guest, app_patient, app_doctor, app_registrar, app_admin;

DO $$
BEGIN
  EXECUTE format(
    'GRANT CONNECT ON DATABASE %I TO clinic_api',
    current_database()
  );
END
$$;

GRANT USAGE ON SCHEMA public TO clinic_api;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM clinic_api;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM clinic_api;
REVOKE SELECT (password_hash) ON public.users FROM clinic_api;
GRANT SELECT (id, email, role, blocked, auth_version) ON public.users TO clinic_api;
GRANT SELECT ON public.doctors TO clinic_api;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
  REVOKE ALL ON TABLES FROM clinic_api;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  REVOKE ALL ON SEQUENCES FROM clinic_api;
