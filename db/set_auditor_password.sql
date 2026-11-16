-- Same pattern as set_api_password.sql: psql reads the file itself, so the
-- password is in no argv and, with log_statement off, in no server log.
\set audit_db_password `cat /run/secrets/audit_db_password`
SET log_statement = 'none';
ALTER ROLE clinic_auditor PASSWORD :'audit_db_password';
