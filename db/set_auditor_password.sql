-- Keep password out of argv and logs.
\set audit_db_password `cat /run/secrets/audit_db_password`
SET log_statement = 'none';
ALTER ROLE clinic_auditor PASSWORD :'audit_db_password';
