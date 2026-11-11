-- The password is read by psql itself (backticks run through popen), so it
-- never appears in any process argv. :'var' quotes it as a SQL literal.
-- The statement must not reach the server log even if log_statement is raised.
\set clinic_api_password `cat /run/secrets/clinic_api_password`
SET log_statement = 'none';
ALTER ROLE clinic_api PASSWORD :'clinic_api_password';
