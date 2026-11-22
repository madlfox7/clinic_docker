-- Keep password out of argv and logs.
\set clinic_api_password `cat /run/secrets/clinic_api_password`
SET log_statement = 'none';
ALTER ROLE clinic_api PASSWORD :'clinic_api_password';
