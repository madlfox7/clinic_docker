FROM postgres:16.15@sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54

COPY db/init.sql /docker-entrypoint-initdb.d/init.sql
COPY db/roles.sql /docker-entrypoint-initdb.d/roles.sql
COPY db/set_api_password.sql /migrations/set_api_password.sql