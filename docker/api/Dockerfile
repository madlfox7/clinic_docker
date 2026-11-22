FROM python:3.12.14-slim-trixie@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f

WORKDIR /app

RUN useradd --system --uid 10001 app

COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=app:app app/ .
COPY --chown=app:app db/init.sql /app/schema/init.sql

EXPOSE 8000
USER app
# Migrate medical fields before serving.
# Only the api mounts the encryption key.
# Validate forwarded headers in app/trusted_proxy.py.
CMD ["sh", "-c", "python -m migrate_medical_fields && exec uvicorn main:app --host 0.0.0.0 --port 8000 --no-proxy-headers"]