FROM python:3.12.14-slim-trixie@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f

WORKDIR /app

RUN useradd --system --uid 10001 app

COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=app:app app/ .

EXPOSE 8000
USER app
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]