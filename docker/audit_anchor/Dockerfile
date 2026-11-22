# audit_anchor stores HMAC chain anchors and verifies the journal.
FROM python:3.12.14-slim-trixie@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f

WORKDIR /audit

RUN useradd --system --uid 10002 auditor

COPY docker/audit_anchor/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY audit/canon.py audit/chainlib.py audit/anchor.py audit/verify_audit.py ./

# /status is public and mounted read-only by the api.
RUN mkdir /status && chown 10002:10002 /status && chmod 755 /status
# /anchors stores chain data in the external audit_anchors volume.
RUN mkdir /anchors && chown 10002:10002 /anchors && chmod 700 /anchors

ENV PYTHONDONTWRITEBYTECODE=1
USER 10002
CMD ["python", "anchor.py"]
