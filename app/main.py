import logging
import os
import re

from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from routes_admin import router as admin_router
from routes_auth import router as auth_router
from routes_booking import router as booking_router
from routes_records import router as records_router
from routes_schedule import router as schedule_router


_REJECTED_SECRETS = {
    "dev-secret-change-me",
    "change_me",
    "changeme",
    "secret",
    "password",
    "password123",
}


def _session_secret() -> str:
    raw = ""
    try:
        with open("/run/secrets/session_secret", encoding="utf-8") as handle:
            raw = handle.read().strip()
    except OSError:
        raw = ""
    if not raw:
        raw = os.environ.get("SESSION_SECRET", "").strip()
    if len(raw) < 32 or raw.lower() in _REJECTED_SECRETS:
        raise RuntimeError(
            "SESSION_SECRET must be a non-default secret of at least 32 characters"
        )
    return raw


SESSION_SECRET = _session_secret()

_TOKEN_QUERY = re.compile(r"([?&]token=)[^&\s\"]+")


class _RedactTokenFilter(logging.Filter):
    """Drop one-time link tokens before uvicorn writes the access line."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple):
            record.args = tuple(
                _TOKEN_QUERY.sub(r"\1redacted", item) if isinstance(item, str) else item
                for item in record.args
            )
        elif isinstance(record.args, dict):
            record.args = {
                key: _TOKEN_QUERY.sub(r"\1redacted", value) if isinstance(value, str) else value
                for key, value in record.args.items()
            }
        if isinstance(record.msg, str) and "token=" in record.msg:
            record.msg = _TOKEN_QUERY.sub(r"\1redacted", record.msg)
        return True


_redact_tokens = _RedactTokenFilter()
for _logger_name in ("uvicorn.access", "uvicorn", "uvicorn.error"):
    logging.getLogger(_logger_name).addFilter(_redact_tokens)





app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)
app.include_router(auth_router)
app.include_router(booking_router)
app.include_router(admin_router)
app.include_router(records_router)
app.include_router(schedule_router)
