import logging
import re

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from csrf import CSRF_ERROR_DETAIL, verify_csrf
from db import load_session_user, log, templates
from field_crypto import FieldDecryptError, init_keyring
from secret_files import read_secret
from static_assets import STATIC_DIR
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
    raw = read_secret("session_secret")
    if len(raw) < 32 or raw.lower() in _REJECTED_SECRETS:
        raise RuntimeError(
            "session_secret must be a non-default secret of at least 32 characters"
        )
    return raw


SESSION_SECRET = _session_secret()
# Fail at startup when the medical field key is missing, empty or malformed.
init_keyring()

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





app = FastAPI(dependencies=[Depends(verify_csrf)])
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)

_ERROR_TEXT = {
    400: ("Bad request", "The request could not be processed."),
    403: ("Access denied", "Your role does not have access to this page."),
    404: ("Page not found", "The page you requested does not exist."),
    405: ("Method not allowed", "This action is not available for this address."),
    422: ("Invalid input", "Some submitted values are missing or invalid. Please check the form and try again."),
}


def _error_page(request: Request, status_code: int, headers=None, message=None):
    title, default_message = _ERROR_TEXT.get(
        status_code, ("Request failed", "The request could not be completed.")
    )
    role = None
    try:
        user, status = load_session_user(request)
        if status == "ok":
            role = user["role"]
    except Exception:
        role = None
    return templates.TemplateResponse(
        request,
        "error.html",
        {
            "request": request,
            "role": role,
            "title": title,
            "message": message or default_message,
        },
        status_code=status_code,
        headers=headers,
    )


@app.exception_handler(StarletteHTTPException)
async def html_http_error(request: Request, exc: StarletteHTTPException):
    message = None
    if exc.status_code == 403 and exc.detail == CSRF_ERROR_DETAIL:
        message = "Session expired, please refresh the page"
    return _error_page(request, exc.status_code, getattr(exc, "headers", None), message)


@app.exception_handler(FieldDecryptError)
async def medical_record_unreadable(request: Request, exc: FieldDecryptError):
    # Only the reason code and path are logged: never the packet, text or key.
    log.error("medical record could not be decrypted: reason=%s path=%s", exc.reason, request.url.path)
    return _error_page(
        request,
        500,
        message="A medical record could not be decrypted. Please contact the clinic administrator.",
    )


@app.exception_handler(RequestValidationError)
async def html_validation_error(request: Request, exc: RequestValidationError):
    return _error_page(request, 422)


app.include_router(auth_router)
app.include_router(booking_router)
app.include_router(admin_router)
app.include_router(records_router)
app.include_router(schedule_router)
# CSS/JS/SVG only; StaticFiles never lists directories and does not follow symlinks.
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
