import hmac
import secrets

from fastapi import HTTPException, Request

SESSION_KEY = "csrf_token"
FIELD_NAME = "csrf_token"
HEADER_NAME = "x-csrf-token"
CSRF_ERROR_DETAIL = "Invalid CSRF token"


def csrf_token(request: Request) -> str:
    token = request.session.get(SESSION_KEY)
    if not isinstance(token, str) or len(token) < 32:
        token = secrets.token_urlsafe(32)
        request.session[SESSION_KEY] = token
    return token


async def verify_csrf(request: Request) -> None:
    expected = csrf_token(request)
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    supplied = request.headers.get(HEADER_NAME, "")
    if not supplied:
        content_type = request.headers.get("content-type", "")
        if content_type.startswith(
            ("application/x-www-form-urlencoded", "multipart/form-data")
        ):
            form = await request.form()
            value = form.get(FIELD_NAME, "")
            supplied = value if isinstance(value, str) else ""
    if not supplied or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=403, detail=CSRF_ERROR_DETAIL)
