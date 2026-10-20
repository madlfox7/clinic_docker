import logging
import os
import smtplib
from email.message import EmailMessage

log = logging.getLogger("clinic.mail")


def _flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes"}


def _connection():
    host = os.environ.get("SMTP_HOST", "").strip()
    if not host:
        raise RuntimeError("SMTP_HOST is not configured")
    port = int(os.environ.get("SMTP_PORT", "587"))
    timeout = float(os.environ.get("SMTP_TIMEOUT", "5"))
    if _flag("SMTP_SSL"):
        return smtplib.SMTP_SSL(host, port, timeout=timeout)
    return smtplib.SMTP(host, port, timeout=timeout)


def _login(smtp) -> None:
    smtp.ehlo()
    if not _flag("SMTP_SSL") and _flag("SMTP_STARTTLS"):
        smtp.starttls()
        smtp.ehlo()
    username = os.environ.get("SMTP_USERNAME", "").strip()
    if username:
        smtp.login(username, os.environ.get("SMTP_PASSWORD", ""))


def smtp_ready() -> bool:
    if not os.environ.get("SMTP_HOST", "").strip():
        return False
    try:
        smtp = _connection()
        try:
            _login(smtp)
            smtp.noop()
        finally:
            smtp.quit()
    except Exception:
        log.exception("SMTP is unavailable")
        return False
    return True


def send_password_reset(recipient: str, token: str) -> None:
    if any(char in recipient for char in "\r\n") or any(char in token for char in "\r\n"):
        raise ValueError("invalid reset message")
    base_url = os.environ.get("PUBLIC_BASE_URL", "http://localhost:8080").strip().rstrip("/")
    if not base_url or any(char in base_url for char in "\r\n"):
        raise ValueError("invalid public base URL")
    message = EmailMessage()
    message["Subject"] = "Reset your clinic password"
    message["From"] = os.environ.get("SMTP_FROM", "noreply@clinic.local").strip()
    message["To"] = recipient
    message.set_content(
        "A password reset was requested for this patient account.\n"
        "The link expires in 15 minutes and works once.\n\n"
        f"{base_url}/reset-password?token={token}\n\n"
        "If you did not request this, you can ignore this message.\n"
    )
    smtp = _connection()
    try:
        _login(smtp)
        smtp.send_message(message)
    finally:
        smtp.quit()
