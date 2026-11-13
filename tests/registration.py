"""Shared registration helpers.

Every POST /register carries a name and a phone, and a new patient signs in
only after the confirmation link from the email (read from Mailpit) is used.
"""
import os
import re

import httpx
import pytest

from tests.csrf_client import CsrfClient
from tests.test_rls_boundary import compose_exec

BASE = os.environ.get("CLINIC_TEST_BASE", "http://localhost:8080")
MAILPIT = os.environ.get("CLINIC_MAILPIT", "http://127.0.0.1:8025")
PATIENT_NAME = "Test Patient"
PATIENT_PHONE = "+374 10 000111"
PATIENT_FIELDS = {"full_name": PATIENT_NAME, "phone": PATIENT_PHONE}
VERIFY_LINK = re.compile(r"/verify-email\?token=([0-9a-f]{64})")


def clear_registration_attempts() -> None:
    """Empty the POST /register rate limit table (superuser psql, tests only).

    The whole suite runs from one source (the Docker gateway behind the proxy)
    and registers far more than 20 accounts in 15 minutes; the limit itself is
    not raised for tests and the app has no bypass.
    """
    compose_exec("db", ["psql", "-X", "-U", "clinic", "-d", "clinic", "-At", "-c",
                        "DELETE FROM registration_attempts"])


@pytest.fixture(autouse=True)
def registration_limit_reset():
    """Import into a test module that posts /register: fresh limit per test."""
    clear_registration_attempts()
    yield


def registration_form(email: str, password: str, confirm_password: str | None = None, **fields) -> dict:
    data = dict(PATIENT_FIELDS)
    data.update(fields)
    data.update(
        {
            "email": email,
            "password": password,
            "confirm_password": password if confirm_password is None else confirm_password,
        }
    )
    return data


def verification_messages(address: str) -> list[dict]:
    """Confirmation emails sent to address, newest first, with their text."""
    response = httpx.get(
        f"{MAILPIT}/api/v1/search",
        params={"query": f'to:"{address}" subject:"Confirm your clinic email"'},
        timeout=5,
    )
    response.raise_for_status()
    found = []
    for summary in response.json().get("messages") or []:
        message_id = summary.get("ID") or summary.get("Id")
        message = httpx.get(f"{MAILPIT}/api/v1/message/{message_id}", timeout=5)
        message.raise_for_status()
        found.append(message.json())
    return found


def latest_verification_token(address: str) -> str:
    for message in verification_messages(address):
        match = VERIFY_LINK.search(message.get("Text") or "")
        if match:
            return match.group(1)
    raise AssertionError(f"no confirmation email for {address}")


def confirm_registration(address: str) -> httpx.Response:
    """Open the newest confirmation link for address and confirm it (POST)."""
    token = latest_verification_token(address)
    with CsrfClient(base_url=BASE, follow_redirects=True, timeout=10.0) as c:
        page = c.get("/verify-email", params={"token": token})
        assert page.status_code == 200, page.status_code
        confirmed = c.post("/verify-email", data={"token": token})
    assert confirmed.url.path == "/login" and "verified=1" in str(confirmed.url), confirmed.url
    return confirmed


def register_patient(c, email: str, password: str, confirm: bool = True, **fields) -> httpx.Response:
    """POST /register with name and phone; confirm the email unless told not to."""
    clear_registration_attempts()
    created = c.post("/register", data=registration_form(email, password, **fields))
    if confirm and "registered=1" in str(created.url):
        confirm_registration(email)
    return created
