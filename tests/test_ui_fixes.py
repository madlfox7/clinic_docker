"""Small UI fixes after the Bootstrap redesign."""
import os

import httpx

from tests.csrf_client import CsrfClient

BASE = os.environ.get("CLINIC_TEST_BASE", "http://localhost:8080")


def _client(**kwargs):
    return CsrfClient(base_url=BASE, follow_redirects=True, timeout=10.0, **kwargs)


def test_home_has_no_made_up_hours():
    with _client() as c:
        page = c.get("/")
    assert page.status_code == 200
    assert "demo hours" not in page.text
    assert "Hours:" not in page.text
