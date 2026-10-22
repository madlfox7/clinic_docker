import base64
import json

import httpx


class CsrfClient(httpx.Client):
    """httpx client that sends the session CSRF token with every POST."""

    def csrf_token(self) -> str:
        token = _token_from_cookie(self.cookies.get("session"))
        if not token:
            super().request("GET", "/")
            token = _token_from_cookie(self.cookies.get("session"))
        return token or ""

    def request(self, method, url, *args, csrf=True, **kwargs):
        if csrf and method.upper() == "POST":
            data = kwargs.get("data")
            if isinstance(data, dict) and "csrf_token" not in data:
                kwargs["data"] = {**data, "csrf_token": self.csrf_token()}
            elif data is None and "files" not in kwargs:
                headers = dict(kwargs.get("headers") or {})
                headers.setdefault("X-CSRF-Token", self.csrf_token())
                kwargs["headers"] = headers
        return super().request(method, url, *args, **kwargs)

    def post(self, url, *args, csrf=True, **kwargs):
        return self.request("POST", url, *args, csrf=csrf, **kwargs)


def _token_from_cookie(value):
    if not value:
        return None
    payload = value.split(".", 1)[0]
    try:
        data = json.loads(base64.b64decode(payload + "=" * (-len(payload) % 4)))
    except (ValueError, json.JSONDecodeError):
        return None
    return data.get("csrf_token") if isinstance(data, dict) else None
