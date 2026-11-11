"""api is reachable only through the proxy, and only the proxy's X-Real-IP is trusted."""
import json
import os
import subprocess
import uuid
from pathlib import Path

import httpx
import pytest

from tests.csrf_client import CsrfClient
from tests.test_rls_boundary import compose_exec, compose_exec_run

ROOT = Path(__file__).resolve().parents[1]
BASE = os.environ.get("CLINIC_TEST_BASE", "http://localhost:8080")
MAILPIT = os.environ.get("CLINIC_MAILPIT", "http://127.0.0.1:8025")
SPOOF = "203.0.113.7"


def _config(env=None) -> dict:
    full_env = {**os.environ, **(env or {})}
    completed = subprocess.run(
        ["docker", "compose", "-f", "docker-compose.yml", "config", "--format", "json"],
        cwd=ROOT, capture_output=True, text=True, env=full_env,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def _psql(sql: str) -> list[str]:
    out = compose_exec("db", ["psql", "-X", "-U", "clinic", "-d", "clinic", "-At", "-c", sql])
    return [line for line in out.splitlines() if line.strip()]


def _proxy_publications(config: dict) -> list[dict]:
    return [p for p in config["services"]["proxy"].get("ports", []) if int(p["target"]) == 8080]


def test_compose_networks_and_bind():
    env = {"CLINIC_PROXY_BIND": "", "CLINIC_PROXY_PORT": ""}
    config = _config({k: v for k, v in env.items()})
    services = config["services"]
    assert set(services["api"]["networks"]) == {"app", "backend", "mail"}
    assert set(services["mailpit"]["networks"]) == {"mail"}
    assert set(services["proxy"]["networks"]) == {"frontend", "app"}
    assert set(services["db"]["networks"]) == {"backend"}
    assert config["networks"]["app"].get("internal") is True
    assert config["networks"]["backend"].get("internal") is True
    assert not config["networks"]["frontend"].get("internal")
    assert not config["networks"]["mail"].get("internal")
    default = _proxy_publications(config)
    assert len(default) == 1 and default[0]["host_ip"] == "0.0.0.0" and default[0]["published"] == "8080"
    narrowed = _proxy_publications(_config({"CLINIC_PROXY_BIND": "127.0.0.1", "CLINIC_PROXY_PORT": "8083"}))
    assert len(narrowed) == 1 and narrowed[0]["host_ip"] == "127.0.0.1" and narrowed[0]["published"] == "8083"


def test_running_stack_publishes_proxy_once():
    completed = subprocess.run(["docker", "compose", "config", "--format", "json"],
                               cwd=ROOT, capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    assert len(_proxy_publications(json.loads(completed.stdout))) == 1


def test_site_through_proxy_is_not_forbidden():
    for path in ("/", "/login", "/doctors", "/static/app.css"):
        response = httpx.get(BASE + path, timeout=10.0)
        assert response.status_code == 200, path


def test_spoofed_forwarding_headers_do_not_change_source():
    email = f"spoof-{uuid.uuid4().hex}@example.com"
    headers = {"X-Real-IP": SPOOF, "X-Forwarded-For": SPOOF, "Forwarded": f"for={SPOOF}"}
    with CsrfClient(base_url=BASE, timeout=10.0) as c:
        mark = int(_psql("SELECT coalesce(max(id), 0) FROM audit_events")[0])
        response = c.post("/login", data={"email": email, "password": "Wrong-Password-1"}, headers=headers)
        assert response.status_code == 401
    sources = _psql(
        f"SELECT source FROM audit_events WHERE id > {mark} AND action = 'auth.login.failure'"
    )
    assert len(sources) == 1 and sources[0] and sources[0] != SPOOF, sources
    _psql(f"DELETE FROM login_attempts WHERE email_fingerprint = public.digest('{email}', 'sha256')")


def test_rotating_spoofed_ip_does_not_bypass_rate_limit():
    email = f"spoof-limit-{uuid.uuid4().hex}@example.com"
    codes = []
    with CsrfClient(base_url=BASE, timeout=10.0) as c:
        for index in range(6):
            fake = f"198.51.100.{index + 1}"
            codes.append(c.post(
                "/login", data={"email": email, "password": "Wrong-Password-1"},
                headers={"X-Real-IP": fake, "X-Forwarded-For": fake},
            ).status_code)
    assert codes == [401] * 5 + [429], codes
    _psql(f"DELETE FROM login_attempts WHERE email_fingerprint = public.digest('{email}', 'sha256')")


def test_neighbour_container_cannot_call_api_directly():
    probe = compose_exec_run("mailpit", ["sh", "-c", "command -v wget"])
    if probe.returncode != 0:
        pytest.skip("no wget in the mailpit image: check http://api:8000 by hand")
    direct = compose_exec_run(
        "mailpit",
        ["wget", "-q", "-S", "-O-", "-T", "3", "--header", "X-Real-IP: 203.0.113.8", "http://api:8000/login"],
    )
    assert "403 Forbidden" in direct.stderr, direct.stderr
    logs = subprocess.run(["docker", "compose", "logs", "--since", "2m", "api"], cwd=ROOT,
                          capture_output=True, text=True, timeout=30)
    assert "direct api request rejected from" in logs.stdout


def test_mailpit_cannot_reach_proxy_or_db():
    container_ips = set()
    for service in ("proxy", "db"):
        cid = subprocess.run(["docker", "compose", "ps", "-q", service], cwd=ROOT,
                             capture_output=True, text=True).stdout.strip()
        inspect = subprocess.run(
            ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", cid],
            capture_output=True, text=True,
        )
        container_ips.update(inspect.stdout.split())
    assert container_ips
    for name in ("proxy", "db"):
        # Some hosts answer every unknown name (fake-IP DNS); it must never be the container.
        resolved = compose_exec_run("mailpit", ["getent", "hosts", name]).stdout.split()
        assert not container_ips.intersection(resolved), (name, resolved)


def test_loopback_inside_api_is_allowed():
    out = compose_exec("api", [
        "python", "-c",
        "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/login', timeout=5).status)",
    ])
    assert out == "200"


def test_password_reset_mail_still_reaches_mailpit():
    email = "pat2@clinic.local"
    httpx.delete(MAILPIT + "/api/v1/messages", timeout=10.0)
    with CsrfClient(base_url=BASE, timeout=10.0) as c:
        response = c.post("/forgot-password", data={"email": email})
        assert response.status_code in (200, 303)
    messages = httpx.get(MAILPIT + "/api/v1/messages", timeout=10.0).json()["messages"]
    assert any(any(to["Address"] == email for to in m["To"]) for m in messages)
