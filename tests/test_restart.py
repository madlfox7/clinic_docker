"""Check restart order and keep nginx's API upstream static."""
import json
import os
import re
import subprocess
import time
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
BASE = os.environ.get("CLINIC_TEST_BASE", "https://localhost:8450")
PROJECT = os.environ.get("COMPOSE_PROJECT_NAME", "")
PROXY = ROOT / "docker" / "proxy"


def _recipe(target: str) -> str:
    done = subprocess.run(["make", "-n", target, "COMPOSE=docker compose -p stub"], cwd=ROOT,
                          capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    return done.stdout


def test_make_restart_is_stop_then_up_in_dependency_order():
    recipe = _recipe("restart")
    lines = recipe.splitlines()
    assert lines[0] == "docker compose -p stub stop"
    assert "docker compose -p stub restart" not in recipe
    assert "docker compose -p stub up -d --no-recreate --wait" in recipe
    assert "./scripts/init_secrets.sh" in recipe and "--build" not in recipe
    assert "did not come up running/healthy" in recipe
    start = _recipe("start")
    assert "docker compose -p stub up --build -d" in start
    # Reuse startup setup.
    strip = lambda text: [l for l in text.splitlines() if " up " not in l]
    assert [l for l in strip(start)] == [l for l in strip(recipe)
                                         if l.startswith(("cp -n", "./scripts", "fail() {", "if [ -e secrets/tls"))]


def test_nginx_has_no_dynamic_resolver_and_a_static_api_upstream():
    """Avoid request-time DNS; proxy only to the static api:8000 upstream."""
    conf = (PROXY / "nginx.conf").read_text() + (PROXY / "clinic_locations.conf").read_text()
    code = "\n".join(line.split("#", 1)[0] for line in conf.splitlines())
    assert not re.search(r"\bresolver(_timeout)?\b", code)
    passes = re.findall(r"\bproxy_pass\s+([^;]+);", code)
    assert len(passes) >= 4 and set(passes) == {"http://api:8000"}, passes
    assert "$" not in "".join(passes)


# Live disposable-stand tests

def _compose(*args, timeout=300):
    return subprocess.run(["docker", "compose", *args], cwd=ROOT, capture_output=True, text=True, timeout=timeout)


def _login_page_status() -> int:
    try:
        return httpx.get(f"{BASE}/login", timeout=10).status_code
    except httpx.HTTPError:
        return 0


def _wait_200(seconds: int) -> float:
    started = time.time()
    while _login_page_status() != 200:
        assert time.time() - started < seconds, f"/login is not 200 after {seconds} s"
        time.sleep(1)
    return time.time() - started


def _inspect(service: str, fmt: str) -> str:
    ids = _compose("ps", "-a", "-q", service).stdout.split()
    assert ids, service
    return subprocess.run(["docker", "inspect", "-f", fmt, ids[0]], capture_output=True, text=True,
                          timeout=60).stdout.strip()


def _reloads() -> int:
    return _compose("logs", "proxy").stdout.count("signal process started")


@pytest.mark.skipif(PROJECT != "e6", reason="only on a disposable stand -p e6 (restarts it four times)")
def test_live_make_restart_four_times():
    reloads = _reloads()
    for attempt in range(4):
        done = subprocess.run(["make", "restart", "COMPOSE=docker compose"], cwd=ROOT,
                              capture_output=True, text=True, timeout=900)
        assert done.returncode == 0, (attempt, done.stdout[-3000:], done.stderr[-3000:])
        assert _login_page_status() == 200, attempt
        assert _inspect("migrate", "{{.State.ExitCode}}") == "0", attempt
        assert _inspect("audit_prepare", "{{.State.ExitCode}}") == "0", attempt
        assert _inspect("seed", "{{.State.ExitCode}}") == "0", attempt
        assert _inspect("audit_anchor", "{{.State.Health.Status}}") == "healthy", attempt
        verify = subprocess.run(["make", "-s", "audit-verify", "COMPOSE=docker compose"], cwd=ROOT,
                                capture_output=True, text=True, timeout=300)
        assert verify.returncode == 0, (attempt, verify.stdout + verify.stderr)
    assert _reloads() == reloads


@pytest.mark.skipif(PROJECT != "e6", reason="only on a disposable stand -p e6 (tunnel mode, no ngrok)")
def test_live_make_restart_keeps_tunnel_mode():
    """Restart must preserve tunnel settings from the original start."""
    tunnel = "https://demo-tunnel.ngrok-free.dev"
    env = dict(os.environ, CLINIC_PUBLIC_TUNNEL="1", PUBLIC_BASE_URL=tunnel)
    plain = {k: v for k, v in os.environ.items() if k not in ("CLINIC_PUBLIC_TUNNEL", "PUBLIC_BASE_URL")}

    def effective(service: str, name: str) -> str:
        return _compose("exec", "-T", service, "printenv", name).stdout.strip()

    def redirect() -> str:
        port = os.environ.get("CLINIC_TEST_HTTP_PORT", "8086")
        return httpx.get(f"http://localhost:{port}/login", timeout=10).headers.get("location", "")

    try:
        started = subprocess.run(["make", "start", "COMPOSE=docker compose"], cwd=ROOT, env=env,
                                 capture_output=True, text=True, timeout=900)
        assert started.returncode == 0, started.stderr[-3000:]
        _wait_200(120)
        restarted = subprocess.run(["make", "restart", "COMPOSE=docker compose"], cwd=ROOT, env=plain,
                                   capture_output=True, text=True, timeout=900)
        assert restarted.returncode == 0, restarted.stderr[-3000:]
        for service in ("proxy", "api"):
            assert effective(service, "PUBLIC_BASE_URL") == tunnel, service
        assert effective("proxy", "CLINIC_PUBLIC_TUNNEL") == "1"
        assert redirect() == f"{tunnel}/login"
        assert _login_page_status() == 200
    finally:
        back = subprocess.run(["make", "start", "COMPOSE=docker compose"], cwd=ROOT,
                              env=dict(plain, CLINIC_PUBLIC_TUNNEL="0"),
                              capture_output=True, text=True, timeout=900)
        assert back.returncode == 0, back.stderr[-3000:]
    assert effective("proxy", "CLINIC_PUBLIC_TUNNEL") == "0"
    _wait_200(120)
