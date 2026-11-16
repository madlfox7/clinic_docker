"""make ngrok / make ngrok-off (scripts/ngrok_demo.sh) without Docker or a
real tunnel: a fake ngrok and a fake COMPOSE record what they were given.
The real ngrok is kept out of PATH (every directory that has one is dropped)."""
import json
import os
import pathlib
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOMAIN = "outspoken-wiry-fabric.ngrok-free.dev"
FAKE_TOKEN = "fake-token-must-never-be-printed-123"
MAKE = shutil.which("make")

FAKE_COMPOSE = r'''#!/usr/bin/env python3
"""Fake `docker compose`: logs each call with the values Compose would use
(environment before .env, as in Compose interpolation)."""
import json, os, pathlib, sys
dotenv = {}
if pathlib.Path(".env").exists():
    for line in pathlib.Path(".env").read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            dotenv[k.strip()] = v.strip()
def value(name, default=""):
    # FAKE_SUDO: like `sudo docker compose`, the environment does not reach Compose
    if name in os.environ and not os.environ.get("FAKE_SUDO"):
        return os.environ[name]
    return dotenv.get(name, default)
args = sys.argv[1:]
with open(os.environ["FAKE_CALLS"], "a") as log:
    log.write(json.dumps({"args": args,
                          "PUBLIC_BASE_URL": value("PUBLIC_BASE_URL", "https://localhost:8450"),
                          "CLINIC_PUBLIC_TUNNEL": value("CLINIC_PUBLIC_TUNNEL", "0")}) + "\n")
if args[:1] == ["exec"] and "printenv" in args:
    name = args[-1]
    defaults = {"PUBLIC_BASE_URL": "https://localhost:8450", "CLINIC_PUBLIC_TUNNEL": "0"}
    service = args[args.index("printenv") - 1]
    if service in os.environ.get("FAKE_STALE_SERVICES", "").split(","):
        name_value = dotenv.get(name, defaults.get(name, ""))
    else:
        name_value = value(name, defaults.get(name, ""))
    print(name_value)
    sys.exit(0)
if args[:1] == ["config"]:
    bind = value("CLINIC_PROXY_BIND", "0.0.0.0")
    print(json.dumps({"services": {"proxy": {"ports": [
        {"target": 8080, "published": value("CLINIC_PROXY_PORT", "8080"), "host_ip": bind},
        {"target": 8443, "published": value("CLINIC_PROXY_TLS_PORT", "8450"), "host_ip": bind}]}}}))
'''

FAKE_NGROK = r'''#!/bin/sh
case "$1 $2" in
  "config check")
    [ -z "${FAKE_NGROK_CHECK_FAILS:-}" ] || { echo "ERROR: bad config" >&2; exit 1; }
    echo "Valid configuration file at $FAKE_NGROK_CONFIG"; exit 0 ;;
esac
[ "$1" = http ] || exit 64
for a in "$@"; do printf '%s\n' "$a"; done > "$FAKE_NGROK_ARGS"
exit "${FAKE_NGROK_RC:-0}"
'''


def _write_exe(path: pathlib.Path, text: str) -> pathlib.Path:
    path.write_text(text)
    path.chmod(0o755)
    return path


def _path_without_ngrok(extra: pathlib.Path) -> str:
    keep = [str(extra)]
    for part in os.environ.get("PATH", "").split(os.pathsep):
        if part and not os.path.exists(os.path.join(part, "ngrok")):
            keep.append(part)
    return os.pathsep.join(keep)


class Demo:
    def __init__(self, tmp_path: pathlib.Path, ngrok: bool = True, authtoken: bool = True):
        self.tmp = tmp_path
        self.root = tmp_path / "repo"
        shutil.copytree(ROOT / "scripts", self.root / "scripts")
        for name in ("Makefile", ".env.example"):
            shutil.copy2(ROOT / name, self.root / name)
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        if ngrok:
            _write_exe(self.bin / "ngrok", FAKE_NGROK)
        self.compose = _write_exe(tmp_path / "fake-compose", FAKE_COMPOSE)
        self.calls = tmp_path / "compose.calls"
        self.ngrok_args = tmp_path / "ngrok.args"
        self.ngrok_config = tmp_path / "ngrok.yml"
        self.ngrok_config.write_text('version: "3"\nagent:\n'
                                     + (f"  authtoken: {FAKE_TOKEN}\n" if authtoken else ""))
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(("CLINIC_", "NGROK_")) and k != "PUBLIC_BASE_URL"}
        self.env.update(PATH=_path_without_ngrok(self.bin), FAKE_CALLS=str(self.calls),
                        FAKE_NGROK_ARGS=str(self.ngrok_args), FAKE_NGROK_CONFIG=str(self.ngrok_config))
        found = shutil.which("ngrok", path=self.env["PATH"])
        assert found in (None, str(self.bin / "ngrok")), found

    def dotenv(self, **values: str) -> None:
        """.env = .env.example with these lines replaced or added."""
        lines = (self.root / ".env.example").read_text().splitlines()
        for name, value in values.items():
            lines = [line for line in lines if not line.startswith(f"{name}=")]
            if value is not None:
                lines.append(f"{name}={value}")
        (self.root / ".env").write_text("\n".join(lines) + "\n")

    def make(self, target: str, **env: str) -> subprocess.CompletedProcess:
        done = subprocess.run([MAKE, "-s", target, f"COMPOSE={self.compose}"], cwd=self.root,
                              env={**self.env, **env}, capture_output=True, text=True, timeout=120)
        assert FAKE_TOKEN not in done.stdout + done.stderr
        return done

    def compose_calls(self) -> list[dict]:
        if not self.calls.exists():
            return []
        return [json.loads(line) for line in self.calls.read_text().splitlines()]

    def ups(self) -> list[dict]:
        return [c for c in self.compose_calls() if c["args"][:1] == ["up"]]


STAND = {"CLINIC_PROXY_BIND": "127.0.0.1", "CLINIC_PROXY_PORT": "8082",
         "CLINIC_PROXY_TLS_PORT": "8452", "PUBLIC_BASE_URL": "https://localhost:8452"}


def test_env_example_names_the_users_ngrok_domain():
    assert f"NGROK_DOMAIN={DOMAIN}\n" in (ROOT / ".env.example").read_text()
    assert "authtoken:" not in (ROOT / ".env.example").read_text()


def test_ngrok_free_dev_domain_passes_all_three_parsers(tmp_path):
    url = f"https://{DOMAIN}"
    env = {k: v for k, v in os.environ.items() if not k.startswith("CLINIC_") and k != "PUBLIC_BASE_URL"}
    # tls_lib (init_secrets.sh in tunnel mode)
    root = tmp_path / "repo"
    shutil.copytree(ROOT / "scripts", root / "scripts")
    done = subprocess.run(["sh", str(root / "scripts" / "init_secrets.sh")], cwd="/", capture_output=True, text=True,
                          env={**env, "PUBLIC_BASE_URL": url, "CLINIC_PUBLIC_TUNNEL": "1",
                               "CLINIC_PROXY_PORT": "8082", "CLINIC_PROXY_TLS_PORT": "8452"}, timeout=60)
    assert done.returncode == 0 and f"PUBLIC_BASE_URL {url} is a tunnel" in done.stdout, done.stderr
    # docker/proxy/15-clinic-tls.sh, run here with its output directory moved
    out = tmp_path / "nginx"
    script = tmp_path / "15-clinic-tls.sh"
    text = (ROOT / "docker" / "proxy" / "15-clinic-tls.sh").read_text()
    assert "\nOUT=/tmp/nginx/clinic\n" in text
    script.write_text(text.replace("\nOUT=/tmp/nginx/clinic\n", f"\nOUT={out}\n"))
    proxy = subprocess.run(["sh", str(script)], capture_output=True, text=True, timeout=30,
                           env={**env, "PUBLIC_BASE_URL": url, "CLINIC_PUBLIC_TUNNEL": "1"})
    assert proxy.returncode == 0, proxy.stderr
    assert (out / "redirect.conf").read_text() == f"return 308 {url}$request_uri;\n"
    # app/public_url.py
    api = subprocess.run(["python3", "-c", "import public_url; print(public_url.public_base_url())"],
                         cwd=ROOT / "app", capture_output=True, text=True, timeout=30,
                         env={**env, "PUBLIC_BASE_URL": url, "SESSION_HTTPS_ONLY": "true"})
    assert api.returncode == 0 and api.stdout.strip() == url, api.stderr


def test_make_ngrok_starts_the_stand_with_the_tunnel_and_runs_ngrok_to_the_https_port(tmp_path):
    demo = Demo(tmp_path)
    demo.dotenv(**STAND)
    before = (demo.root / ".env").read_bytes()
    done = demo.make("ngrok")
    assert done.returncode == 0, done.stderr
    assert demo.ngrok_args.read_text().splitlines() == [
        "http", "https://localhost:8452", "--url", f"https://{DOMAIN}",
        "--upstream-tls-verify", "--upstream-tls-verify-cas", str(demo.root / "secrets" / "tls" / "ca.crt")]
    # The environment beat .env for Compose and for init_secrets.sh; .env is untouched.
    ups = demo.ups()
    assert len(ups) == 1
    assert ups[0]["PUBLIC_BASE_URL"] == f"https://{DOMAIN}" and ups[0]["CLINIC_PUBLIC_TUNNEL"] == "1"
    assert "is a tunnel to https://localhost:8452" in done.stdout
    assert (demo.root / ".env").read_bytes() == before
    assert f"Site:   https://{DOMAIN}" in done.stdout and "make ngrok-off" in done.stdout
    assert "Visit Site" in done.stdout and "PUBLIC" in done.stdout


def test_make_ngrok_takes_the_https_port_from_the_stand_settings(tmp_path):
    demo = Demo(tmp_path)
    demo.dotenv(**{**STAND, "CLINIC_PROXY_PORT": "9073", "CLINIC_PROXY_TLS_PORT": "9443",
                   "PUBLIC_BASE_URL": "https://localhost:9443"})
    done = demo.make("ngrok")
    assert done.returncode == 0, done.stderr
    assert demo.ngrok_args.read_text().splitlines()[1] == "https://localhost:9443"
    # Never the HTTP port (it only redirects to PUBLIC_BASE_URL: a loop).
    assert "9073" not in demo.ngrok_args.read_text()


def test_make_ngrok_after_ctrl_c_keeps_the_stand(tmp_path):
    demo = Demo(tmp_path)
    demo.dotenv(**STAND)
    done = demo.make("ngrok", FAKE_NGROK_RC="130")
    assert done.returncode == 0, done.stderr
    assert "tunnel closed" in done.stdout and "make ngrok-off" in done.stdout
    assert not any(c["args"][:1] in (["down"], ["stop"]) for c in demo.compose_calls())


def test_make_ngrok_without_ngrok(tmp_path):
    demo = Demo(tmp_path, ngrok=False)
    demo.dotenv(**STAND)
    done = demo.make("ngrok")
    assert done.returncode != 0 and "ngrok is not installed" in done.stderr, done.stderr
    assert demo.ups() == []


@pytest.mark.parametrize("domain, needle", [
    (None, "NGROK_DOMAIN is not set"),
    ("", "NGROK_DOMAIN is not set"),
    (f"https://{DOMAIN}", "bare domain"),
    (f"{DOMAIN}:443", "bare domain"),
    (f"{DOMAIN}/x", "bare domain"),
    ("Outspoken-Wiry-Fabric.ngrok-free.dev", "lower-case"),
    (f"{DOMAIN}.", "lower-case"),
    ("u@" + DOMAIN, "user info"),
    ("localhost", "full domain name"),
], ids=["missing", "empty", "scheme", "port", "path", "uppercase", "trailing-dot", "userinfo", "single-label"])
def test_make_ngrok_needs_a_valid_domain(tmp_path, domain, needle):
    demo = Demo(tmp_path)
    demo.dotenv(**STAND, NGROK_DOMAIN=domain)
    done = demo.make("ngrok")
    assert done.returncode != 0 and needle in done.stderr, done.stderr
    assert demo.ups() == [] and not demo.ngrok_args.exists()


def test_make_ngrok_refuses_a_tunnel_domain_that_is_an_ip(tmp_path):
    demo = Demo(tmp_path)
    demo.dotenv(**STAND, NGROK_DOMAIN="203.0.113.7")
    done = demo.make("ngrok")
    assert done.returncode != 0 and "not the IP address" in done.stderr, done.stderr
    assert not demo.ngrok_args.exists()


def test_make_ngrok_without_an_authtoken(tmp_path):
    demo = Demo(tmp_path, authtoken=False)
    demo.dotenv(**STAND)
    done = demo.make("ngrok")
    assert done.returncode != 0 and "ngrok has no authtoken" in done.stderr, done.stderr
    assert "ngrok config add-authtoken" in done.stderr
    assert demo.ups() == [] and not demo.ngrok_args.exists()
    broken = demo.make("ngrok", FAKE_NGROK_CHECK_FAILS="1")
    assert broken.returncode != 0 and "ngrok config check failed" in broken.stderr, broken.stderr
    assert demo.ups() == []


def test_make_ngrok_accepts_the_authtoken_from_the_environment_without_printing_it(tmp_path):
    demo = Demo(tmp_path, authtoken=False)
    demo.dotenv(**STAND)
    done = demo.make("ngrok", NGROK_AUTHTOKEN=FAKE_TOKEN)  # Demo.make asserts it is not printed
    assert done.returncode == 0, done.stderr
    assert FAKE_TOKEN not in demo.ngrok_args.read_text()


def test_make_ngrok_refuses_a_proxy_bound_where_localhost_cannot_reach(tmp_path):
    demo = Demo(tmp_path)
    demo.dotenv(**{**STAND, "CLINIC_PROXY_BIND": "192.0.2.10"})
    done = demo.make("ngrok")
    assert done.returncode != 0 and "bound to 192.0.2.10" in done.stderr, done.stderr
    assert demo.ups() == [] and not demo.ngrok_args.exists()


def test_make_ngrok_off_goes_back_to_the_dotenv_address(tmp_path):
    demo = Demo(tmp_path)
    demo.dotenv(**STAND)
    assert demo.make("ngrok").returncode == 0
    # Even with the tunnel values exported in this shell, .env wins again.
    done = demo.make("ngrok-off", PUBLIC_BASE_URL=f"https://{DOMAIN}", CLINIC_PUBLIC_TUNNEL="1")
    assert done.returncode == 0, done.stderr
    last = demo.ups()[-1]
    assert last["PUBLIC_BASE_URL"] == "https://localhost:8452" and last["CLINIC_PUBLIC_TUNNEL"] == "0"
    assert "Site:   https://localhost:8452" in done.stdout
    assert "is a tunnel" not in done.stdout


def test_makefile_ngrok_targets_pass_the_compose_command():
    makefile = (ROOT / "Makefile").read_text()
    assert '\tCOMPOSE="$(COMPOSE)" MAKE="$(MAKE)" PYTHON="$(PYTHON)" ./scripts/ngrok_demo.sh on\n' in makefile
    assert '\tCOMPOSE="$(COMPOSE)" MAKE="$(MAKE)" PYTHON="$(PYTHON)" ./scripts/ngrok_demo.sh off\n' in makefile
    assert "tests/test_ngrok_demo.py" in makefile


def _ngrok_started(demo: "Demo") -> bool:
    return demo.ngrok_args.exists()


def test_sudo_dropping_the_environment_stops_before_ngrok(tmp_path):
    demo = Demo(tmp_path)
    demo.dotenv(NGROK_DOMAIN=DOMAIN, **STAND)
    done = demo.make("ngrok", FAKE_SUDO="1")
    assert done.returncode != 0
    err = done.stderr
    assert "the api container uses PUBLIC_BASE_URL=https://localhost:8452, not https://" + DOMAIN in err
    assert "ngrok not started" in err and "sudo -E" in err and "without sudo" in err
    assert not _ngrok_started(demo)
    assert "Site:" not in done.stdout


@pytest.mark.parametrize("stale", ["proxy", "api"])
def test_one_container_on_the_old_address_stops_before_ngrok(tmp_path, stale):
    demo = Demo(tmp_path)
    demo.dotenv(NGROK_DOMAIN=DOMAIN, **STAND)
    done = demo.make("ngrok", FAKE_STALE_SERVICES=stale)
    assert done.returncode != 0 and f"the {stale} container uses PUBLIC_BASE_URL" in done.stderr
    assert not _ngrok_started(demo)


def test_tunnel_flag_missing_in_the_proxy_stops_before_ngrok(tmp_path):
    demo = Demo(tmp_path)
    # the address reaches Compose through .env, the flag does not (stale proxy)
    demo.dotenv(NGROK_DOMAIN=DOMAIN, **{**STAND, "PUBLIC_BASE_URL": f"https://{DOMAIN}"})
    done = demo.make("ngrok", FAKE_SUDO="1")
    assert done.returncode != 0 and "CLINIC_PUBLIC_TUNNEL=0, not 1" in done.stderr
    assert not _ngrok_started(demo)


def test_matching_address_starts_ngrok_after_the_check(tmp_path):
    demo = Demo(tmp_path)
    demo.dotenv(NGROK_DOMAIN=DOMAIN, **STAND)
    done = demo.make("ngrok")
    assert done.returncode == 0, done.stderr
    assert f"check   api and proxy use PUBLIC_BASE_URL=https://{DOMAIN} (tunnel mode)" in done.stdout
    assert done.stdout.index("check   api and proxy") < done.stdout.index("Site:")
    assert _ngrok_started(demo)
    reads = [c["args"] for c in demo.compose_calls() if c["args"][:1] == ["exec"]]
    assert reads and all(a[-2] == "printenv" and a[-1] in ("PUBLIC_BASE_URL", "CLINIC_PUBLIC_TUNNEL")
                         for a in reads)
