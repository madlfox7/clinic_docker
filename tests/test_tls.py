"""17_tls_audit_chain part A: local CA and server certificate, HTTPS on the
proxy, HTTP redirect and HSTS, Secure cookie, production certificate mode."""
import hashlib
import json
import os
import pathlib
import re
import shutil
import socket
import ssl
import subprocess
import threading
import time

import httpx
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
TLS = ROOT / "secrets" / "tls"
SERVICES_WITHOUT_TLS = ("api", "db", "migrate", "seed", "mailpit", "audit_anchor")


def _compose(*args, timeout=120):
    return subprocess.run(["docker", "compose", *args], cwd=ROOT, capture_output=True, text=True, timeout=timeout)


def _openssl(*args, check=True):
    done = subprocess.run(["openssl", *args], capture_output=True, text=True)
    if check:
        assert done.returncode == 0, done.stderr
    return done


def _sha(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _script_copy(tmp_path: pathlib.Path) -> pathlib.Path:
    """scripts/ in a temporary root: init_secrets.sh cds to its parent, so the
    copy only ever touches tmp_path/secrets, never the stand's own files."""
    shutil.copytree(ROOT / "scripts", tmp_path / "scripts")
    return tmp_path


def _run_init(root: pathlib.Path, **env):
    full = {k: v for k, v in os.environ.items() if not k.startswith("CLINIC_") and k != "PUBLIC_BASE_URL"}
    full.update(env)
    return subprocess.run(["sh", str(root / "scripts" / "init_secrets.sh")], cwd="/", env=full,
                          capture_output=True, text=True, timeout=60)


def _issue_leaf(tmp: pathlib.Path, ca_dir: pathlib.Path, name: str, san: str, days: int) -> tuple[pathlib.Path, pathlib.Path]:
    key, csr, crt, ext = (tmp / f"{name}.key", tmp / f"{name}.csr", tmp / f"{name}.crt", tmp / f"{name}.ext")
    ext.write_text(
        f"subjectAltName = {san}\nbasicConstraints = critical, CA:FALSE\n"
        "keyUsage = critical, digitalSignature\nextendedKeyUsage = serverAuth\n"
        "subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid\n"
    )
    _openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
             "-keyout", str(key), "-out", str(csr), "-subj", f"/CN={name}")
    _openssl("x509", "-req", "-in", str(csr), "-CA", str(ca_dir / "ca.crt"), "-CAkey", str(ca_dir / "ca.key"),
             "-set_serial", "0x" + os.urandom(8).hex(), "-days", str(days), "-extfile", str(ext), "-out", str(crt))
    return key, crt


# --- 1. Local CA and server certificate --------------------------------------

def test_ca_key_is_never_mounted_and_tls_files_reach_only_the_proxy():
    config = json.loads(_compose("config", "--format", "json").stdout)
    assert "ca.key" not in json.dumps(config)
    secrets = config["secrets"]
    assert secrets["tls_cert"]["file"].endswith("secrets/tls/server.crt")
    assert secrets["tls_key"]["file"].endswith("secrets/tls/server.key")
    for name, service in config["services"].items():
        used = {s["source"] if isinstance(s, dict) else s for s in service.get("secrets", [])}
        if name == "proxy":
            assert used == {"tls_cert", "tls_key"}, used
        else:
            assert not used & {"tls_cert", "tls_key"}, name
    listed = _compose("exec", "-T", "proxy", "ls", "/run/secrets")
    assert listed.returncode == 0, listed.stderr
    assert sorted(listed.stdout.split()) == ["tls_cert", "tls_key"]
    running = set(_compose("ps", "--services", "--status", "running").stdout.split())
    for name in SERVICES_WITHOUT_TLS:
        if name not in running:
            continue
        files = _compose("exec", "-T", name, "sh", "-c", "ls /run/secrets 2>/dev/null || true").stdout.split()
        assert "tls_key" not in files and "tls_cert" not in files, name


def test_no_dockerfile_copies_secrets_or_the_ca_key():
    found = subprocess.run(["grep", "-rn", "ca.key", str(ROOT / "docker")], capture_output=True, text=True)
    assert found.stdout == "", found.stdout
    for dockerfile in (ROOT / "docker").rglob("Dockerfile"):
        for line in dockerfile.read_text().splitlines():
            if line.strip().upper().startswith(("COPY", "ADD")):
                assert "secrets" not in line, (dockerfile, line)


def test_server_and_ca_certificates_have_the_strict_extensions():
    leaf = _openssl("x509", "-in", str(TLS / "server.crt"), "-noout", "-text").stdout
    assert "DNS:localhost, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1\n" in leaf
    assert "TLS Web Server Authentication" in leaf
    assert "ASN1 OID: prime256v1" in leaf or "NIST CURVE: P-256" in leaf
    assert "X509v3 Authority Key Identifier" in leaf
    assert "X509v3 Basic Constraints: critical\n                CA:FALSE" in leaf
    days = _openssl("x509", "-in", str(TLS / "server.crt"), "-noout", "-checkend", str(366 * 86400), check=False)
    assert days.returncode != 0, "the server certificate is valid for more than 366 days"
    ca = _openssl("x509", "-in", str(TLS / "ca.crt"), "-noout", "-text").stdout
    assert "X509v3 Name Constraints: critical" in ca
    constraints = ca.split("X509v3 Name Constraints: critical", 1)[1].split("X509v3", 1)[0]
    for name in ("DNS:localhost", "IP:127.0.0.1/255.255.255.255",
                 "IP:0:0:0:0:0:0:0:1/FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"):
        assert name in constraints, constraints
    assert constraints.count("DNS:") + constraints.count("IP:") == 3, constraints
    assert "X509v3 Basic Constraints: critical\n                CA:TRUE, pathlen:0" in ca


def test_name_constraints_refuse_a_leaf_for_another_site(tmp_path):
    # The CA key is only read; the leaf lives in tmp_path and is removed with it.
    _, crt = _issue_leaf(tmp_path, TLS, "example.com", "DNS:example.com", 5)
    checked = _openssl("verify", "-CAfile", str(TLS / "ca.crt"), str(crt), check=False)
    assert checked.returncode != 0 and "permitted subtree violation" in checked.stdout + checked.stderr


def test_init_secrets_is_idempotent_and_never_mounts_ca_files(tmp_path):
    root = _script_copy(tmp_path)
    first = _run_init(root)
    assert first.returncode == 0, first.stderr
    tls = root / "secrets" / "tls"
    before = {p.name: _sha(p) for p in tls.iterdir() if p.is_file()}
    assert set(before) == {"ca.key", "ca.crt", "server.key", "server.crt"}
    second = _run_init(root)
    assert second.returncode == 0, second.stderr
    assert {p.name: _sha(p) for p in tls.iterdir() if p.is_file()} == before
    assert "keep    secrets/tls/server.key, secrets/tls/server.crt" in second.stdout
    assert not list(tls.glob(".tmp.*")), "temporary files left behind"
    for line in first.stdout.splitlines() + second.stdout.splitlines():
        assert "BEGIN" not in line


def test_short_lived_leaf_is_issued_again_in_place(tmp_path):
    root = _script_copy(tmp_path)
    assert _run_init(root).returncode == 0
    tls = root / "secrets" / "tls"
    ca_sha = _sha(tls / "ca.crt")
    key, crt = _issue_leaf(tmp_path, tls, "localhost", "DNS:localhost, IP:127.0.0.1, IP:::1", 10)
    (tls / "server.key").write_bytes(key.read_bytes())
    (tls / "server.crt").write_bytes(crt.read_bytes())
    inode = (tls / "server.crt").stat().st_ino
    old_serial = _openssl("x509", "-in", str(tls / "server.crt"), "-noout", "-serial").stdout
    again = _run_init(root)
    assert again.returncode == 0, again.stderr
    assert "expires within 30 days" in again.stdout
    assert _openssl("x509", "-in", str(tls / "server.crt"), "-noout", "-serial").stdout != old_serial
    assert _sha(tls / "ca.crt") == ca_sha
    assert (tls / "server.crt").stat().st_ino == inode
    backups = list(tls.glob("backup-*"))
    assert len(backups) == 1 and (backups[0].stat().st_mode & 0o777) == 0o700
    for f in backups[0].iterdir():
        assert f.stat().st_mode & 0o777 == 0o600


def test_wrong_key_or_one_ca_file_is_handled(tmp_path):
    root = _script_copy(tmp_path)
    assert _run_init(root).returncode == 0
    tls = root / "secrets" / "tls"
    other_key, _ = _issue_leaf(tmp_path, tls, "localhost", "DNS:localhost", 30)
    (tls / "server.key").write_bytes(other_key.read_bytes())
    fixed = _run_init(root)
    assert fixed.returncode == 0 and "key does not match certificate" in fixed.stdout
    (tls / "ca.key").unlink()
    broken = _run_init(root)
    assert broken.returncode != 0 and "only one of secrets/tls/ca.key and secrets/tls/ca.crt" in broken.stderr
    assert _run_init(root, CLINIC_TLS_MODE="prod").returncode != 0


def test_tls_file_modes_and_proxy_access():
    if shutil.which("getfacl") is None:
        pytest.skip("no getfacl on this host: init_secrets.sh falls back without ACL")
    assert TLS.stat().st_mode & 0o777 == 0o700
    for name in ("server.key", "server.crt"):
        path = TLS / name
        assert path.stat().st_mode & 0o007 == 0, name
        acl = subprocess.run(["getfacl", "-cpn", str(path)], capture_output=True, text=True).stdout.splitlines()
        if path.stat().st_uid == os.getuid():
            assert "user:101:r--" in acl and "other::---" in acl, (name, acl)
    for name in ("ca.key", "ca.crt"):
        path = TLS / name
        assert path.stat().st_mode & 0o777 == 0o600, name
        acl = subprocess.run(["getfacl", "-cpn", str(path)], capture_output=True, text=True).stdout.splitlines()
        assert not [line for line in acl if line.startswith("user:") and line != "user::rw-"], (name, acl)
    # busybox `test -r` looks at mode bits only and ignores the ACL, so read the file.
    read = "cat /run/secrets/tls_key > /dev/null"
    ok = _compose("exec", "-T", "-u", "101", "proxy", "sh", "-c", read)
    assert ok.returncode == 0, ok.stderr
    denied = _compose("exec", "-T", "-u", "12345", "proxy", "sh", "-c", read)
    assert denied.returncode != 0


# --- 2. HTTPS on the proxy -----------------------------------------------------

def _published(target: int) -> int:
    config = json.loads(_compose("config", "--format", "json").stdout)
    ports = [p for p in config["services"]["proxy"]["ports"] if int(p["target"]) == target]
    assert len(ports) == 1, ports
    return int(ports[0]["published"])


def _tls_port() -> int:
    return _published(8443)


def _strict_context() -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=str(TLS / "ca.crt"))
    assert context.verify_flags & ssl.VERIFY_X509_STRICT, "Python default context is not strict"
    return context


def _handshake(host: str, context: ssl.SSLContext, server_hostname=None):
    with socket.create_connection((host, _tls_port()), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=server_hostname or host) as tls:
            return tls.version(), tls.getpeercert()


def _https_get(path: str, host: str = "localhost", context=None) -> tuple[int, dict, bytes]:
    """One HTTP/1.1 request over a verified TLS socket (no redirects followed)."""
    context = context or _strict_context()
    with socket.create_connection((host, _tls_port()), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            tls.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}:{_tls_port()}\r\nConnection: close\r\n\r\n".encode())
            data = b""
            while chunk := tls.recv(65536):
                data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1])
    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers.setdefault(name.strip().lower(), []).append(value.strip())
    return status, headers, body


def test_strict_python_handshake_by_name_and_by_ip():
    context = _strict_context()
    for host in ("localhost", "127.0.0.1"):
        version, cert = _handshake(host, context)
        assert version in ("TLSv1.2", "TLSv1.3"), version
        assert ("DNS", "localhost") in cert["subjectAltName"]


def test_tls_12_and_13_pass_and_tls_11_is_refused_by_the_server():
    for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
        context = _strict_context()
        context.minimum_version = context.maximum_version = version
        assert _handshake("127.0.0.1", context)[0] == version.name.replace("v1_", "v1.")
    old = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    old.load_verify_locations(str(TLS / "ca.crt"))
    try:
        old.set_ciphers("DEFAULT:@SECLEVEL=0")
        old.minimum_version = old.maximum_version = ssl.TLSVersion.TLSv1_1
    except (ValueError, ssl.SSLError) as exc:
        pytest.skip(f"this client cannot speak TLS 1.1 at all: {exc}")
    # Control: the same client talks TLS 1.1 to a local server that allows it.
    if not _client_can_speak_tls11(old):
        pytest.skip("this OpenSSL refuses TLS 1.1 on the client side; the server refusal cannot be shown")
    with pytest.raises(ssl.SSLError) as refused:
        _handshake("127.0.0.1", old)
    text = str(refused.value)
    if "NO_PROTOCOLS_AVAILABLE" in text:
        pytest.skip("the client refused TLS 1.1 itself (NO_PROTOCOLS_AVAILABLE), not the server")
    assert "PROTOCOL_VERSION" in text or "protocol version" in text, text
    conf = (ROOT / "docker" / "proxy" / "nginx.conf").read_text()
    assert "    ssl_protocols TLSv1.2 TLSv1.3;\n" in conf


def _client_can_speak_tls11(client: ssl.SSLContext) -> bool:
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        server.set_ciphers("DEFAULT:@SECLEVEL=0")
        server.minimum_version = ssl.TLSVersion.TLSv1
        server.load_cert_chain(str(TLS / "server.crt"), str(TLS / "server.key"))
    except (ssl.SSLError, OSError, ValueError):
        return False
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    result = {}

    def accept():
        try:
            conn, _ = listener.accept()
            with server.wrap_socket(conn, server_side=True) as tls:
                result["server"] = tls.version()
        except (ssl.SSLError, OSError) as exc:
            result["error"] = exc

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with client.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
                ok = tls.version() == "TLSv1.1"
    except (ssl.SSLError, OSError):
        ok = False
    finally:
        thread.join(5)
        listener.close()
    return ok


def test_certificate_is_checked_against_the_stand_ca_only():
    # The compiled-in system store, not SSL_CERT_FILE (which points at the stand CA).
    paths = ssl.get_default_verify_paths()
    system_only = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    loaded = False
    for cafile, capath in ((paths.openssl_cafile, None), (None, paths.openssl_capath)):
        if (cafile and os.path.isfile(cafile)) or (capath and os.path.isdir(capath)):
            system_only.load_verify_locations(cafile=cafile, capath=capath)
            loaded = True
    assert loaded, paths
    with pytest.raises(ssl.SSLCertVerificationError):
        _handshake("localhost", system_only)
    status, _, _ = _https_get("/login")
    assert status == 200


def test_app_redirects_stay_on_https():
    status, headers, _ = _https_get("/doctors/")
    assert status in (307, 308), status
    location = headers["location"][0]
    assert not location.startswith("http://"), location


def test_tls_server_config_statics():
    conf = (ROOT / "docker" / "proxy" / "nginx.conf").read_text()
    tls_server = conf.split("listen 8443 ssl;", 1)[1]
    for needed in ("ssl_session_tickets off;", "ssl_prefer_server_ciphers off;",
                   "ssl_session_cache shared:clinic_tls:10m;", "http2 on;",
                   "ssl_certificate     /run/secrets/tls_cert;", "ssl_certificate_key /run/secrets/tls_key;",
                   "include /etc/nginx/clinic/security_headers.conf;",
                   "include /etc/nginx/clinic/clinic_locations.conf;"):
        assert needed in tls_server, needed
    http_server = conf.split("listen 8443 ssl;", 1)[0].rsplit("server {", 1)[0].split("server {", 1)[1]
    assert "proxy_pass" not in http_server and "hsts.conf" not in http_server
    assert "include /tmp/nginx/clinic/hsts.conf;" in tls_server
    everything = conf + (ROOT / "docker" / "proxy" / "clinic_locations.conf").read_text()
    assert "ssl_stapling" not in everything and "limit_req" not in everything
    ciphers = re.search(r"ssl_ciphers ([^;]+);", tls_server).group(1).split(":")
    assert ciphers and all(c.startswith("ECDHE-") and ("GCM" in c or "CHACHA20" in c) for c in ciphers), ciphers
    assert _compose("run", "--rm", "--no-deps", "-T", "proxy", "nginx", "-t").returncode == 0


# --- 4. Tests verify certificates ----------------------------------------------

def test_no_test_or_experiment_disables_certificate_checks():
    forbidden = re.compile(r"verify\s*=\s*False|CERT_NONE|check_hostname\s*=\s*False|_create_unverified_context")
    me = pathlib.Path(__file__).resolve()
    hits = []
    for top in ("tests", "experiments"):
        for path in (ROOT / top).rglob("*.py"):
            if path.resolve() == me or ".venv" in path.parts:
                continue
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if forbidden.search(line):
                    hits.append(f"{path.relative_to(ROOT)}:{number}")
    assert not hits, hits


def test_default_test_base_is_https():
    for path in [*(ROOT / "tests").glob("*.py"), ROOT / "experiments" / "concurrent_book.py"]:
        text = path.read_text(encoding="utf-8")
        assert 'CLINIC_TEST_BASE", ' + '"http://' not in text, path
    assert 'CLINIC_TEST_BASE:-https://localhost:8450' in (ROOT / "tests" / "run_tests.sh").read_text()
    makefile = (ROOT / "Makefile").read_text()
    assert "TEST_BASE ?= https://localhost:8450" in makefile and "SSL_CERT_FILE=$(TEST_CA)" in makefile


# --- 2.3-2.5 HTTP redirect and HSTS ---------------------------------------------

def _proxy_env() -> dict:
    config = json.loads(_compose("config", "--format", "json").stdout)
    return config["services"]["proxy"]["environment"]


def _origin() -> str:
    return _proxy_env()["PUBLIC_BASE_URL"]


def _hsts() -> str:
    return f"max-age={_proxy_env()['CLINIC_HSTS_MAX_AGE']}"


def _http(method: str, path: str, **kwargs) -> httpx.Response:
    with httpx.Client(base_url=f"http://127.0.0.1:{_published(8080)}", follow_redirects=False, timeout=10) as c:
        return c.request(method, path, **kwargs)


def _https_client(**kwargs) -> httpx.Client:
    return httpx.Client(base_url=f"https://localhost:{_tls_port()}", follow_redirects=False,
                        verify=_strict_context(), timeout=10, **kwargs)


def test_plain_http_only_redirects_to_the_https_origin_with_308():
    origin = _origin()
    assert origin.startswith("https://")
    for method, path, kwargs in (("GET", "/login", {}),
                                 ("POST", "/login", {"data": {"email": "a@b.c", "password": "x"}}),
                                 ("GET", "/doctors?x=1", {}), ("GET", "/static/app.css", {})):
        response = _http(method, path, **kwargs)
        assert response.status_code == 308, (method, path, response.status_code)
        assert response.headers["location"] == origin + path
        assert "set-cookie" not in response.headers
        assert "strict-transport-security" not in response.headers
        assert "csrf" not in response.text.lower() and "<form" not in response.text.lower()


def test_plain_http_redirect_ignores_the_client_host_header():
    response = _http("GET", "/login", headers={"Host": "evil.example"})
    assert response.status_code == 308
    assert response.headers["location"] == _origin() + "/login"


def test_hsts_once_on_every_https_answer():
    expected = [_hsts()]
    with _https_client() as c:
        answers = [
            ("/", c.get("/")),
            ("/login", c.get("/login")),
            ("/static/app.css", c.get("/static/app.css")),
            ("/no-such-page", c.get("/no-such-page")),
            ("/me", c.get("/me")),
        ]
        page = c.get("/login")
        token = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
        data = {"email": "nobody@example.invalid", "password": "wrong-password"}
        if token:
            data["csrf_token"] = token.group(1)
        answers.append(("POST /login", c.post("/login", data=data)))
    statuses = {where: r.status_code for where, r in answers}
    assert statuses["/no-such-page"] == 404 and statuses["/me"] == 303, statuses
    assert statuses["POST /login"] in (400, 401, 403), statuses
    for where, response in answers:
        values = response.headers.get_list("strict-transport-security")
        assert values == expected, (where, values)
        assert "includesubdomains" not in values[0].lower() and "preload" not in values[0].lower()


def _wait_https_ready(seconds: int = 120) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            with _https_client() as c:
                if c.get("/login").status_code == 200:
                    return
        except httpx.HTTPError:
            pass
        time.sleep(1)
    raise AssertionError("the stand did not come back after api start")


def test_hsts_and_clinic_page_when_api_is_down():
    stopped = _compose("stop", "api")
    assert stopped.returncode == 0, stopped.stderr
    try:
        # A stopped container's address may not answer at all: nginx then
        # waits proxy_connect_timeout (60 s) and answers 504.
        with _https_client() as c:
            response = c.get("/login", timeout=100)
        assert response.status_code in (502, 504), response.status_code
        assert "The clinic service is temporarily unavailable." in response.text
        assert response.headers.get_list("strict-transport-security") == [_hsts()]
        assert "content-security-policy" in response.headers
        assert "no-store" in response.headers.get("cache-control", "")
    finally:
        started = _compose("start", "api")
        assert started.returncode == 0, started.stderr
        _wait_https_ready()


def _proxy_script(**env) -> subprocess.CompletedProcess:
    args = []
    for name, value in env.items():
        args += ["-e", f"{name}={value}"]
    return _compose("run", "--rm", "--no-deps", "-T", *args, "proxy", "nginx", "-t", timeout=180)


@pytest.mark.parametrize("env", [
    {"CLINIC_HSTS_MAX_AGE": "abc"},
    {"CLINIC_HSTS_MAX_AGE": "-1"},
    {"CLINIC_HSTS_MAX_AGE": "1e3"},
    {"CLINIC_HSTS_MAX_AGE": "3600;evil"},
    {"CLINIC_HSTS_MAX_AGE": "63072001"},
    {"PUBLIC_BASE_URL": "http://localhost:8450"},
    {"PUBLIC_BASE_URL": "https://localhost:8450/path"},
    {"PUBLIC_BASE_URL": "https://user@localhost"},
    {"PUBLIC_BASE_URL": "https://localhost:8450?x=1"},
    {"PUBLIC_BASE_URL": "https://local host"},
    {"PUBLIC_BASE_URL": "https://localhost:8450;return 200"},
    {"CLINIC_TLS_MODE": "prod"},
], ids=lambda env: "-".join(f"{k}={v}" for k, v in env.items()))
def test_proxy_refuses_to_start_with_a_bad_value(env):
    done = _proxy_script(**env)
    assert done.returncode != 0
    assert "15-clinic-tls.sh:" in done.stdout + done.stderr


def test_proxy_config_is_valid_with_good_values():
    for env in ({}, {"CLINIC_HSTS_MAX_AGE": "31536000", "PUBLIC_BASE_URL": "https://clinic.example.org"},
                {"PUBLIC_BASE_URL": "https://127.0.0.1:8450"}, {"PUBLIC_BASE_URL": "https://[::1]:8450"}):
        done = _proxy_script(**env)
        assert done.returncode == 0, (env, done.stderr[-2000:])
        assert "syntax is ok" in done.stderr, done.stderr[-2000:]


# --- 3. Secure cookie and one PUBLIC_BASE_URL ------------------------------------

MAILPIT = os.environ.get("CLINIC_MAILPIT", "http://127.0.0.1:8025")


def _api_env() -> dict:
    config = json.loads(_compose("config", "--format", "json").stdout)
    return config["services"]["api"]["environment"]


def test_api_and_proxy_share_one_default_origin_and_secure_cookie_default():
    env = {k: v for k, v in os.environ.items() if k != "PUBLIC_BASE_URL" and k != "SESSION_HTTPS_ONLY"}
    done = subprocess.run(["docker", "compose", "-f", "docker-compose.yml", "--env-file", "/dev/null",
                           "config", "--format", "json"], cwd=ROOT, capture_output=True, text=True, env=env)
    assert done.returncode == 0, done.stderr
    services = json.loads(done.stdout)["services"]
    assert services["api"]["environment"]["PUBLIC_BASE_URL"] == "https://localhost:8450"
    assert services["proxy"]["environment"]["PUBLIC_BASE_URL"] == "https://localhost:8450"
    assert services["api"]["environment"]["SESSION_HTTPS_ONLY"] == "true"
    example = (ROOT / ".env.example").read_text()
    assert "\nPUBLIC_BASE_URL=https://localhost:8450\n" in example
    assert "\nSESSION_HTTPS_ONLY=true\n" in example


def _api_run(code: str, **env) -> subprocess.CompletedProcess:
    args = []
    for name, value in env.items():
        args += ["-e", f"{name}={value}"]
    return _compose("run", "--rm", "--no-deps", "-T", *args, "api", "python", "-c", code, timeout=180)


@pytest.mark.parametrize("env", [
    {"SESSION_HTTPS_ONLY": "true", "PUBLIC_BASE_URL": "http://localhost:8450"},
    {"PUBLIC_BASE_URL": "https://localhost:8450/path"},
    {"PUBLIC_BASE_URL": "https://localhost:8450?x"},
    {"PUBLIC_BASE_URL": "https://a@b"},
    {"PUBLIC_BASE_URL": "https://localhost:8450#top"},
    {"PUBLIC_BASE_URL": "https://localhost:99999"},
    {"PUBLIC_BASE_URL": "https://local host"},
    {"PUBLIC_BASE_URL": "https://localhost:8450\r\nBcc: x@y"},
    {"PUBLIC_BASE_URL": "ftp://localhost"},
], ids=["http", "path", "query", "userinfo", "fragment", "port", "space", "crlf", "scheme"])
def test_bad_public_base_url_stops_the_api(env):
    done = _api_run("import main", **env)
    assert done.returncode != 0, env
    assert "RuntimeError" in done.stderr and "PUBLIC_BASE_URL" in done.stderr, done.stderr[-800:]


def test_public_base_url_defaults_and_http_only_without_secure_cookie():
    out = _api_run("import os; os.environ.pop('SESSION_HTTPS_ONLY', None); os.environ.pop('PUBLIC_BASE_URL', None);"
                   " import session_config, public_url;"
                   " print(session_config.HTTPS_ONLY, public_url.public_base_url())")
    assert out.returncode == 0, out.stderr[-800:]
    assert out.stdout.split() == ["True", "https://localhost:8450"]
    out = _api_run("import public_url; print(public_url.public_base_url())",
                   SESSION_HTTPS_ONLY="false", PUBLIC_BASE_URL="http://127.0.0.1:8000/")
    assert out.returncode == 0, out.stderr[-800:]
    assert out.stdout.strip() == "http://127.0.0.1:8000"


def test_public_base_url_has_one_source_in_the_app():
    hits = []
    for path in (ROOT / "app").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "http://localhost:8080" in text:
            hits.append(f"{path.name}: literal")
        if "PUBLIC_BASE_URL" in text and "environ" in text and path.name != "public_url.py":
            for line in text.splitlines():
                if "PUBLIC_BASE_URL" in line and "environ" in line:
                    hits.append(f"{path.name}: {line.strip()}")
    assert not hits, hits


def _mail_text(address: str, subject: str) -> str:
    for _ in range(20):
        found = httpx.get(f"{MAILPIT}/api/v1/search", params={"query": f'to:"{address}" subject:"{subject}"'}, timeout=5)
        found.raise_for_status()
        messages = found.json().get("messages") or []
        if messages:
            message_id = messages[0].get("ID") or messages[0].get("Id")
            return httpx.get(f"{MAILPIT}/api/v1/message/{message_id}", timeout=5).json().get("Text") or ""
        time.sleep(0.5)
    raise AssertionError(f"no mail '{subject}' for {address}")


def test_mail_links_are_https_on_the_public_origin_and_open():
    from tests.csrf_client import CsrfClient
    from tests.registration import clear_registration_attempts, registration_form
    from tests.test_polish import _drop_user

    origin = _api_env()["PUBLIC_BASE_URL"].rstrip("/")
    assert origin.startswith("https://")
    address = f"tls-links-{os.urandom(5).hex()}@example.com"
    clear_registration_attempts()
    try:
        with CsrfClient(base_url=origin, follow_redirects=True, timeout=10.0) as c:
            c.get("/register")
            created = c.post("/register", data=registration_form(address, "Tls-Links-Check-2026!"))
            assert created.status_code == 200, created.status_code
        verify = re.search(re.escape(origin) + r"/verify-email\?token=[0-9a-f]{64}",
                           _mail_text(address, "Confirm your clinic email"))
        assert verify, "verification link is not on the public https origin"
        with httpx.Client(follow_redirects=False, timeout=10) as plain:
            assert plain.get(verify.group(0)).status_code == 200
        with CsrfClient(base_url=origin, follow_redirects=True, timeout=10.0) as c:
            c.get("/forgot-password")
            assert c.post("/forgot-password", data={"email": address}).status_code == 200
        reset = re.search(re.escape(origin) + r"/reset-password\?token=[0-9a-f]{64}",
                          _mail_text(address, "Reset your clinic password"))
        assert reset, "reset link is not on the public https origin"
        with httpx.Client(follow_redirects=False, timeout=10) as plain:
            assert plain.get(reset.group(0)).status_code == 200
    finally:
        _drop_user(address)
        clear_registration_attempts()


def _init_env(**env) -> dict:
    base = {"PUBLIC_BASE_URL": "", "CLINIC_PROXY_PORT": "", "CLINIC_PROXY_TLS_PORT": "", "SESSION_HTTPS_ONLY": ""}
    base.update(env)
    return base


@pytest.mark.parametrize("env, needle", [
    ({"CLINIC_PROXY_PORT": "8082"}, "CLINIC_PROXY_TLS_PORT is empty"),
    ({"CLINIC_PROXY_PORT": "8082", "CLINIC_PROXY_TLS_PORT": "8452", "PUBLIC_BASE_URL": "https://localhost:8450"},
     "point to port 8450"),
    ({"PUBLIC_BASE_URL": "https://localhost"}, "point to port 443"),
    ({"PUBLIC_BASE_URL": "http://localhost:8450"}, "must start with https://"),
], ids=["tls-port-missing", "port-mismatch", "no-port", "http"])
def test_init_secrets_refuses_mismatched_ports_in_local_mode(tmp_path, env, needle):
    root = _script_copy(tmp_path)
    done = _run_init(root, **_init_env(**env))
    assert done.returncode != 0, done.stdout
    assert needle in done.stderr, done.stderr
    assert not (root / "secrets" / "tls").exists() or not any((root / "secrets" / "tls").iterdir())


def test_init_secrets_accepts_matching_ports(tmp_path):
    root = _script_copy(tmp_path)
    done = _run_init(root, **_init_env(CLINIC_PROXY_PORT="8082", CLINIC_PROXY_TLS_PORT="8452",
                                       PUBLIC_BASE_URL="https://localhost:8452/"))
    assert done.returncode == 0, done.stderr
