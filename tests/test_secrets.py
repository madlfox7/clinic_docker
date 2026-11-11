import ast
import json
import os
import pathlib
import shutil
import stat
import subprocess

import pytest

from test_rls_boundary import compose_exec

ROOT = pathlib.Path(__file__).resolve().parents[1]
SECRET_FILES = (
    "postgres_password",
    "clinic_api_password",
    "session_secret",
    "demo_password",
    "field_encryption_key",
)
FIELD_KEY_SECRETS = ("field_encryption_key", "field_encryption_previous_keys")
FORBIDDEN_ENV = (
    "DATABASE_URL",
    "PGPASSWORD",
    "POSTGRES_PASSWORD",
    "CLINIC_API_PASSWORD",
    "SESSION_SECRET",
    "SMTP_PASSWORD",
    "DEMO_PASSWORD",
    "FIELD_ENCRYPTION_KEY",
)
OLD_DEMO_PASSWORD = "password" + "123"
# Lists of rejected weak values may name the old demo password; nothing else may.
DENYLIST_NAMES = {"DEFAULT_REGISTRATION_PASSWORDS", "_REJECTED_SECRETS"}


def _secret_values() -> list[str]:
    values = []
    for name in SECRET_FILES:
        value = (ROOT / "secrets" / name).read_text(encoding="utf-8").strip()
        assert value, f"secrets/{name} is empty"
        values.append(value)
    return values


def test_containers_get_no_secrets_through_env():
    secrets = _secret_values()
    for service in ("api", "db"):
        env = compose_exec(service, ["env"])
        names = {line.split("=", 1)[0] for line in env.splitlines()}
        assert not names & set(FORBIDDEN_ENV), (service, names & set(FORBIDDEN_ENV))
        for value in secrets:
            assert value not in env, f"{service} env contains a secret value"


def test_api_user_reads_secret_files_and_has_no_fallback():
    script = """
import json, os
from secret_files import read_secret
result = {"uid": os.getuid()}
for name in ("clinic_api_password", "session_secret", "smtp_password"):
    read_secret(name)
try:
    read_secret("does_not_exist")
    result["missing"] = "no error"
except RuntimeError:
    result["missing"] = "error"
print(json.dumps(result))
"""
    result = json.loads(compose_exec("api", ["python", "-"], input_text=script))
    assert result["uid"] != 0
    assert result["missing"] == "error"


def _denylist_constants(tree: ast.AST) -> set[int]:
    allowed = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Set):
            if {t.id for t in node.targets if isinstance(t, ast.Name)} & DENYLIST_NAMES:
                allowed.update(id(elt) for elt in node.value.elts)
    return allowed


def test_old_demo_password_is_not_in_application_sources():
    app_dir = ROOT / "app"
    for name in ("db.py", "seed.py"):
        assert OLD_DEMO_PASSWORD not in (app_dir / name).read_text(encoding="utf-8"), name
    for path in sorted(app_dir.rglob("*")):
        if not path.is_file() or path.suffix == ".pyc":
            continue
        text = path.read_text(encoding="utf-8")
        if OLD_DEMO_PASSWORD not in text:
            continue
        assert path.suffix == ".py", f"{path.relative_to(ROOT)} contains the old demo password"
        tree = ast.parse(text)
        allowed = _denylist_constants(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and node.value == OLD_DEMO_PASSWORD:
                assert id(node) in allowed, (
                    f"{path.relative_to(ROOT)}:{node.lineno} uses the old demo password"
                )
    for path in (ROOT / "docker-compose.yml", ROOT / ".env.example", ROOT / "scripts" / "init_secrets.sh"):
        assert OLD_DEMO_PASSWORD not in path.read_text(encoding="utf-8"), path.name


def test_seed_reads_demo_password_only_from_secret_file():
    source = (ROOT / "app" / "db.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    func = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "demo_password"
    )
    calls = [
        node for node in ast.walk(func)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    ]
    assert any(
        call.func.id == "read_secret"
        and [arg.value for arg in call.args if isinstance(arg, ast.Constant)] == ["demo_password"]
        for call in calls
    )
    func_source = ast.get_source_segment(source, func)
    assert "environ" not in func_source and "getenv" not in func_source

    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "./secrets/demo_password" in compose

    # Run demo_password() inside the seed image: the mounted file works, and a
    # missing or empty file fails even when an env variable offers a value.
    script = """
import json, os, tempfile
import secret_files
from db import demo_password
result = {"uid": os.getuid(), "mounted": bool(demo_password())}
os.environ["DEMO_PASSWORD"] = "env-value-must-be-ignored"
with tempfile.TemporaryDirectory() as empty:
    secret_files.SECRETS_DIR = empty
    for case in ("missing", "empty"):
        if case == "empty":
            open(os.path.join(empty, "demo_password"), "w").close()
        try:
            demo_password()
            result[case] = "no error"
        except RuntimeError:
            result[case] = "error"
print(json.dumps(result))
"""
    completed = subprocess.run(
        ["docker", "compose", "run", "--rm", "--no-deps", "-T", "seed", "python", "-"],
        cwd=ROOT,
        input=script,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    result = json.loads(completed.stdout.strip().splitlines()[-1])
    assert result == {"uid": result["uid"], "mounted": True, "missing": "error", "empty": "error"}
    assert result["uid"] != 0


def _field_key_values() -> list[str]:
    line = (ROOT / "secrets" / "field_encryption_key").read_text(encoding="utf-8").strip()
    key_id, _, key_hex = line.partition(":")
    assert key_id and len(key_hex) == 64, "secrets/field_encryption_key is not '<key_id>:<hex>'"
    return [line, key_hex]


def test_field_key_is_mounted_only_on_api_and_never_leaks():
    config = subprocess.run(
        ["docker", "compose", "config", "--format", "json"],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert config.returncode == 0, config.stderr
    services = json.loads(config.stdout)["services"]
    for name, service in services.items():
        mounted = {item["source"] for item in service.get("secrets") or []}
        if name == "api":
            assert set(FIELD_KEY_SECRETS) <= mounted
        else:
            assert not mounted & set(FIELD_KEY_SECRETS), name
    assert "FIELD_ENCRYPTION" not in json.dumps(
        {name: service.get("environment") for name, service in services.items()}
    )

    plain_config = subprocess.run(
        ["docker", "compose", "config"], cwd=ROOT, capture_output=True, text=True
    ).stdout
    api_id = subprocess.run(
        ["docker", "compose", "ps", "-q", "api"], cwd=ROOT, capture_output=True, text=True
    ).stdout.strip()
    inspect = subprocess.run(
        ["docker", "inspect", api_id], cwd=ROOT, capture_output=True, text=True
    ).stdout
    logs = subprocess.run(
        ["docker", "compose", "logs", "api", "db", "migrate", "seed"],
        cwd=ROOT, capture_output=True, text=True,
    ).stdout
    env_files = "".join(
        (ROOT / name).read_text(encoding="utf-8")
        for name in (".env", ".env.example")
        if (ROOT / name).exists()
    )
    for value in _field_key_values():
        for label, text in (
            ("compose config", plain_config),
            ("docker inspect api", inspect),
            ("logs", logs),
            (".env files", env_files),
        ):
            assert value not in text, f"field key value found in {label}"

    assert "field_encryption_key" in compose_exec("api", ["ls", "/run/secrets"])
    assert "field_encryption" not in compose_exec("db", ["ls", "/run/secrets"])

    for name in FIELD_KEY_SECRETS:
        mode = (ROOT / "secrets" / name).stat().st_mode
        assert not mode & (stat.S_IROTH | stat.S_IWOTH), f"secrets/{name} is world-accessible"


def test_api_refuses_to_start_without_a_valid_field_key():
    # Import main (the uvicorn app) with a private secrets dir: a missing, empty
    # or malformed key stops startup, and an env variable is never used instead.
    script = r"""
import json, os, shutil, subprocess, sys, tempfile
result = {"uid": os.getuid()}
for case in ("missing", "empty", "malformed", "valid"):
    with tempfile.TemporaryDirectory() as tmp:
        for name in ("session_secret", "clinic_api_password", "smtp_password"):
            shutil.copy(f"/run/secrets/{name}", tmp)
        shutil.copy("/run/secrets/field_encryption_previous_keys", tmp)
        if case == "empty":
            open(os.path.join(tmp, "field_encryption_key"), "w").close()
        elif case == "malformed":
            with open(os.path.join(tmp, "field_encryption_key"), "w") as handle:
                handle.write("v1:not-hex")
        elif case == "valid":
            shutil.copy("/run/secrets/field_encryption_key", tmp)
        env = dict(os.environ, FIELD_ENCRYPTION_KEY="v9:" + "ab" * 32)
        run = subprocess.run(
            [sys.executable, "-c",
             f"import secret_files; secret_files.SECRETS_DIR = {tmp!r}; import main"],
            capture_output=True, text=True, env=env,
        )
        result[case] = {
            "code": run.returncode,
            "names_secret": "field_encryption_key" in run.stderr,
        }
print(json.dumps(result))
"""
    result = json.loads(compose_exec("api", ["python", "-"], input_text=script))
    assert result["uid"] != 0
    for case in ("missing", "empty", "malformed"):
        assert result[case]["code"] != 0, case
        assert result[case]["names_secret"], case
    assert result["valid"]["code"] == 0, result["valid"]


def test_field_key_reader_has_no_env_fallback():
    source = (ROOT / "app" / "field_crypto.py").read_text(encoding="utf-8")
    assert "environ" not in source and "getenv" not in source
    tree = ast.parse(source)
    func = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "load_keyring"
    )
    read_calls = [
        node for node in ast.walk(func)
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "read_secret"
    ]
    assert len(read_calls) == 2


def test_init_secrets_does_not_overwrite_field_key():
    files = [ROOT / "secrets" / name for name in FIELD_KEY_SECRETS]
    before = [path.read_bytes() for path in files]
    run = subprocess.run(
        ["./scripts/init_secrets.sh"], cwd=ROOT, capture_output=True, text=True
    )
    assert run.returncode == 0, run.stderr
    assert [path.read_bytes() for path in files] == before
    assert "keep    secrets/field_encryption_key" in run.stdout
    for value in _field_key_values():
        assert value not in run.stdout + run.stderr


def test_migrate_keeps_api_password_out_of_argv():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    migrate = compose.split("\n  migrate:", 1)[1].split("\n  api:", 1)[0]
    assert "-v clinic_api_password" not in migrate
    assert "$$(cat /run/secrets/clinic_api_password)" not in migrate
    assert "[ -s /run/secrets/clinic_api_password ] || " in migrate
    sql = (ROOT / "db" / "set_api_password.sql").read_text(encoding="utf-8")
    assert "\\set clinic_api_password `cat /run/secrets/clinic_api_password`" in sql
    assert "SET log_statement = 'none';" in sql
    assert "ALTER ROLE clinic_api PASSWORD :'clinic_api_password';" in sql


SECRET_READERS = {
    "postgres_password": ("db", "999"),
    "clinic_api_password": ("api", "10001"),
    "session_secret": ("api", "10001"),
    "smtp_password": ("api", "10001"),
    "demo_password": ("seed", "10001"),
}


def _compose_run(args):
    return subprocess.run(["docker", "compose", *args], cwd=ROOT, capture_output=True, text=True, timeout=60)


def test_secret_files_are_readable_only_by_their_container_user():
    if shutil.which("getfacl") is None:
        pytest.skip("no getfacl on this host: init_secrets.sh falls back to 644 with a warning")
    for name, (service, uid) in SECRET_READERS.items():
        path = ROOT / "secrets" / name
        mode = path.stat().st_mode
        assert not mode & (stat.S_IROTH | stat.S_IWOTH), f"secrets/{name} is world-accessible"
        acl = subprocess.run(["getfacl", "-cpn", str(path)], capture_output=True, text=True).stdout
        # Files handed to the container uid by the root fallback carry no ACL.
        if path.stat().st_uid == os.getuid():
            assert f"user:{uid}:r--" in acl.splitlines(), (name, acl)
            assert "other::---" in acl.splitlines(), (name, acl)
    for service in ("api", "db"):
        names = [n for n, (s, _) in SECRET_READERS.items() if s == service]
        user = "999" if service == "db" else "10001"
        for name in names:
            ok = _compose_run(["exec", "-T", "-u", user, service, "test", "-r", f"/run/secrets/{name}"])
            assert ok.returncode == 0, f"{service} uid {user} cannot read {name}"
            denied = _compose_run(["exec", "-T", "-u", "12345", service, "test", "-r", f"/run/secrets/{name}"])
            assert denied.returncode != 0, f"uid 12345 can read {name} in {service}"
