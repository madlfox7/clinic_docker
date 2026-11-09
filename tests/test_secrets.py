import ast
import json
import pathlib
import subprocess

from test_rls_boundary import compose_exec

ROOT = pathlib.Path(__file__).resolve().parents[1]
SECRET_FILES = ("postgres_password", "clinic_api_password", "session_secret", "demo_password")
FORBIDDEN_ENV = (
    "DATABASE_URL",
    "PGPASSWORD",
    "POSTGRES_PASSWORD",
    "CLINIC_API_PASSWORD",
    "SESSION_SECRET",
    "SMTP_PASSWORD",
    "DEMO_PASSWORD",
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
