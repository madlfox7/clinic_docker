import json
import pathlib

from test_rls_boundary import compose_exec

ROOT = pathlib.Path(__file__).resolve().parents[1]
SECRET_FILES = ("postgres_password", "clinic_api_password", "session_secret")
FORBIDDEN_ENV = (
    "DATABASE_URL",
    "PGPASSWORD",
    "POSTGRES_PASSWORD",
    "CLINIC_API_PASSWORD",
    "SESSION_SECRET",
    "SMTP_PASSWORD",
)


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
