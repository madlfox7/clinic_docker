from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEMO_PASSWORD_FILE = ROOT / "secrets" / "demo_password"


def demo_password() -> str:
    """Password of the seeded demo accounts, read from the same secret file as seed."""
    value = DEMO_PASSWORD_FILE.read_text(encoding="utf-8").strip()
    assert value, "secrets/demo_password is empty; run scripts/init_secrets.sh"
    return value
