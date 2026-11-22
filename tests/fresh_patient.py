"""Create fresh patients for tests; audit history survives cleanup."""
import subprocess
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAT = "pat@clinic.local"


def _psql(sql: str) -> str:
    done = subprocess.run(
        ["docker", "compose", "exec", "-T", "db", "psql", "-X", "-U", "clinic", "-d", "clinic",
         "-v", "ON_ERROR_STOP=1", "-At", "-c", sql],
        cwd=ROOT, capture_output=True, text=True, timeout=120,
    )
    assert done.returncode == 0, done.stderr or done.stdout
    return done.stdout.strip()


def create_fresh_patient(prefix: str = "fresh") -> tuple[str, int]:
    """New confirmed patient with PAT's password; returns (email, user id)."""
    email = f"{prefix}-{uuid.uuid4().hex[:12]}@example.test"
    user_id = int(_psql(
        "WITH u AS (INSERT INTO users (email, password_hash, role, blocked, email_verified_at) "
        f"VALUES ('{email}', (SELECT password_hash FROM users WHERE email = '{PAT}'), 'patient', false, now()) "
        "RETURNING id), p AS (INSERT INTO patient_profiles (user_id, full_name, phone) "
        "SELECT id, 'Fresh Patient', '+374 10 000222' FROM u) SELECT id FROM u"
    ).splitlines()[0])
    return email, user_id


def drop_fresh_patient(user_id: int) -> None:
    """Remove the patient's appointments and account; journal events stay."""
    _psql(
        f"DELETE FROM appointments WHERE patient_user_id = {user_id}; "
        f"DELETE FROM login_attempts WHERE email_fingerprint = "
        f"(SELECT public.digest(email, 'sha256') FROM users WHERE id = {user_id}); "
        f"DELETE FROM users WHERE id = {user_id}"
    )
