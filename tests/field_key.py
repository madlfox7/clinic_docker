"""Encrypt and decrypt medical text in tests with the stand's own key files.

Reads secrets/field_encryption_key and secrets/field_encryption_previous_keys
from the checkout (the same files the api mounts). No key value lives in the repo.

Packets are bound to their row id and appointment id, which raw SQL fixtures
do not know before the INSERT. sql_packet() therefore returns a unique
placeholder packet; seal_pending() (called by the tests' psql helpers right
after each statement) swaps every placeholder that reached a table for the
real packet bound to that row.
"""

import os
import subprocess
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import field_crypto  # noqa: E402

# Syntactically valid packet for RLS probes that are rejected or rolled back;
# it decrypts under no key.
PROBE_PACKET = "fe2:probe:AAAAAAAAAAAAAAAA:AAAA:AAAAAAAAAAAAAAAAAAAAAA"

_pending = {}


def _read(name: str) -> str:
    path = ROOT / "secrets" / name
    try:
        return path.read_text(encoding="utf-8")
    except PermissionError:
        # File handed to the api uid (no ACL support): read it from the api container.
        completed = subprocess.run(
            ["docker", "compose", "exec", "-T", "api", "cat", f"/run/secrets/{name}"],
            cwd=ROOT, capture_output=True, text=True,
        )
        assert completed.returncode == 0, f"cannot read secret {name}"
        return completed.stdout


def stand_keyring() -> field_crypto.Keyring:
    return field_crypto.Keyring.from_texts(
        _read(field_crypto.CURRENT_KEY_SECRET), _read(field_crypto.PREVIOUS_KEYS_SECRET)
    )


def encrypt(table: str, row_id: int, appointment_id: int, text: str) -> str:
    return stand_keyring().encrypt(table, row_id, appointment_id, text)


def decrypt(table: str, row_id: int, appointment_id: int, packet: str) -> str:
    return stand_keyring().decrypt(table, row_id, appointment_id, packet)


def legacy_packet(table: str, text: str, ring=None) -> str:
    """An fe1 packet as the first release wrote it (table + key id only)."""
    ring = ring or stand_keyring()
    key_id = ring.current_id
    nonce = os.urandom(12)
    sealed = ring._keys[key_id].encrypt(
        nonce, text.encode("utf-8"), field_crypto._legacy_aad(table, key_id)
    )
    b64 = field_crypto._b64e
    return ":".join(("fe1", key_id, b64(nonce), b64(sealed[:-16]), b64(sealed[-16:])))


def _psql_superuser(sql: str) -> list:
    completed = subprocess.run(
        ["docker", "compose", "exec", "-T", "db", "psql", "-X", "-U", "clinic", "-d", "clinic",
         "-v", "ON_ERROR_STOP=1", "-At", "-F", "|", "-c", sql],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    return [line for line in completed.stdout.splitlines() if line.strip()]


def sql_packet(table: str, text: str) -> str:
    """SQL literal of a placeholder packet, sealed to its row by seal_pending()."""
    field_crypto._check_table(table)
    placeholder = (
        f"fe2:pending:{field_crypto._b64e(os.urandom(12))}:"
        f"{uuid.uuid4().hex}:AAAAAAAAAAAAAAAAAAAAAA"
    )
    _pending[placeholder] = (table, text)
    return "'" + placeholder + "'"


def seal_pending() -> None:
    """Replace placeholders that were inserted by the last statement(s)."""
    if not _pending:
        return
    pending = dict(_pending)
    _pending.clear()
    ring = stand_keyring()
    for table in field_crypto.MEDICAL_TABLES:
        mine = [p for p, (t, _) in pending.items() if t == table]
        if not mine:
            continue
        listed = ", ".join(f"'{p}'" for p in mine)
        rows = _psql_superuser(
            f"SELECT id, appointment_id, body FROM {table} WHERE body IN ({listed})"
        )
        updates = []
        for line in rows:
            row_id, appointment_id, placeholder = line.split("|")
            packet = ring.encrypt(
                table, int(row_id), int(appointment_id), pending[placeholder][1]
            )
            updates.append(
                f"UPDATE {table} SET body = '{packet}' "
                f"WHERE id = {int(row_id)} AND body = '{placeholder}';"
            )
        if updates:
            _psql_superuser("BEGIN; " + " ".join(updates) + " COMMIT;")


is_packet = field_crypto.is_packet
is_legacy_packet = field_crypto.is_legacy_packet
