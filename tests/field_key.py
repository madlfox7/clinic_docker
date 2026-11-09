"""Encrypt and decrypt medical text in tests with the stand's own key files.

Reads secrets/field_encryption_key and secrets/field_encryption_previous_keys
from the checkout (the same files the api mounts). No key value lives in the repo.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import field_crypto  # noqa: E402

# Syntactically valid packet for RLS probes that are rejected or rolled back;
# it decrypts under no key.
PROBE_PACKET = "fe1:probe:AAAAAAAAAAAAAAAA:AAAA:AAAAAAAAAAAAAAAAAAAAAA"


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


def encrypt(table: str, text: str) -> str:
    return stand_keyring().encrypt(table, text)


def decrypt(table: str, packet: str) -> str:
    return stand_keyring().decrypt(table, packet)


def sql_packet(table: str, text: str) -> str:
    """SQL literal of an encrypted packet (packets contain no quotes)."""
    return "'" + encrypt(table, text) + "'"


is_packet = field_crypto.is_packet
