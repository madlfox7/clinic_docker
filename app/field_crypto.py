"""AES-256-GCM encryption of medical text (visit_notes.body, prescriptions.body).

Only the api process holds the keys. The database stores a packet:

    fe2:<key_id>:<nonce>:<ciphertext>:<tag>

nonce (12 bytes), ciphertext and tag (16 bytes) are unpadded base64url.
The associated data binds the packet header, the table, the row id and the
appointment id, so a packet cannot be relabelled to another key or moved to
another row (of the same or the other table): it then fails to decrypt.

Legacy fe1 packets (bound to table and key id only) are never shown: only
migrate_medical_fields decrypts them, once, to rewrite them as fe2.

Key files (Docker secrets, api only):
  field_encryption_key            one line "<key_id>:<64 hex chars>", the key for new writes
  field_encryption_previous_keys  zero or more such lines, kept for reading older rows
"""

import base64
import binascii
import os
import re

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


PACKET_VERSION = "fe2"
LEGACY_PACKET_VERSION = "fe1"
MEDICAL_TABLES = ("visit_notes", "prescriptions")
KEY_ID_PATTERN = r"[A-Za-z0-9_-]{1,32}"


def _packet_re(version: str):
    return re.compile(
        rf"^{version}:({KEY_ID_PATTERN}):([A-Za-z0-9_-]{{16}}):([A-Za-z0-9_-]+):([A-Za-z0-9_-]{{22}})$"
    )


PACKET_RE = _packet_re(PACKET_VERSION)
LEGACY_PACKET_RE = _packet_re(LEGACY_PACKET_VERSION)
_KEY_ID_RE = re.compile(rf"^{KEY_ID_PATTERN}$")
_KEY_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_NONCE_BYTES = 12
_TAG_BYTES = 16

CURRENT_KEY_SECRET = "field_encryption_key"
PREVIOUS_KEYS_SECRET = "field_encryption_previous_keys"


class FieldKeyError(RuntimeError):
    """Key material is missing or malformed. Messages never contain key bytes."""


class FieldDecryptError(Exception):
    """A stored value could not be decrypted. Carries only a short reason code."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _aad(table: str, key_id: str, row_id: int, appointment_id: int) -> bytes:
    return (
        f"{PACKET_VERSION}:{key_id}|{table}.body|id={row_id}|appointment_id={appointment_id}"
    ).encode("ascii")


def _legacy_aad(table: str, key_id: str) -> bytes:
    return f"{LEGACY_PACKET_VERSION}:{key_id}|{table}.body".encode("ascii")


def _check_table(table: str) -> None:
    if table not in MEDICAL_TABLES:
        raise ValueError("not an encrypted medical table")


def _check_row(row_id, appointment_id) -> None:
    for value in (row_id, appointment_id):
        if type(value) is not int or value < 1:
            raise ValueError("row id and appointment id must be positive integers")


def parse_key_line(line: str, source: str) -> tuple[str, bytes]:
    key_id, sep, key_hex = line.strip().partition(":")
    if not sep or not _KEY_ID_RE.match(key_id) or not _KEY_HEX_RE.match(key_hex):
        raise FieldKeyError(
            f"{source}: expected '<key_id>:<64 hex characters>' "
            "(key_id: letters, digits, '_' or '-', up to 32)"
        )
    return key_id, bytes.fromhex(key_hex)


def is_packet(value) -> bool:
    """A current (row-bound) packet."""
    return isinstance(value, str) and PACKET_RE.match(value) is not None


def is_legacy_packet(value) -> bool:
    return isinstance(value, str) and LEGACY_PACKET_RE.match(value) is not None


def packet_key_id(value: str):
    if not isinstance(value, str):
        return None
    match = PACKET_RE.match(value) or LEGACY_PACKET_RE.match(value)
    return match.group(1) if match else None


class Keyring:
    def __init__(self, current_id: str, keys: dict):
        if current_id not in keys:
            raise FieldKeyError("current key id is not in the keyring")
        self.current_id = current_id
        self._keys = {key_id: AESGCM(raw) for key_id, raw in keys.items()}

    @classmethod
    def from_texts(cls, current_text: str, previous_text: str = "") -> "Keyring":
        current_lines = [l for l in (current_text or "").splitlines() if l.strip()]
        if not current_lines:
            raise FieldKeyError(
                f"Docker secret {CURRENT_KEY_SECRET} is empty; run scripts/init_secrets.sh"
            )
        if len(current_lines) != 1:
            raise FieldKeyError(f"{CURRENT_KEY_SECRET} must contain exactly one key line")
        current_id, current_raw = parse_key_line(current_lines[0], CURRENT_KEY_SECRET)
        keys = {current_id: current_raw}
        for number, line in enumerate((previous_text or "").splitlines(), start=1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            key_id, raw = parse_key_line(line, f"{PREVIOUS_KEYS_SECRET} line {number}")
            if key_id in keys:
                if keys[key_id] != raw:
                    raise FieldKeyError(f"key id {key_id} is defined twice with different keys")
                continue
            keys[key_id] = raw
        return cls(current_id, keys)

    @property
    def key_ids(self) -> list:
        return sorted(self._keys)

    def encrypt(self, table: str, row_id: int, appointment_id: int, plaintext: str) -> str:
        _check_table(table)
        _check_row(row_id, appointment_id)
        if not isinstance(plaintext, str):
            raise TypeError("plaintext must be str")
        nonce = os.urandom(_NONCE_BYTES)
        sealed = self._keys[self.current_id].encrypt(
            nonce,
            plaintext.encode("utf-8"),
            _aad(table, self.current_id, row_id, appointment_id),
        )
        ciphertext, tag = sealed[:-_TAG_BYTES], sealed[-_TAG_BYTES:]
        return ":".join(
            (PACKET_VERSION, self.current_id, _b64e(nonce), _b64e(ciphertext), _b64e(tag))
        )

    def _open(self, match, aad_for) -> str:
        key_id, nonce_text, ciphertext_text, tag_text = match.groups()
        aead = self._keys.get(key_id)
        if aead is None:
            raise FieldDecryptError("unknown_key_id")
        try:
            nonce = _b64d(nonce_text)
            sealed = _b64d(ciphertext_text) + _b64d(tag_text)
            return aead.decrypt(nonce, sealed, aad_for(key_id)).decode("utf-8")
        except (InvalidTag, binascii.Error, ValueError):
            # Wrong row, wrong table, tampered packet or wrong key bytes.
            raise FieldDecryptError("integrity_check_failed") from None

    def decrypt(self, table: str, row_id: int, appointment_id: int, packet: str) -> str:
        """Open a packet stored in this exact row; any other row fails."""
        _check_table(table)
        _check_row(row_id, appointment_id)
        match = PACKET_RE.match(packet) if isinstance(packet, str) else None
        if match is None:
            if is_legacy_packet(packet):
                raise FieldDecryptError("unbound_packet")
            raise FieldDecryptError("not_encrypted")
        return self._open(
            match, lambda key_id: _aad(table, key_id, row_id, appointment_id)
        )

    def decrypt_legacy(self, table: str, packet: str) -> str:
        """Open an fe1 packet (table and key id only). Migration use only."""
        _check_table(table)
        match = LEGACY_PACKET_RE.match(packet) if isinstance(packet, str) else None
        if match is None:
            raise FieldDecryptError("not_legacy_packet")
        return self._open(match, lambda key_id: _legacy_aad(table, key_id))


_keyring = None


def load_keyring() -> Keyring:
    """Read both key secrets. No env fallback, no default key."""
    from secret_files import read_secret

    return Keyring.from_texts(
        read_secret(CURRENT_KEY_SECRET), read_secret(PREVIOUS_KEYS_SECRET)
    )


def init_keyring() -> Keyring:
    global _keyring
    _keyring = load_keyring()
    return _keyring


def keyring() -> Keyring:
    if _keyring is None:
        return init_keyring()
    return _keyring


def encrypt_body(table: str, row_id: int, appointment_id: int, plaintext: str) -> str:
    return keyring().encrypt(table, row_id, appointment_id, plaintext)


def decrypt_body(table: str, row_id: int, appointment_id: int, packet: str) -> str:
    return keyring().decrypt(table, row_id, appointment_id, packet)
