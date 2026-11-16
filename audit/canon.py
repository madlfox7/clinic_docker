"""Canonical form v1 of an audit journal row (plan 17 §6.2), independent of
the SQL function public.audit_canon_v1: verify_audit and the anchors trust
only this code, never functions in the database.

Fields in this order, each as b"<length>:<UTF-8 bytes>" and NULL as b"-":
seq, id, created_at, actor_user_id, actor_role, action, target_type,
target_id, reason, source, old_value, new_value. Integers are decimal text;
created_at is whole microseconds since the UTC epoch.
row_hash = sha256(prev_hash || canon); prev_hash of seq 1 = sha256(chain_id bytes).
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import uuid

PREFIX = b"clinic-audit-v1"
HASH_VERSION = 1
FIELDS = ("seq", "id", "created_at", "actor_user_id", "actor_role", "action", "target_type",
          "target_id", "reason", "source", "old_value", "new_value")
CHAIN_COLUMNS = ("seq", "prev_hash", "row_hash", "hash_version")
_EPOCH = _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)


def _field(value) -> bytes:
    if value is None:
        return b"-"
    if isinstance(value, bool):
        raise TypeError("booleans are not journal fields")
    if isinstance(value, int):
        data = str(value).encode("ascii")
    elif isinstance(value, str):
        data = value.encode("utf-8")
    else:
        raise TypeError(f"unexpected field type {type(value).__name__}")
    return str(len(data)).encode("ascii") + b":" + data


def epoch_micros(value: _dt.datetime) -> int:
    if value.tzinfo is None:
        raise ValueError("created_at must carry a time zone")
    return (value - _EPOCH) // _dt.timedelta(microseconds=1)


def canon_v1(row: dict) -> bytes:
    parts = [PREFIX]
    for name in FIELDS:
        value = row[name]
        if name == "created_at":
            value = epoch_micros(value)
        parts.append(_field(value))
    return b"".join(parts)


# The one place that names the hash algorithm on the Python side (v1: SHA-256);
# the SQL side is audit_row_hash_v1 / audit_genesis_hash_v1 in db/init.sql.
def _digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def genesis_prev_hash(chain_id) -> bytes:
    return _digest(uuid.UUID(str(chain_id)).bytes)


def row_hash(prev_hash: bytes, row: dict) -> bytes:
    return _digest(bytes(prev_hash) + canon_v1(row))
