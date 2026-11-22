"""Migrate medical text to fe2; reruns leave fe2 unchanged unless re-encrypting."""

import sys

from db import db
from field_crypto import (
    MEDICAL_TABLES,
    FieldDecryptError,
    Keyring,
    is_legacy_packet,
    is_packet,
    keyring,
)

BATCH_SIZE = 200


def _plaintext(ring: Keyring, table: str, row_id: int, appointment_id: int, stored: str) -> str:
    if is_packet(stored):
        return ring.decrypt(table, row_id, appointment_id, stored)
    if is_legacy_packet(stored):
        return ring.decrypt_legacy(table, stored)
    return stored


def migrate(conn, ring: Keyring, reencrypt: bool = False) -> dict:
    """Rewrite rows in batches; the caller decides whether to commit."""
    counts = {}
    with conn.cursor() as cur:
        for table in MEDICAL_TABLES:
            done = 0
            failed = 0
            after_id = 0
            while True:
                cur.execute(
                    "SELECT id, appointment_id, body "
                    "FROM public.medical_bodies_to_encrypt(%s, %s, %s, %s, %s)",
                    (table, ring.current_id, reencrypt, after_id, BATCH_SIZE),
                )
                rows = cur.fetchall()
                if not rows:
                    break
                for row_id, appointment_id, stored in rows:
                    after_id = row_id
                    try:
                        plaintext = _plaintext(ring, table, row_id, appointment_id, stored)
                    except FieldDecryptError as exc:
                        print(
                            f"medical field migration: {table} id={row_id} "
                            f"could not be decrypted ({exc.reason}); left unchanged",
                            file=sys.stderr,
                        )
                        failed += 1
                        continue
                    cur.execute(
                        "SELECT public.medical_body_replace(%s, %s, %s, %s)",
                        (
                            table,
                            row_id,
                            stored,
                            ring.encrypt(table, row_id, appointment_id, plaintext),
                        ),
                    )
                    if cur.fetchone()[0]:
                        done += 1
            counts[table] = {"encrypted": done, "failed": failed}
    return counts


def main(argv) -> int:
    reencrypt = "--reencrypt" in argv
    ring = keyring()
    conn = db()
    try:
        counts = migrate(conn, ring, reencrypt=reencrypt)
        conn.commit()
    finally:
        conn.close()
    summary = ", ".join(
        f"{table}: {c['encrypted']} encrypted, {c['failed']} unreadable"
        for table, c in counts.items()
    )
    mode = "re-encrypt" if reencrypt else "bind"
    print(
        f"medical field migration ({mode}) with key_id={ring.current_id}: {summary}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
