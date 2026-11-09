"""Encrypt medical text that is still stored as plaintext.

Runs in the api container before uvicorn starts (see docker/api/Dockerfile),
because only the api has the field encryption key. Safe to run repeatedly:
rows that already hold a packet are skipped.

    python -m migrate_medical_fields              # plaintext rows -> current key
    python -m migrate_medical_fields --reencrypt  # also rows under older key ids

Output names tables, counts and key ids only, never text or key material.
"""

import sys

from db import db
from field_crypto import MEDICAL_TABLES, FieldDecryptError, Keyring, is_packet, keyring

BATCH_SIZE = 200


def migrate(conn, ring: Keyring, reencrypt: bool = False) -> dict:
    """Encrypt rows in batches; the caller decides whether to commit."""
    counts = {}
    with conn.cursor() as cur:
        for table in MEDICAL_TABLES:
            done = 0
            failed = 0
            after_id = 0
            while True:
                cur.execute(
                    "SELECT id, body FROM public.medical_bodies_to_encrypt(%s, %s, %s, %s, %s)",
                    (table, ring.current_id, reencrypt, after_id, BATCH_SIZE),
                )
                rows = cur.fetchall()
                if not rows:
                    break
                for row_id, stored in rows:
                    after_id = row_id
                    if is_packet(stored):
                        try:
                            plaintext = ring.decrypt(table, stored)
                        except FieldDecryptError as exc:
                            print(
                                f"medical field migration: {table} id={row_id} "
                                f"could not be decrypted ({exc.reason}); left unchanged",
                                file=sys.stderr,
                            )
                            failed += 1
                            continue
                    else:
                        plaintext = stored
                    cur.execute(
                        "SELECT public.medical_body_replace(%s, %s, %s, %s)",
                        (table, row_id, stored, ring.encrypt(table, plaintext)),
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
    mode = "re-encrypt" if reencrypt else "plaintext"
    print(
        f"medical field migration ({mode}) with key_id={ring.current_id}: {summary}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
