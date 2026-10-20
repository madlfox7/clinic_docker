"""Server-only reset for the last remaining administrator.

The web interface cannot email a reset link to the sole admin account.
Run this inside the API container:

    python send_reset_link.py admin@clinic.local
"""

import sys

from db import db
from mailer import send_password_reset


def main() -> int:
    if len(sys.argv) != 2 or not sys.argv[1].strip():
        print("usage: python send_reset_link.py EMAIL", file=sys.stderr)
        return 2
    email = sys.argv[1].strip()
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT reset_token, rate_limited, outcome
                FROM public.request_password_reset(%s, %s, TRUE)
                """,
                (email, "cli"),
            )
            row = cur.fetchone()
        conn.commit()
    finally:
        conn.close()
    token, limited, outcome = row if row else (None, False, "unknown")
    if limited:
        print("Too many reset attempts. Try again later.", file=sys.stderr)
        return 1
    if outcome != "issued" or not token:
        print(
            "This command only sends a reset link to the last remaining administrator.",
            file=sys.stderr,
        )
        return 1
    try:
        send_password_reset(email.lower(), token)
    except Exception as exc:
        print(f"SMTP failed: {exc}", file=sys.stderr)
        print(
            "Server recovery link (not shown in the web interface): "
            f"/reset-password?token={token}",
            file=sys.stderr,
        )
        return 1
    print("Reset link sent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
