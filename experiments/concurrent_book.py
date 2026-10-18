"""Race multiple patient booking requests against one slot on the local app."""

import os
import re
import subprocess
import sys
import threading
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
BASE = os.environ.get("CLINIC_TEST_BASE", "http://localhost:8080")
PASSWORD = "password123"
ACCOUNTS = [
    ("pat@clinic.local", PASSWORD),
    ("pat2@clinic.local", PASSWORD),
]


def scheduled_count(slot_id: int) -> int:
    completed = subprocess.run(
        [
            "docker", "compose", "exec", "-T", "db",
            "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
            "-U", "clinic", "-d", "clinic", "-At",
            "-c",
            f"SELECT count(*) FROM appointments WHERE slot_id={slot_id} AND status='scheduled'",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr or completed.stdout)
    return int(completed.stdout.strip())


def race_accounts(prefix: str) -> list[tuple[str, str]]:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", prefix):
        raise ValueError("Concurrent user prefix contains unsupported characters")
    completed = subprocess.run(
        [
            "docker", "compose", "exec", "-T", "db",
            "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
            "-U", "clinic", "-d", "clinic", "-At",
            "-c",
            f"SELECT email FROM users WHERE email LIKE '{prefix}-%@clinic.local' ORDER BY email",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr or completed.stdout)
    return [(email, PASSWORD) for email in completed.stdout.splitlines() if email]


def worker(index: int, slot_id: int, barrier: threading.Barrier, results: dict[int, str]) -> None:
    email, password = ACCOUNTS[index % len(ACCOUNTS)]
    try:
        with httpx.Client(base_url=BASE, follow_redirects=True, timeout=20.0) as client:
            login = client.post("/login", data={"email": email, "password": password})
            if login.status_code != 200 or not login.url.path.endswith("/me"):
                results[index] = f"login-failed:{email}:{login.status_code}"
                barrier.abort()
                return

            barrier.wait(timeout=20.0)
            response = client.post(f"/slots/{slot_id}/book")
            content = f"{response.url} {response.text}".lower()
            if "unavailable" in content or "overlap" in content:
                results[index] = "rejected"
            elif response.url.path == "/my" or "scheduled" in content:
                results[index] = "accepted"
            else:
                results[index] = f"unknown:{response.status_code}:{response.url}"
    except threading.BrokenBarrierError:
        results[index] = "not-started:another-worker-failed-login"
    except Exception as error:
        results[index] = f"error:{type(error).__name__}:{error}"
        barrier.abort()


def main() -> int:
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python experiments/concurrent_book.py SLOT_ID [REQUEST_COUNT]")
        return 2

    slot_id = int(sys.argv[1])
    request_count = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    if request_count < 1:
        print("REQUEST_COUNT must be at least 1")
        return 2

    prefix = os.environ.get("CONCURRENT_BOOK_USER_PREFIX")
    if prefix:
        try:
            accounts = race_accounts(prefix)
        except (RuntimeError, ValueError) as error:
            print(error)
            return 2
        if len(accounts) < request_count:
            print(f"Expected {request_count} unique users, found {len(accounts)}")
            return 2
        global ACCOUNTS
        ACCOUNTS = accounts[:request_count]

    barrier = threading.Barrier(request_count)
    results: dict[int, str] = {}
    threads = [
        threading.Thread(target=worker, args=(i, slot_id, barrier, results))
        for i in range(request_count)
    ]

    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    print(results)
    accepted = list(results.values()).count("accepted")
    rejected = list(results.values()).count("rejected")
    unknown = len(results) - accepted - rejected
    persisted = scheduled_count(slot_id)
    distinct_accounts = len({email for email, _ in ACCOUNTS})
    print("accepted", accepted)
    print("rejected", rejected)
    print("unknown", unknown)
    print("scheduled_rows", persisted)
    print("distinct_accounts", distinct_accounts)
    if (
        len(results) != request_count
        or accepted != 1
        or rejected != request_count - 1
        or persisted != 1
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
