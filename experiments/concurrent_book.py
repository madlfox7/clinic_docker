"""Race multiple patient booking requests against one slot on the local app."""

import sys
import threading

import httpx

BASE = "http://localhost:8080"
PASSWORD = "password123"
ACCOUNTS = [
    ("pat@clinic.local", PASSWORD),
    ("pat2@clinic.local", PASSWORD),
]


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
    print("accepted", accepted)
    print("rejected", rejected)
    if accepted > 1:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
