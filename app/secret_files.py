SECRETS_DIR = "/run/secrets"


def read_secret(name: str) -> str:
    path = f"{SECRETS_DIR}/{name}"
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError as exc:
        raise RuntimeError(f"Docker secret {name} is missing or unreadable at {path}") from exc
