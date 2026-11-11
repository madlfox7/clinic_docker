"""Versioned URLs for files under static/.

Each file's SHA-256 is computed once at startup and appended as ?v=<hash>,
so the proxy can cache /static responses for a long time and a changed file
gets a new URL.
"""
import hashlib
from pathlib import Path

STATIC_DIR = Path(__file__).resolve().parent / "static"


def _hash_files(root: Path) -> dict[str, str]:
    versions = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            rel = path.relative_to(root).as_posix()
            versions[rel] = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
    return versions


_VERSIONS = _hash_files(STATIC_DIR)


def static_url(path: str) -> str:
    rel = path.lstrip("/")
    version = _VERSIONS.get(rel)
    if version is None:
        raise ValueError(f"unknown static file: {rel}")
    return f"/static/{rel}?v={version}"
