"""A failed audit cycle says what failed: errno, the call and the path, never
file contents or the message of a database error (WSL2 /mnt/c used to show a
bare "PermissionError"). Unit tests, no docker."""
import os
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "audit"))

import anchor  # noqa: E402
import chainlib as cl  # noqa: E402

# --- "audit cycle failed" says errno, call and path (never contents) ------------------

def test_cycle_error_names_errno_call_and_path(tmp_path):
    locked = tmp_path / "anchors"
    locked.mkdir()
    locked.chmod(0o500)     # no write: the file cannot be created
    try:
        if os.access(locked, os.W_OK):
            pytest.skip("running as root: permissions are not enforced")
        try:
            cl.append_line(locked / "chains.log", b"k" * 32, bytes(32), "v1 open x")
        except OSError as exc:
            text = anchor.describe_error(exc)
    finally:
        locked.chmod(stat.S_IRWXU)
    assert text == f"PermissionError errno=EACCES(13) op=os.open path={locked / 'chains.log'}"


def test_fd_calls_get_the_path(tmp_path, monkeypatch):
    target = tmp_path / "chains.log"

    def refuse(fd, mode):
        raise PermissionError(1, "Operation not permitted")
    monkeypatch.setattr(cl.os, "fchmod", refuse)
    with pytest.raises(PermissionError) as caught:
        cl.append_line(target, b"k" * 32, bytes(32), "v1 open x")
    text = anchor.describe_error(caught.value)
    assert text.startswith("PermissionError errno=EPERM(1) op=")
    assert text.endswith(f"path={target}")


def test_non_os_errors_keep_only_the_type():
    class FakeDbError(Exception):
        pass
    assert anchor.describe_error(FakeDbError("password=hunter2 host=db")) == "FakeDbError"
    assert anchor.describe_error(ValueError("secret")) == "ValueError"


def test_run_cycle_logs_the_described_error(monkeypatch, tmp_path):
    def broken_connect():
        raise PermissionError(13, "Permission denied", "/run/secrets/audit_db_password")
    monkeypatch.setattr(cl, "connect", broken_connect)
    result = anchor.run_cycle(b"k" * 32, {})
    assert result.line == ("ERROR audit cycle failed: PermissionError errno=EACCES(13) op=cl.connect "
                           "path=/run/secrets/audit_db_password")
    assert result.error == "database"     # the classification stays the same
