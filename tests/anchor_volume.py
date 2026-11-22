"""Read and restore external anchors via a one-off container."""
import io
import json
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

TAR_OUT = ("import sys, tarfile; t = tarfile.open(fileobj=sys.stdout.buffer, mode='w|'); "
           "t.add('/anchors', arcname='.'); t.close()")
TAR_IN = ("import sys, tarfile; "
          "tarfile.open(fileobj=sys.stdin.buffer, mode='r|').extractall('/anchors', filter='data')")
WIPE = "import os; [os.remove(os.path.join('/anchors', n)) for n in os.listdir('/anchors')]"
LISTING = "import json, os; print(json.dumps(sorted(os.listdir('/anchors'))))"


def _python(code: str, data: bytes | None = None) -> subprocess.CompletedProcess:
    done = subprocess.run(["docker", "compose", "run", "--rm", "--no-deps", "-T", "--entrypoint", "python",
                           "audit_anchor", "-c", code], cwd=ROOT, input=data, capture_output=True, timeout=300)
    assert done.returncode == 0, done.stderr.decode(errors="replace")[-2000:]
    return done


def volume_name() -> str:
    done = subprocess.run(["docker", "compose", "config", "--format", "json"], cwd=ROOT,
                          capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)["volumes"]["audit_anchors"]["name"]


def snapshot(dest: Path | None = None) -> Path:
    """A copy of /anchors on the host (a new temporary directory by default)."""
    if dest is None:
        dest = Path(tempfile.mkdtemp(prefix="anchors-"))
    dest.mkdir(parents=True, exist_ok=True)
    data = _python(TAR_OUT).stdout
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        archive.extractall(dest, filter="data")
    return dest


def listing() -> list[str]:
    return json.loads(_python(LISTING).stdout)


def check_dir() -> subprocess.CompletedProcess:
    return subprocess.run(["docker", "compose", "run", "--rm", "--no-deps", "-T", "audit_anchor", "python",
                           "anchor.py", "--check-dir"], cwd=ROOT, capture_output=True, text=True, timeout=300)


def wipe() -> None:
    _python(WIPE)


def restore(src: Path) -> None:
    """Put the files of a snapshot back (as uid 10002), without .lock."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for path in sorted(src.iterdir()):
            if path.name != ".lock":
                archive.add(path, arcname=path.name)
    _python(TAR_IN, buffer.getvalue())


def remove_volume() -> None:
    """The volume gone (the disposable stand only): its containers first."""
    name = volume_name()
    assert name.startswith("e6"), f"only the disposable e6 stand, not {name}"
    done = subprocess.run(["docker", "compose", "rm", "-f", "-s", "audit_anchor", "audit_prepare"], cwd=ROOT,
                          capture_output=True, text=True, timeout=300)
    assert done.returncode == 0, done.stderr
    for _ in range(10):
        gone = subprocess.run(["docker", "volume", "rm", name], capture_output=True, text=True, timeout=120)
        if gone.returncode == 0:
            return
        time.sleep(2)    # Wait for one-off containers to release the volume.
    raise AssertionError(gone.stderr)


def created_at() -> str:
    done = subprocess.run(["docker", "volume", "inspect", "-f", "{{.CreatedAt}}", volume_name()],
                          capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    return done.stdout.strip()
