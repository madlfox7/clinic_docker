"""Plan 18.2: the "Log integrity" banner on /admin/audit.

Unit tests of app/audit_status.py (read_banner) on temporary files, then the
page itself on the running stand, and the red/grey cases on the disposable
stand -p e6 only (they stop audit_anchor, change a journal row as the
database superuser and replace the chain)."""
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from tests.csrf_client import CsrfClient
from tests.demo_secret import demo_password

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))
sys.path.insert(0, str(ROOT / "audit"))
import audit_status as st  # noqa: E402  (app/audit_status.py)
import anchor  # noqa: E402  (audit/anchor.py, the writer)

BASE = os.environ.get("CLINIC_TEST_BASE", "https://localhost:8450")
PROJECT = os.environ.get("COMPOSE_PROJECT_NAME", "")
PASSWORD = demo_password()
ADMIN = "admin@clinic.local"
OTHERS = {"patient": "pat@clinic.local", "doctor": "doc@clinic.local", "registrar": "reg@clinic.local"}

NOW = 1_800_000_000.0
INTERVAL, FULL = 60, 600


def _good(**changes) -> dict:
    data = {"v": 1, "state": "ok", "checked_at": NOW - 5, "full_checked_at": NOW - 100, "full_ok": True,
            "anchored_at": NOW - 5, "last_anchor_seq": 42, "problem": None,
            "retired_forced": 0, "retired_offline": 0, "replaced_history": 0}
    data.update(changes)
    return data


def _banner(tmp_path, content, now=NOW) -> st.Banner:
    path = tmp_path / "status.json"
    if isinstance(content, dict):
        content = json.dumps(content)
    if isinstance(content, str):
        content = content.encode()
    path.write_bytes(content)
    return st.read_banner(str(path), now, INTERVAL, FULL)


# --- unit: read_banner ------------------------------------------------------------

def test_valid_fresh_ok_is_green(tmp_path):
    banner = _banner(tmp_path, _good())
    assert banner.state == "ok" and banner.label == "OK" and banner.reason is None
    assert banner.last_anchor_seq == 42 and banner.checked_at is not None


def test_limits_are_inclusive(tmp_path):
    edge = _good(checked_at=NOW - (3 * INTERVAL + 60), full_checked_at=NOW - (2 * FULL + 60),
                 anchored_at=NOW + 60)
    assert _banner(tmp_path, edge).state == "ok"


def test_the_writer_output_is_green(tmp_path):
    """The file audit_anchor writes is read back as OK (schema v1 on both sides)."""
    public = anchor.PublicStatus(FULL)
    _, data = public.step(NOW - 5, lambda full: _fake_result(full))
    anchor.write_public_status(tmp_path, data)
    assert st.read_banner(str(tmp_path / anchor.PUBLIC_STATUS_NAME), NOW, INTERVAL, FULL).state == "ok"


def _fake_result(full):
    result = anchor.Result(True, "anchoring", anchored=(42, "x"), line="anchored")
    result.full = anchor.FullCheck(True) if full else None
    result.counts = (0, 0, 0)
    return result


BAD_CASES = {
    "stale checked_at": _good(checked_at=NOW - (3 * INTERVAL + 60) - 1),
    "stale full_checked_at": _good(full_checked_at=NOW - (2 * FULL + 60) - 1),
    "no full check yet": _good(full_checked_at=None, full_ok=None),
    "future checked_at": _good(checked_at=NOW + 61),
    "future full_checked_at": _good(full_checked_at=NOW + 61),
    "future anchored_at": _good(anchored_at=NOW + 61),
    "empty": b"",
    "4097 bytes": json.dumps(_good()).encode().ljust(4097),
    "broken json": b'{"v": 1, "state": "ok"',
    "not an object": b"[1]",
    "v=2": _good(v=2),
    "v=true": _good(v=True),
    "extra key": {**_good(), "detail": "x"},
    "missing key": {k: v for k, v in _good().items() if k != "full_ok"},
    "seq as a string": _good(last_anchor_seq="42"),
    "negative seq": _good(last_anchor_seq=-1),
    "negative problem seq": _good(state="broken", problem={"type": "gap", "seq": -1, "kind": None}),
    "true instead of int": _good(retired_forced=True),
    "float count": _good(replaced_history=0.0),
    "negative time": _good(checked_at=-1),
    "NaN": json.dumps(_good()).replace('"checked_at": %r' % (NOW - 5), '"checked_at": NaN').encode(),
    "Infinity": json.dumps(_good()).replace('"checked_at": %r' % (NOW - 5), '"checked_at": Infinity').encode(),
    "time as a string": _good(checked_at=str(NOW)),
    "full_ok=false": _good(full_ok=False),
    "full_ok=1": _good(full_ok=1),
    "replaced_history=1 with state ok": _good(replaced_history=1),
    "state OK in capitals": _good(state="OK"),
    "unknown kind": _good(state="broken", problem={"type": "chain_replaced", "seq": None, "kind": "other"}),
    "problem with an extra key": _good(state="broken", problem={"type": "gap", "seq": 1, "kind": None, "x": 1}),
    "ok with a problem": _good(problem={"type": "row_hash", "seq": 3, "kind": None}),
    "state broken": _good(state="broken", problem={"type": "row_hash", "seq": 3, "kind": None}),
    "state unchecked": _good(state="unchecked", problem={"type": "database", "seq": None, "kind": None}),
    "not utf-8": b"\xff\xfe{}",
}


@pytest.mark.parametrize("case", sorted(BAD_CASES))
def test_no_bad_case_is_green(tmp_path, case):
    banner = _banner(tmp_path, BAD_CASES[case])
    assert banner.state in ("broken", "unchecked"), case
    assert banner.label != "OK"


def test_missing_file_is_not_checked(tmp_path):
    banner = st.read_banner(str(tmp_path / "status.json"), NOW, INTERVAL, FULL)
    assert (banner.state, banner.reason, banner.label) == ("unchecked", "missing", "not checked")


def test_symlink_and_directory_are_not_read(tmp_path):
    target = tmp_path / "real.json"
    target.write_text(json.dumps(_good()))
    (tmp_path / "status.json").symlink_to(target)
    assert st.read_banner(str(tmp_path / "status.json"), NOW, INTERVAL, FULL).reason == "invalid"
    (tmp_path / "dir").mkdir()
    assert st.read_banner(str(tmp_path / "dir"), NOW, INTERVAL, FULL).reason == "invalid"


@pytest.mark.parametrize("case, reason", [
    ("stale checked_at", "stale"), ("stale full_checked_at", "stale"), ("future checked_at", "future"),
    ("empty", "invalid"), ("4097 bytes", "invalid"), ("v=2", "invalid"), ("extra key", "invalid"),
])
def test_reasons_of_not_checked(tmp_path, case, reason):
    banner = _banner(tmp_path, BAD_CASES[case])
    assert (banner.state, banner.reason) == ("unchecked", reason)
    assert banner.text == st.UNCHECKED_REASONS[reason]


def test_replaced_history_and_full_ok_false_are_red(tmp_path):
    banner = _banner(tmp_path, _good(replaced_history=1))
    assert (banner.state, banner.reason) == ("broken", "chain_replaced")
    banner = _banner(tmp_path, _good(state="broken", full_ok=False, replaced_history=2,
                                     problem={"type": "chain_replaced", "seq": None, "kind": "reused"}))
    assert (banner.state, banner.reason, banner.kind) == ("broken", "chain_replaced", "reused")


def test_broken_shows_the_text_and_seq(tmp_path):
    banner = _banner(tmp_path, _good(state="broken", full_ok=False,
                                     problem={"type": "row_hash", "seq": 7, "kind": None}))
    assert (banner.state, banner.reason, banner.seq, banner.text) == \
        ("broken", "row_hash", 7, st.INTEGRITY_PROBLEMS["row_hash"])


def test_unknown_type_is_broken_unknown(tmp_path):
    banner = _banner(tmp_path, _good(state="broken", problem={"type": "<script>alert(1)</script>",
                                                              "seq": 1, "kind": None}))
    assert (banner.state, banner.reason, banner.text) == ("broken", "unknown", st.UNKNOWN_PROBLEM)
    assert "<" not in json.dumps(banner.__dict__)
    long = _banner(tmp_path, _good(state="broken", problem={"type": "x" * 65, "seq": 1, "kind": None}))
    assert long.state != "ok"


@pytest.mark.parametrize("reason", ["database", "anchor_dir", "retired"])
def test_database_anchor_dir_and_retired_are_not_checked_not_broken(tmp_path, reason):
    banner = _banner(tmp_path, _good(state="unchecked", problem={"type": reason, "seq": None, "kind": None}))
    assert (banner.state, banner.reason, banner.label) == ("unchecked", reason, "not checked")


def test_every_whitelisted_type_has_a_text():
    assert set(anchor.PROBLEM_TYPES) == set(st.INTEGRITY_PROBLEMS)
    assert set(anchor.UNCHECKED_REASONS) <= set(st.UNCHECKED_REASONS)
    assert set(st.UNCHECKED_REASONS) == {"database", "anchor_dir", "retired", "stale", "missing", "invalid",
                                         "future"}
    for text in [*st.INTEGRITY_PROBLEMS.values(), *st.UNCHECKED_REASONS.values(), st.UNKNOWN_PROBLEM]:
        assert text and text.isascii() and "<" not in text and "&" not in text


def test_read_banner_never_raises(tmp_path, monkeypatch):
    def boom(*args):
        raise RuntimeError("x")
    monkeypatch.setattr(st, "_read", boom)
    assert st.read_banner(str(tmp_path / "status.json"), NOW, INTERVAL, FULL).state == "unchecked"


@pytest.mark.parametrize("value, expected", [("10", 10), ("3600", 3600), ("9", 60), ("abc", 60), ("", 60)])
def test_api_interval_from_its_own_environment(monkeypatch, value, expected):
    monkeypatch.setenv("CLINIC_AUDIT_ANCHOR_INTERVAL", value)
    assert st.env_seconds("CLINIC_AUDIT_ANCHOR_INTERVAL", st.INTERVAL_DEFAULT, st.INTERVAL_RANGE) == expected


def test_template_prints_only_banner_fields_without_safe():
    html = (ROOT / "app" / "templates" / "admin_audit.html").read_text()
    assert "|safe" not in html.replace(" ", "") and "autoescape false" not in html
    block = html[html.index("{% if integrity %}"):html.index("{% endif %}\n<div class=\"card mb-3\">")]
    for name in re.findall(r"integrity\.(\w+)", block):
        assert name in {"state", "label", "text", "seq", "kind", "checked_at", "full_checked_at",
                        "anchored_at", "last_anchor_seq", "retired_forced", "retired_offline"}, name
    assert "Log integrity:" in block and "make audit-verify" in block


def test_route_reads_the_banner_after_the_role_check():
    source = (ROOT / "app" / "routes_admin.py").read_text()
    body = source[source.index("def admin_audit("):source.index('@router.get("/admin/users")')]
    assert body.index('require_user(request, "admin")') < body.index("read_banner(")
    assert '"Cache-Control": "no-store"' in body


# --- live: the page on the running stand -------------------------------------------

def _client(**kwargs):
    return CsrfClient(base_url=BASE, timeout=30.0, **kwargs)


def _login(c, email):
    page = c.post("/login", data={"email": email, "password": PASSWORD}, follow_redirects=True)
    assert page.status_code == 200 and page.url.path == "/me", (email, page.status_code)


def _compose(*args, timeout=120) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", "compose", *args], cwd=ROOT, capture_output=True, text=True,
                          timeout=timeout)


def _anchor_env(name: str, default: int) -> int:
    done = _compose("config", "--format", "json")
    assert done.returncode == 0, done.stderr
    value = json.loads(done.stdout)["services"]["audit_anchor"]["environment"].get(name)
    return int(value) if value and str(value).isdigit() else default


def _audit_page(c) -> httpx.Response:
    page = c.get("/admin/audit")
    assert page.status_code == 200, page.status_code
    return page


def _state(page) -> str:
    found = re.search(r'data-integrity="(ok|broken|unchecked)"', page.text)
    assert found, "no banner"
    return found.group(1)


def _wait_state(want: str, seconds: float, text: str | None = None) -> httpx.Response:
    deadline = time.time() + seconds
    with _client() as c:
        _login(c, ADMIN)
        while True:
            page = _audit_page(c)
            if _state(page) == want and (text is None or text in page.text):
                return page
            assert time.time() < deadline, (want, text, _state(page), _banner_text(page))
            time.sleep(5)


def _banner_text(page) -> str:
    start = page.text.find("data-integrity=")
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page.text[start:start + 2500]))[:600]


def test_admin_sees_the_banner_without_secrets():
    every = _anchor_env("CLINIC_AUDIT_ANCHOR_INTERVAL", 60)
    page = _wait_state("ok", 2 * every + 60)
    assert "Log integrity: OK" in page.text
    assert "no-store" in page.headers.get("cache-control", "")
    banner = _banner_text(page)
    assert "Last check:" in banner and "Last full check:" in banner and "Last anchor: seq" in banner
    assert not re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", banner)
    assert not re.search(r"[0-9a-f]{64}", banner) and "/anchors" not in banner and "/status" not in banner


@pytest.mark.parametrize("role", sorted(OTHERS))
def test_other_roles_get_403_without_the_banner(role):
    with _client() as c:
        _login(c, OTHERS[role])
        page = c.get("/admin/audit")
    assert page.status_code == 403 and "Log integrity" not in page.text


def test_guest_is_sent_to_login_without_the_banner():
    with _client() as c:
        page = c.get("/admin/audit")
    assert page.status_code == 303 and page.headers["location"].endswith("/login")
    assert "Log integrity" not in page.text


def test_api_mounts_the_status_read_only_and_has_no_audit_secrets():
    touched = _compose("exec", "-T", "api", "sh", "-c", "touch /audit_status/x")
    assert touched.returncode != 0, touched.stdout
    config = json.loads(_compose("config", "--format", "json").stdout)["services"]
    mounts = {v["target"]: v for v in config["api"]["volumes"]}
    assert set(mounts) == {"/audit_status"} and mounts["/audit_status"].get("read_only") is True
    writer = {v["target"]: v for v in config["audit_anchor"]["volumes"]}
    assert mounts["/audit_status"]["source"] == writer["/status"]["source"] == "audit_status"
    assert writer["/status"].get("read_only") is not True
    listed = _compose("exec", "-T", "api", "ls", "/run/secrets")
    assert listed.returncode == 0, listed.stderr
    assert "audit_anchor_key" not in listed.stdout and "audit_db_password" not in listed.stdout
    assert _compose("exec", "-T", "api", "test", "-e", "/anchors").returncode != 0
    readable = _compose("exec", "-T", "api", "test", "-r", "/audit_status/status.json")
    assert readable.returncode == 0


def test_rendered_banner_escapes_an_unknown_type():
    """The template itself, rendered in the api image with a hostile type."""
    script = (
        "import json, audit_status as st\n"
        "from db import templates\n"
        "class U: path = '/admin/audit'\n"
        "class R: url = U()\n"
        "open('/tmp/s.json', 'w').write(json.dumps({'v': 1, 'state': 'broken', 'checked_at': 1.0,"
        " 'full_checked_at': 1.0, 'full_ok': False, 'anchored_at': None, 'last_anchor_seq': None,"
        " 'problem': {'type': '<script>alert(1)</script>', 'seq': 1, 'kind': None},"
        " 'retired_forced': 0, 'retired_offline': 0, 'replaced_history': 0}))\n"
        "b = st.read_banner('/tmp/s.json', 2.0, 60, 600)\n"
        "print(templates.get_template('admin_audit.html').render(request=R(), role=None, integrity=b,"
        " events=[], errors=[], filters={}, actions=[], action_prefixes=[], actor_roles=[],"
        " target_types=[], older_page=False, newest_url='/admin/audit', next_url=None))\n"
    )
    done = _compose("exec", "-T", "api", "python", "-c", script)
    assert done.returncode == 0, done.stderr[-2000:]
    assert "Log integrity: BROKEN" in done.stdout and st.UNKNOWN_PROBLEM in done.stdout
    assert "<script" not in done.stdout.split("data-integrity=")[1].split("</div>\n<div class=\"card")[0]
    assert "alert(1)" not in done.stdout


# --- live, -p e6 only: grey and red ------------------------------------------------

E6_ONLY = pytest.mark.skipif(PROJECT != "e6", reason="only on the disposable stand -p e6")


@E6_ONLY
def test_e6_banner_is_not_checked_when_audit_anchor_stops():
    every = _anchor_env("CLINIC_AUDIT_ANCHOR_INTERVAL", 60)
    _wait_state("ok", 2 * every + 120)
    assert _compose("stop", "audit_anchor").returncode == 0
    try:
        page = _wait_state("unchecked", 3 * every + 60 + 60, st.UNCHECKED_REASONS["stale"])
        assert "Log integrity: not checked" in page.text
    finally:
        assert _compose("start", "audit_anchor").returncode == 0
    _wait_state("ok", 2 * every + 60)


def _psql(sql: str) -> list[str]:
    done = _compose("exec", "-T", "db", "psql", "-X", "-q", "-U", "clinic", "-d", "clinic",
                    "-v", "ON_ERROR_STOP=1", "-At", "-c", sql)
    assert done.returncode == 0, done.stderr
    return [line for line in done.stdout.splitlines() if line.strip()]


@E6_ONLY
def test_e6_changed_row_before_the_last_anchor_turns_the_banner_red():
    """A superuser change of an old row (hashes left alone) is not seen by the
    incremental step; the full check (CLINIC_AUDIT_FULL_CHECK_EVERY=60 in the
    e6 env) turns the banner red with row_hash and the seq within 10 min +
    one interval."""
    sys.path.insert(0, str(ROOT / "experiments"))
    import e6_tamper  # noqa: E402

    every = _anchor_env("CLINIC_AUDIT_ANCHOR_INTERVAL", 60)
    full = _anchor_env("CLINIC_AUDIT_FULL_CHECK_EVERY", 600)
    page = _wait_state("ok", 2 * every + 120)
    anchored = int(re.search(r"Last anchor: seq (\d+)", _banner_text(page)).group(1))
    assert anchored >= 2, anchored
    seq = anchored // 2
    _psql(e6_tamper.superuser_sql(e6_tamper.change_row_sql(seq)))
    page = _wait_state("broken", full + every + 60, f"{st.INTEGRITY_PROBLEMS['row_hash']} at seq {seq}")
    assert "Log integrity: BROKEN" in page.text


@E6_ONLY
def test_e6_banner_stays_red_after_chain_replaced_and_a_forced_reset():
    every = _anchor_env("CLINIC_AUDIT_ANCHOR_INTERVAL", 60)
    full = _anchor_env("CLINIC_AUDIT_FULL_CHECK_EVERY", 600)
    old = _psql("SELECT chain_id FROM audit_chain_head")[0]
    for args in (["down", "-v"], ["up", "-d"]):      # the volume dropped behind make's back
        done = _compose(*args, timeout=1200)
        assert done.returncode == 0, done.stderr[-2000:]
    deadline = time.time() + 300
    while True:
        head = _compose("exec", "-T", "db", "psql", "-X", "-q", "-U", "clinic", "-d", "clinic", "-At", "-c",
                        "SELECT chain_id FROM audit_chain_head")
        if head.returncode == 0 and head.stdout.strip():
            break
        assert time.time() < deadline
        time.sleep(3)
    assert head.stdout.strip() != old
    _wait_state("broken", 2 * every + 120, st.INTEGRITY_PROBLEMS["chain_replaced"])
    forced = subprocess.run(["make", "reset", "CONFIRM=yes", "RETIRE_FORCE=yes", "COMPOSE=docker compose"],
                            cwd=ROOT, capture_output=True, text=True, timeout=1800)
    assert forced.returncode == 0, forced.stdout[-3000:] + forced.stderr[-3000:]
    page = _wait_state("broken", 2 * every + 180, st.INTEGRITY_PROBLEMS["chain_replaced"])
    time.sleep(full + every)          # a later full check does not turn it green
    page = _wait_state("broken", 60, st.INTEGRITY_PROBLEMS["chain_replaced"])
    assert "Log integrity: BROKEN" in page.text
