"""E6 audit-chain tamper test; disposable stand only."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import random
import re
import subprocess
import sys
import time
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
PROJECT = "e6"

sys.path.insert(0, str(ROOT / "tests"))
import anchor_volume  # noqa: E402  (reads the anchors through audit_anchor)
FORBIDDEN_PORTS = {8080, 8082, 8083, 8450, 8452, 8453, 8025, 8027, 8028, 1025, 1027, 1028}
PORTS = {"http": 8086, "https": 8456, "mail_ui": 8030, "smtp": 1030}
TZ = ZoneInfo("Asia/Yerevan")
TRIGGERS = (
    ("audit_events", "zz_audit_chain"),
    ("audit_events", "audit_events_no_update_delete"),
    ("audit_events", "audit_events_no_truncate"),
    ("audit_chain_head", "audit_chain_head_guard"),
    ("audit_chain_head", "audit_chain_head_no_delete"),
    ("audit_chain_head", "audit_chain_head_no_truncate"),
)
LOG: list[str] = []
LOG_PATH: Path | None = None


def now() -> str:
    return dt.datetime.now(TZ).strftime("%Y-%m-%d %H:%M:%S %Z")


def log(text: str) -> None:
    line = f"[{now()}] {text}"
    print(line, flush=True)
    LOG.append(line)
    if LOG_PATH:
        with LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")


# Prevent access to another stand.

def env_file_value(path: Path, name: str) -> str | None:
    value = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith(f"{name}="):
            value = line.split("=", 1)[1]
    return value


def guard(env_path: Path) -> None:
    anchor = env_file_value(env_path, "CLINIC_AUDIT_ANCHOR_VOLUME")
    if not anchor:
        raise SystemExit("guard: CLINIC_AUDIT_ANCHOR_VOLUME is not set in .env.e6")
    if not anchor.startswith(f"{PROJECT}_audit_anchors_"):
        raise SystemExit(f"guard: the e6 anchor volume {anchor} is not an {PROJECT}_audit_anchors_<stamp> volume")
    for name in ("CLINIC_PROXY_PORT", "CLINIC_PROXY_TLS_PORT"):
        port = int(env_file_value(env_path, name) or 0)
        if port in FORBIDDEN_PORTS or not port:
            raise SystemExit(f"guard: {name}={port} belongs to another stand")
    mail = (ROOT / "docker-compose.e6.yml").read_text()
    for port in re.findall(r"127\.0\.0\.1:(\d+):", mail):
        if int(port) in FORBIDDEN_PORTS:
            raise SystemExit(f"guard: mailpit port {port} belongs to another stand")


def ports_free() -> None:
    listening = subprocess.run(["ss", "-ltn"], capture_output=True, text=True).stdout
    published = subprocess.run(["docker", "ps", "--format", "{{.Ports}}"], capture_output=True, text=True).stdout
    for port in PORTS.values():
        if re.search(rf":{port}\b", listening) or re.search(rf":{port}->", published):
            raise SystemExit(f"port {port} is busy: pick other ports and record them in the report")


def compose(*args, check=True, timeout=900, quiet=False) -> subprocess.CompletedProcess:
    cmd = ["docker", "compose", "--env-file", ".env.e6", "-p", PROJECT,
           "-f", "docker-compose.yml", "-f", "docker-compose.e6.yml", *args]
    done = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    if check and done.returncode != 0:
        raise RuntimeError(f"compose {' '.join(args[:3])} failed: {done.stderr[-1500:]}")
    return done


def psql(sql: str, check=True) -> list[str]:
    done = compose("exec", "-T", "db", "psql", "-X", "-q", "-U", "clinic", "-d", "clinic",
                   "-v", "ON_ERROR_STOP=1", "-At", "-F", "|", "-c", sql, check=False, timeout=600)
    if check and done.returncode != 0:
        raise RuntimeError(f"psql failed: {done.stderr[-800:]}")
    return [line for line in done.stdout.splitlines() if line.strip()]


def once() -> str:
    done = compose("exec", "-T", "audit_anchor", "python", "anchor.py", "--once", check=False)
    return (done.stdout.strip().splitlines() or [""])[-1]


def verify(strict=False) -> tuple[int, list[str]]:
    args = ["exec", "-T", "audit_anchor", "python", "verify_audit.py"] + (["--strict"] if strict else [])
    done = compose(*args, check=False)
    return done.returncode, done.stdout.strip().splitlines()


def registry_kinds() -> list[str]:
    path = anchor_volume.snapshot() / "chains.log"
    return [line.split()[1] + (f" {line.split()[4]}" if line.split()[1] == "switch" else "")
            for line in path.read_text().splitlines()] if path.exists() else []


def trigger_modes() -> dict:
    rows = psql("SELECT c.relname || '.' || t.tgname, t.tgenabled::text FROM pg_trigger t "
                "JOIN pg_class c ON c.oid = t.tgrelid WHERE c.relname IN ('audit_events', 'audit_chain_head') "
                "AND NOT t.tgisinternal")
    return dict(r.split("|") for r in rows)


def enable_always() -> str:
    return "".join(f"ALTER TABLE public.{t} ENABLE ALWAYS TRIGGER {n}; " for t, n in TRIGGERS)


def superuser_sql(sql: str) -> str:
    """Disable triggers for tampering; restore ALWAYS mode."""
    return ("BEGIN; ALTER TABLE public.audit_events DISABLE TRIGGER USER; "
            "ALTER TABLE public.audit_chain_head DISABLE TRIGGER USER; "
            f"{sql}; {enable_always()} COMMIT;")


def as_superuser(sql: str) -> list[str]:
    return psql(superuser_sql(sql))


def change_row_sql(seq: int) -> str:
    """Change one row; leave hashes for row_hash detection."""
    return f"UPDATE public.audit_events SET action = action || '.x' WHERE seq = {int(seq)}"


def dump() -> None:
    psql("DROP SCHEMA IF EXISTS e6 CASCADE; CREATE SCHEMA e6; "
         "CREATE TABLE e6.ev AS SELECT * FROM public.audit_events; "
         "CREATE TABLE e6.head AS SELECT * FROM public.audit_chain_head;")


def restore() -> None:
    as_superuser("DELETE FROM public.audit_events; INSERT INTO public.audit_events SELECT * FROM e6.ev; "
                 "DELETE FROM public.audit_chain_head; INSERT INTO public.audit_chain_head SELECT * FROM e6.head")


def head() -> tuple[str, int]:
    chain, last = psql("SELECT chain_id, last_seq FROM audit_chain_head")[0].split("|")
    return chain, int(last)


def up_and_wait_head(timeout=600) -> None:
    """Wait for migration; anchor may be unhealthy."""
    compose("up", "-d", timeout=timeout)
    deadline = time.time() + timeout
    while time.time() < deadline:
        state = compose("ps", "-a", "--format", "{{.State}} {{.ExitCode}}", "migrate", check=False).stdout.strip()
        if state.startswith("exited") and psql("SELECT count(*) FROM audit_chain_head", check=False) == ["1"]:
            return
        time.sleep(3)
    raise RuntimeError("migrate did not finish or no chain head")


def wait_healthy(want: str, timeout=200) -> str:
    deadline, state = time.time() + timeout, ""
    while time.time() < deadline:
        state = compose("ps", "--format", "{{.Health}}", "audit_anchor", check=False).stdout.strip()
        if state == want:
            return state
        time.sleep(5)
    return state


def generate(total: int, rng: random.Random) -> dict:
    from tests.csrf_client import CsrfClient
    from tests.demo_secret import demo_password

    base = f"https://localhost:{PORTS['https']}"
    ca = str(ROOT / "secrets" / "tls" / "ca.crt")
    password = demo_password()  # read from secrets/demo_password, never printed
    counts = {"http_login": 0, "http_failed": 0, "sql": 0}
    for i in range(40):
        email = ("admin@clinic.local", "pat@clinic.local")[i % 2]
        with CsrfClient(base_url=base, verify=ca, follow_redirects=True, timeout=20.0) as c:
            if c.post("/login", data={"email": email, "password": password}).status_code == 200:
                counts["http_login"] += 1
            c.post("/logout")
    for i in range(15):
        with CsrfClient(base_url=base, verify=ca, follow_redirects=True, timeout=20.0) as c:
            c.post("/login", data={"email": f"nobody-e6-{i}@clinic.local", "password": "Wrong-Password-2026!"})
            counts["http_failed"] += 1
    have = int(psql("SELECT count(*) FROM audit_events")[0])
    need = max(0, total - have)
    admin = psql("SELECT id FROM users WHERE email = 'admin@clinic.local'")[0]
    actions = ["appointment.cancel", "appointment.reschedule", "visit_note.create", "service.update",
               "user.block", "settings.update"]
    for start in range(0, need, 50):
        values = []
        for _ in range(min(50, need - start)):
            reason = "'login'" if rng.random() < 0.4 else "NULL"
            source = "'127.0.0.1'" if rng.random() < 0.5 else "NULL"
            target = str(rng.randint(1, 500)) if rng.random() < 0.7 else "NULL"
            values.append(f"({admin}, 'admin', '{rng.choice(actions)}', 'e6', {target}, {reason}, {source})")
        psql("INSERT INTO audit_events (actor_user_id, actor_role, action, target_type, target_id, reason, source) "
             "VALUES " + ", ".join(values))
        counts["sql"] += len(values)
    counts["rows"] = int(psql("SELECT count(*) FROM audit_events")[0])
    return counts


def rows_meta() -> list[dict]:
    out = []
    for line in psql("SELECT seq, id, reason IS NULL, source IS NULL, target_id IS NULL FROM audit_events ORDER BY seq"):
        seq, rid, rn, sn, tn = line.split("|")
        out.append({"seq": int(seq), "id": int(rid), "reason_null": rn == "t", "source_null": sn == "t",
                    "target_null": tn == "t"})
    return out


def anchors_seq() -> list[int]:
    chain, _ = head()
    path = anchor_volume.snapshot() / f"{chain}.log"
    return [int(line.split()[2]) for line in path.read_text().splitlines()] if path.exists() else []


def recompute_suffix(seq: int) -> str:
    return f"""
UPDATE public.audit_events SET action = action || '.x' WHERE seq = {seq};
DO $$
DECLARE r record; prev bytea;
BEGIN
  SELECT row_hash INTO prev FROM public.audit_events WHERE seq = {seq} - 1;
  IF prev IS NULL THEN
    SELECT public.audit_genesis_hash_v1(chain_id) INTO prev FROM public.audit_chain_head;
  END IF;
  FOR r IN SELECT * FROM public.audit_events WHERE seq >= {seq} ORDER BY seq LOOP
    UPDATE public.audit_events SET prev_hash = prev,
      row_hash = public.audit_row_hash_v1(prev, public.audit_canon_v1(r.seq, r.id, r.created_at,
        r.actor_user_id, r.actor_role, r.action, r.target_type, r.target_id, r.reason, r.source,
        r.old_value, r.new_value))
      WHERE seq = r.seq RETURNING row_hash INTO prev;
  END LOOP;
  UPDATE public.audit_chain_head SET last_hash = prev;
END $$"""


def plan_tamperings(rng: random.Random, meta: list[dict]) -> list[dict]:
    n = meta[-1]["seq"]
    middle = [m for m in meta if 10 <= m["seq"] <= n - 10]
    pick = lambda cond=lambda m: True: rng.choice([m for m in middle if cond(m)])  # noqa: E731
    cases = []

    def add(kind, field, seq, sql, expect_type, expect_seq):
        cases.append({"kind": kind, "field": field, "seq": seq, "sql": sql,
                      "expect_type": expect_type, "expect_seq": expect_seq})

    m = pick(); add("update", "created_at", m["seq"],
                    f"UPDATE public.audit_events SET created_at = created_at + interval '1 second' WHERE seq = {m['seq']}",
                    "row_hash", m["seq"])
    m = pick(); add("update", "action", m["seq"],
                    f"UPDATE public.audit_events SET action = 'appointment.cancel.x' WHERE seq = {m['seq']}",
                    "row_hash", m["seq"])
    m = pick(); add("update", "actor_user_id", m["seq"],
                    f"UPDATE public.audit_events SET actor_user_id = actor_user_id + 1 WHERE seq = {m['seq']}",
                    "row_hash", m["seq"])
    m = pick(lambda m: m["reason_null"]); add("update", "reason NULL->value", m["seq"],
                    f"UPDATE public.audit_events SET reason = 'blocked' WHERE seq = {m['seq']}", "row_hash", m["seq"])
    m = pick(lambda m: not m["reason_null"]); add("update", "reason value->NULL", m["seq"],
                    f"UPDATE public.audit_events SET reason = NULL WHERE seq = {m['seq']}", "row_hash", m["seq"])
    m = pick(lambda m: m["source_null"]); add("update", "source NULL->value", m["seq"],
                    f"UPDATE public.audit_events SET source = '10.0.0.1' WHERE seq = {m['seq']}", "row_hash", m["seq"])
    m = pick(lambda m: not m["target_null"]); add("update", "target_id value->NULL", m["seq"],
                    f"UPDATE public.audit_events SET target_id = NULL WHERE seq = {m['seq']}", "row_hash", m["seq"])
    m = pick(lambda m: m["target_null"]); add("update", "target_id NULL->value", m["seq"],
                    f"UPDATE public.audit_events SET target_id = 7 WHERE seq = {m['seq']}", "row_hash", m["seq"])
    used = set()
    for _ in range(4):
        m = pick(lambda m: m["seq"] not in used); used.add(m["seq"])
        add("delete", "middle row", m["seq"], f"DELETE FROM public.audit_events WHERE seq = {m['seq']}",
            "gap", m["seq"])
    for k in (1, rng.randint(2, 20)):
        add("delete", f"tail {k} rows", n - k + 1, f"DELETE FROM public.audit_events WHERE seq > {n - k}",
            "truncated", n - k + 1)
    for k in (1, rng.randint(2, 20)):
        add("delete", f"tail {k} rows + head", n - k + 1,
            f"DELETE FROM public.audit_events WHERE seq > {n - k}; "
            f"UPDATE public.audit_chain_head SET last_seq = {n - k}, "
            f"last_hash = (SELECT row_hash FROM public.audit_events WHERE seq = {n - k})",
            "truncated", n - k + 1)
    for _ in range(2):
        m = pick(); add("recompute", "SHA suffix + head", m["seq"], recompute_suffix(m["seq"]),
                        "anchor_mismatch", None)
    add("truncate", "TRUNCATE (triggers off)", 1, "TRUNCATE public.audit_events", "truncated", 1)
    a = pick(); b = pick(lambda m: m["seq"] > a["seq"])
    add("swap", f"seq {a['seq']}<->{b['seq']}", a["seq"],
        f"UPDATE public.audit_events SET seq = {n + 1000} WHERE seq = {a['seq']}; "
        f"UPDATE public.audit_events SET seq = {a['seq']} WHERE seq = {b['seq']}; "
        f"UPDATE public.audit_events SET seq = {b['seq']} WHERE seq = {n + 1000}", "prev_hash", a["seq"])
    assert len(cases) == 20
    return cases


def parse_broken(lines: list[str]) -> dict:
    line = next((l for l in lines if l.startswith("BROKEN")), "")
    found = dict(re.findall(r"(\w+)=(\S+)", line))
    return {"line": line, "type": found.get("type"), "seq": int(found["seq"]) if found.get("seq", "-").isdigit() else None,
            "id": found.get("id")}


def run_tamperings(rng: random.Random) -> list[dict]:
    results = []
    cases = plan_tamperings(rng, rows_meta())
    for number, case in enumerate(cases, 1):
        anchored = once()
        dump()
        anchors = anchors_seq()
        if case["expect_seq"] is None:
            case["expect_seq"] = min(s for s in anchors if s >= case["seq"])
        as_superuser(case["sql"])
        code, lines = verify()
        broken = parse_broken(lines)
        found = code != 0 and broken["type"] == case["expect_type"] and broken["seq"] == case["expect_seq"]
        restore()
        modes = trigger_modes()
        code_after, lines_after = verify()
        restored = code_after == 0 and all(v == "A" for v in modes.values()) and len(modes) == 6
        results.append({**{k: case[k] for k in ("kind", "field", "seq", "expect_type", "expect_seq")},
                        "number": number, "rc": code, "got_type": broken["type"], "got_seq": broken["seq"],
                        "got_id": broken["id"], "found": found, "restored": restored})
        log(f"tamper {number:2d} {case['kind']:9s} {case['field']:24s} seq={case['seq']} -> rc={code} "
            f"{broken['line'] or '(no BROKEN line)'} | expected type={case['expect_type']} "
            f"seq={case['expect_seq']} found={found} | restore verify rc={code_after} "
            f"modes={'A' if restored else modes} [{anchored.split(' (')[0]}]")
        if not restored:
            raise RuntimeError(f"restore after tampering {number} failed: {lines_after[-1:]}")
    return results


def perf(rows: int) -> dict:
    have = int(psql("SELECT count(*) FROM audit_events")[0])
    admin = psql("SELECT id FROM users WHERE email = 'admin@clinic.local'")[0]
    start = time.time()
    psql(f"INSERT INTO audit_events (actor_user_id, actor_role, action, target_type, target_id) "
         f"SELECT {admin}, 'admin', 'perf.event', 'e6', g FROM generate_series(1, {rows - have}) g")
    insert_s = time.time() - start
    once()
    code = ("import resource, time, sys; sys.argv = ['verify_audit.py']; import verify_audit as v; "
            "t = time.time(); rc = v.main([]); "
            "print('PERF rc=%d seconds=%.2f maxrss_mb=%.1f' % (rc, time.time() - t, "
            "resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024))")
    done = compose("exec", "-T", "audit_anchor", "python", "-c", code, check=False)
    line = next((l for l in done.stdout.splitlines() if l.startswith("PERF")), "PERF failed")
    return {"rows": int(psql("SELECT count(*) FROM audit_events")[0]), "insert_s": round(insert_s, 1),
            "insert_rows": rows - have, "verify": line}


def main() -> int:
    global LOG_PATH
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--disposable-stand", required=True)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--events", type=int, default=520)
    parser.add_argument("--perf", type=int, default=0, help="rows for the verify_audit timing (0: skip)")
    parser.add_argument("--keep", action="store_true", help="do not run down -v at the end")
    args = parser.parse_args()
    if args.disposable_stand != PROJECT or os.environ.get("COMPOSE_PROJECT_NAME", PROJECT) != PROJECT:
        raise SystemExit("e6_tamper.py runs only with --disposable-stand e6 (COMPOSE_PROJECT_NAME e6 or unset)")
    seed = args.seed if args.seed is not None else int(time.time())
    rng = random.Random(seed)
    stamp = dt.datetime.now(TZ).strftime("%Y%m%d-%H%M")
    anchor_volume_name = f"{PROJECT}_audit_anchors_{stamp}"
    env = [line for line in (ROOT / ".env.example").read_text().splitlines()
           if line and not line.startswith("#") and not line.startswith(("NGROK_DOMAIN=", "PUBLIC_BASE_URL="))]
    env += [f"PUBLIC_BASE_URL=https://localhost:{PORTS['https']}", "CLINIC_PROXY_BIND=127.0.0.1",
            f"CLINIC_PROXY_PORT={PORTS['http']}", f"CLINIC_PROXY_TLS_PORT={PORTS['https']}",
            f"HOST_UID={os.getuid()}", f"HOST_GID={os.getgid()}",
            f"CLINIC_AUDIT_ANCHOR_VOLUME={anchor_volume_name}", "CLINIC_AUDIT_ANCHOR_INTERVAL=60"]
    (ROOT / ".env.e6").write_text("\n".join(env) + "\n")
    guard(ROOT / ".env.e6")
    os.environ.update(COMPOSE_PROJECT_NAME=PROJECT, COMPOSE_ENV_FILES=".env.e6",
                      COMPOSE_FILE="docker-compose.yml:docker-compose.e6.yml")
    ports_free()
    done = subprocess.run(["sh", "scripts/init_secrets.sh"], cwd=ROOT, capture_output=True, text=True)
    if done.returncode != 0:
        raise SystemExit("init_secrets.sh failed")
    # Isolate this stand's anchors.
    made = subprocess.run(["docker", "volume", "create", "--label", "clinic.audit=keep", anchor_volume_name],
                          capture_output=True, text=True)
    if made.returncode != 0:
        raise SystemExit(f"cannot create the e6 anchor volume: {made.stderr.strip()}")
    LOG_PATH = ROOT / "experiments" / f"e6_{stamp}.log"
    report: dict = {"seed": seed, "stamp": stamp, "anchor_volume": anchor_volume_name, "ports": PORTS}
    log(f"E6 start seed={seed} anchors={anchor_volume_name} ports={PORTS}")

    compose("down", "-v", "--remove-orphans")
    compose("up", "--build", "-d", "--wait", timeout=1800)
    log(f"stand up, head chain={head()[0]} rows={head()[1]}")
    log(f"first --once: {once()}")

    compose("stop", "proxy", "api")
    out = compose("exec", "-T", "audit_anchor", "python", "anchor.py", "--retire", check=False)
    log(f"control: retire rc={out.returncode} {out.stdout.strip()}")
    old_chain = head()[0]
    as_superuser("TRUNCATE public.audit_events; DELETE FROM public.audit_chain_head")
    up_and_wait_head()
    new_chain = head()[0]
    log(f"control: once {once()}")
    state = wait_healthy("healthy")
    code, lines = verify()
    kinds = registry_kinds()
    control_ok = (new_chain != old_chain and "switch" not in " ".join(kinds) and kinds[-2:] == ["retire", "open"]
                  and state == "healthy" and code == 0)
    report["control"] = {"old": old_chain, "new": new_chain, "registry": kinds, "health": state,
                         "verify_rc": code, "verify": lines[-1:], "ok": control_ok}
    log(f"control: registry={kinds} health={state} verify rc={code} {lines[-1:]} ok={control_ok}")

    counts = generate(args.events, rng)
    report["events"] = counts
    log(f"generated {counts}")
    log(f"anchor after generation: {once()}")

    test_env = dict(os.environ, COMPOSE_PROJECT_NAME=PROJECT, COMPOSE_ENV_FILES=".env.e6",
                    COMPOSE_FILE="docker-compose.yml:docker-compose.e6.yml",
                    CLINIC_AUDIT_ANCHOR_VOLUME=anchor_volume_name, CLINIC_TEST_BASE=f"https://localhost:{PORTS['https']}",
                    CLINIC_MAILPIT=f"http://127.0.0.1:{PORTS['mail_ui']}",
                    SSL_CERT_FILE=str(ROOT / "secrets" / "tls" / "ca.crt"))
    py = os.environ.get("E6_PYTHON", sys.executable)
    pt = subprocess.run([py, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_audit_chain.py", "-k",
                         "fresh_volume_has_an_empty_genesis or live_twenty_parallel_once"], cwd=ROOT, env=test_env,
                        capture_output=True, text=True, timeout=900)
    report["pytest_e6"] = pt.stdout.strip().splitlines()[-1:] if pt.stdout else [pt.stderr[-300:]]
    if pt.returncode != 0:
        log("pytest e6-only failures: " + " | ".join(l for l in pt.stdout.splitlines() if l.startswith(("E ", "FAILED"))))
    log(f"pytest e6-only (fresh volume, 20 parallel --once next to the loop): {report['pytest_e6']}")

    code, lines = verify()
    report["clean_verify"] = lines[-1:]
    log(f"control run without tampering: rc={code} {lines[-1:]}")
    results = run_tamperings(rng)
    report["tamperings"] = results
    log(f"tamperings found {sum(r['found'] for r in results)}/20, restored {sum(r['restored'] for r in results)}/20")

    if args.perf:
        report["perf"] = perf(args.perf)
        log(f"perf {report['perf']}")

    psql("ALTER TABLE public.audit_events DISABLE TRIGGER zz_audit_chain; "
         "ALTER TABLE public.audit_events ENABLE TRIGGER zz_audit_chain")
    code, lines = verify()
    b6 = parse_broken(lines)
    compose("run", "--rm", "--no-deps", "-T", "migrate")
    code2, lines2 = verify()
    report["b6"] = {"rc": code, "line": b6["line"], "after_migrate_rc": code2, "after": lines2[-1:]}
    log(f"Б6: rc={code} {b6['line']} -> migrate -> rc={code2} {lines2[-1:]}")

    once()
    dump()
    as_superuser("TRUNCATE public.audit_events; DELETE FROM public.audit_chain_head")
    up_and_wait_head()
    log(f"replaced: once {once()}")
    state = wait_healthy("unhealthy", timeout=200)
    code, lines = verify()
    report["replaced_new"] = {"registry": registry_kinds()[-1], "health": state, "rc": code,
                              "line": parse_broken(lines)["line"]}
    log(f"replaced(new): registry={registry_kinds()[-1]} health={state} rc={code} {parse_broken(lines)['line']}")

    restore()
    log(f"reused: once {once()}")
    code, lines = verify()
    report["replaced_reused"] = {"registry": registry_kinds()[-1], "rc": code, "line": parse_broken(lines)["line"]}
    log(f"replaced(reused): registry={registry_kinds()[-1]} rc={code} {parse_broken(lines)['line']}")
    code, lines = verify(strict=True)
    report["strict"] = {"rc": code, "line": lines[-1:]}
    log(f"final verify --strict: rc={code} {lines[-1:]}")

    pt = subprocess.run([py, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_audit_chain.py", "-k",
                         "missing_head_stops_migrate"], cwd=ROOT, env=test_env, capture_output=True, text=True,
                        timeout=900)
    report["pytest_missing_head"] = pt.stdout.strip().splitlines()[-1:]
    if pt.returncode != 0:
        log("pytest e6-only failures: " + " | ".join(l for l in pt.stdout.splitlines() if l.startswith(("E ", "FAILED"))))
    log(f"pytest e6-only (missing head stops migrate): {report['pytest_missing_head']}")

    (ROOT / "experiments" / f"e6_{stamp}.json").write_text(json.dumps(report, indent=2, default=str))
    if not args.keep:
        compose("down", "-v", "--remove-orphans")
        log("stand e6 removed (down -v); anchor directory kept")
    passed = lambda lines: bool(lines) and " passed" in lines[-1] and "failed" not in lines[-1]  # noqa: E731
    ok = (control_ok and all(r["found"] and r["restored"] for r in results)
          and report["b6"]["after_migrate_rc"] == 0 and "trigger_mode" in report["b6"]["line"]
          and report["replaced_new"]["registry"] == "switch new" and report["replaced_new"]["rc"] != 0
          and report["replaced_reused"]["registry"] == "switch reused" and report["replaced_reused"]["rc"] != 0
          and report["strict"]["rc"] != 0
          and passed(report["pytest_e6"]) and passed(report["pytest_missing_head"]))
    log(f"E6 done ok={ok}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
