"""Plan 18.3: views of the admin journal are journaled (audit.view).

One event per view: the admin, target audit_log, target_id = the bit mask of
the filters used (1 action, 2 actor_role, 4 actor, 8 target_type, 16
target_id, 32 from, 64 to), never a filter value. The same mask by the same
admin is written again only after public.audit_view_window() (10 minutes)
since the last written one. If the view cannot be written, the journal is not
shown (503). The e2e flow uses a fresh admin account, so the window of
earlier runs does not matter; the window itself and the failed write are
tested on the disposable stand -p e6 only."""
import os
import re
import subprocess
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

import pytest

from tests.csrf_client import CsrfClient
from tests.demo_secret import demo_password

ROOT = Path(__file__).resolve().parents[1]
BASE = os.environ.get("CLINIC_TEST_BASE", "https://localhost:8450")
PROJECT = os.environ.get("COMPOSE_PROJECT_NAME", "")
PASSWORD = demo_password()
ADMIN = "admin@clinic.local"
PAT = "pat@clinic.local"
OTHERS = {"app_patient": PAT, "app_doctor": "doc@clinic.local", "app_registrar": "reg@clinic.local"}
COLUMNS = ("actor_user_id", "actor_role", "action", "target_type", "target_id", "reason", "source",
           "old_value", "new_value")


def _psql_try(sql: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "exec", "-T", "db", "psql", "-X", "-q", "-U", "clinic", "-d", "clinic",
         "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose", "-At", "-F", "|", "-c", sql],
        cwd=ROOT, capture_output=True, text=True, timeout=120,
    )


def _psql(sql: str) -> list[str]:
    done = _psql_try(sql)
    assert done.returncode == 0, done.stderr or done.stdout
    return [line for line in done.stdout.splitlines() if line.strip()]


def _user_id(email: str) -> int:
    return int(_psql(f"SELECT id FROM users WHERE email = '{email}'")[0])


def _as_role(role: str, user_id: int, sql: str) -> subprocess.CompletedProcess:
    return _psql_try(f"BEGIN; SET LOCAL ROLE {role}; "
                     f"SELECT set_config('app.user_id', '{user_id}', true); {sql}; ROLLBACK;")


def _views(admin_id: int, mark: int) -> list[str]:
    return _psql(f"SELECT target_id FROM audit_events WHERE id > {mark} AND action = 'audit.view' "
                 f"AND actor_user_id = {admin_id} ORDER BY id")


def _mark() -> int:
    return int(_psql("SELECT coalesce(max(id), 0) FROM audit_events")[0])


def _client(**kwargs):
    return CsrfClient(base_url=BASE, timeout=30.0, **kwargs)


def _login(c, email):
    page = c.post("/login", data={"email": email, "password": PASSWORD}, follow_redirects=True)
    assert page.status_code == 200 and page.url.path == "/me", (email, page.status_code)


@pytest.fixture
def fresh_admin():
    """A new admin with the demo password (copy of the admin's hash), removed
    afterwards; its journal events stay (no foreign key, plan 17 Р6)."""
    email = f"view-admin-{uuid.uuid4().hex[:12]}@example.test"
    admin_id = int(_psql(
        "INSERT INTO users (email, password_hash, role, blocked, email_verified_at) "
        f"VALUES ('{email}', (SELECT password_hash FROM users WHERE email = '{ADMIN}'), 'admin', false, now()) "
        "RETURNING id")[0])
    try:
        yield email, admin_id
    finally:
        _psql(f"DELETE FROM login_attempts WHERE email_fingerprint = public.digest('{email}', 'sha256'); "
              f"DELETE FROM users WHERE id = {admin_id}")


# --- SQL: the function and its grants ----------------------------------------------

@pytest.mark.parametrize("role", sorted(OTHERS))
def test_record_audit_view_is_refused_to_other_roles(role):
    done = _as_role(role, _user_id(OTHERS[role]), "SELECT public.record_audit_view(0)")
    assert done.returncode != 0 and "42501" in done.stderr, (role, done.stderr)


def test_record_audit_view_needs_the_admin_context():
    no_context = _psql_try("BEGIN; SET LOCAL ROLE clinic_api; SELECT public.record_audit_view(0); ROLLBACK;")
    assert no_context.returncode != 0 and "42501" in no_context.stderr, no_context.stderr
    not_admin = _as_role("app_admin", _user_id(PAT), "SELECT public.record_audit_view(0)")
    assert not_admin.returncode != 0 and "42501" in not_admin.stderr, not_admin.stderr
    no_user = _psql_try("BEGIN; SET LOCAL ROLE app_admin; SELECT public.record_audit_view(0); ROLLBACK;")
    assert no_user.returncode != 0 and "42501" in no_user.stderr, no_user.stderr


@pytest.mark.parametrize("mask", ["-1", "128", "NULL"])
def test_record_audit_view_refuses_a_bad_mask(mask):
    done = _as_role("app_admin", _user_id(ADMIN), f"SELECT public.record_audit_view({mask})")
    assert done.returncode != 0 and "22023" in done.stderr, (mask, done.stderr)


def test_only_app_admin_may_execute_and_nobody_the_window():
    for role in ("public", "clinic_api", "clinic_auditor", "app_guest", "app_patient", "app_doctor",
                 "app_registrar", "app_admin"):
        view, window = _psql(
            f"SELECT has_function_privilege('{role}', 'public.record_audit_view(integer)', 'EXECUTE')::text "
            f"|| '|' || has_function_privilege('{role}', 'public.audit_view_window()', 'EXECUTE')::text"
        )[0].split("|")
        assert (view, window) == ("true" if role == "app_admin" else "false", "false"), role
    grantees = _psql("SELECT routine_name || ':' || grantee FROM information_schema.routine_privileges "
                     "WHERE routine_name IN ('record_audit_view', 'audit_view_window') "
                     "AND privilege_type = 'EXECUTE' AND grantee <> 'clinic' ORDER BY 1")
    assert grantees == ["record_audit_view:app_admin"]
    definer = _psql("SELECT proname || '|' || prosecdef::text || '|' || provolatile::text || '|' "
                    "|| array_to_string(proconfig, ',') FROM pg_proc "
                    "WHERE proname IN ('record_audit_view', 'audit_view_window') ORDER BY 1")
    assert definer == ["audit_view_window|false|s|search_path=pg_catalog, public, pg_temp",
                       "record_audit_view|true|v|search_path=pg_catalog, public, pg_temp"]
    assert _psql("SELECT public.audit_view_window()::text") == ["00:10:00"]
    assert _psql("SELECT count(*) FROM pg_indexes WHERE indexname = 'audit_events_view_actor_idx'") == ["1"]


def test_twenty_parallel_views_write_one_event(fresh_admin):
    _, admin_id = fresh_admin
    mark = _mark()
    sql = (f"BEGIN; SET LOCAL ROLE app_admin; SELECT set_config('app.user_id', '{admin_id}', true); "
           "SELECT public.record_audit_view(0); COMMIT;")
    results = []

    def one():
        results.append(_psql_try(sql))

    threads = [threading.Thread(target=one) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(r.returncode == 0 for r in results), [r.stderr for r in results if r.returncode]
    assert sorted(r.stdout.split()[-1] for r in results).count("t") == 1
    assert _views(admin_id, mark) == ["0"]


# --- e2e ------------------------------------------------------------------------

def test_views_are_journaled_once_per_filter_set_without_values(fresh_admin):
    email, admin_id = fresh_admin
    pat_id = _user_id(PAT)
    mark = _mark()
    with _client() as admin:
        _login(admin, email)
        first = admin.get("/admin/audit")
        assert first.status_code == 200
        assert _views(admin_id, mark) == ["0"]                       # 1. first view: one event
        assert admin.get("/admin/audit").status_code == 200           # 2. F5 ...
        newest = re.findall(r'data-audit-id="(\d+)"', first.text)
        assert newest
        assert admin.get("/admin/audit", params={"before_id": newest[-1]}).status_code == 200  # ... paging
        assert _views(admin_id, mark) == ["0"]
        assert admin.get("/admin/audit", params={"action": "auth."}).status_code == 200    # 3. new filter
        assert _views(admin_id, mark) == ["0", "1"]
        assert admin.get("/admin/audit", params={"action": "auth."}).status_code == 200
        assert _views(admin_id, mark) == ["0", "1"]
        assert admin.get("/admin/audit", params={"actor": PAT}).status_code == 200          # 4. a person
        assert _views(admin_id, mark) == ["0", "1", "4"]
        # bad filters are not in the mask; an unknown email still is (a search for a person)
        admin.get("/admin/audit", params={"action": "x' OR 1=1", "target_id": "abc", "before_id": "5"})
        admin.get("/admin/audit", params={"actor": f"nobody-{uuid.uuid4().hex}@example.com",
                                          "from": "2026-01-01", "to": "2026-01-02"})
        assert _views(admin_id, mark) == ["0", "1", "4", "100"]
        listed = admin.get("/admin/audit", params={"action": "audit.view"})
        assert "audit_log (filters: actor, from, to)" in listed.text
        assert "audit_log (filters: none)" in listed.text
    rows = _psql(f"SELECT {', '.join(f'coalesce({c}::text, chr(126))' for c in COLUMNS)} "
                 f"FROM audit_events WHERE id > {mark} AND action = 'audit.view' AND actor_user_id = {admin_id} "
                 "ORDER BY id")
    assert rows == [f"{admin_id}|admin|audit.view|audit_log|{mask}|~|~|~|~" for mask in (0, 1, 4, 100)]
    whole = _psql(f"SELECT row_to_json(e)::text FROM audit_events AS e WHERE id > {mark} "
                  f"AND action = 'audit.view' AND actor_user_id = {admin_id}")
    digest = _psql(f"SELECT encode(public.digest('{PAT}', 'sha256'), 'hex')")[0]
    for text in whole:
        assert PAT not in text and "nobody-" not in text and digest not in text
        assert f'"target_id":{pat_id},' not in text or pat_id in (0, 1, 4, 100)


def test_other_roles_and_guests_add_no_view():
    mark = _mark()
    for email in OTHERS.values():
        with _client() as c:
            _login(c, email)
            for params in ({}, {"action": "auth."}):
                assert c.get("/admin/audit", params=params).status_code == 403
    with _client() as guest:
        page = guest.get("/admin/audit")
        assert page.status_code == 303 and page.headers["location"].endswith("/login")
    assert _psql(f"SELECT count(*) FROM audit_events WHERE id > {mark} AND action = 'audit.view'") == ["0"]


def test_audit_view_is_a_filter_of_the_journal_page():
    with _client() as admin:
        _login(admin, ADMIN)
        page = admin.get("/admin/audit", params={"action": "audit."})
        assert page.status_code == 200 and "were not valid" not in page.text
        assert re.findall(r"<code>([^<]+)</code>", page.text.split("<tbody>", 1)[1]) \
            and all(a == "audit.view" for a in re.findall(r"<code>([^<]+)</code>", page.text.split("<tbody>", 1)[1]))
        by_target = admin.get("/admin/audit", params={"target_type": "audit_log"})
        assert by_target.status_code == 200 and "were not valid" not in by_target.text


def test_route_records_the_view_before_reading_and_fails_closed():
    source = (ROOT / "app" / "routes_admin.py").read_text()
    body = source[source.index("def admin_audit("):source.index('@router.get("/admin/users")')]
    assert body.index('require_user(request, "admin")') < body.index("_record_audit_view(") \
        < body.index("FROM audit_events e")
    assert "status_code=503" in body
    helper = source[source.index("def _record_audit_view("):source.index('@router.get("/admin/audit")')]
    assert "except psycopg2.Error" in helper and "type(exc).__name__" in helper
    assert "conn.commit()" in helper


# --- -p e6 only: the window and a failed write ---------------------------------------

E6_ONLY = pytest.mark.skipif(PROJECT != "e6", reason="only on the disposable stand -p e6")


def _window_sql(length: str) -> str:
    return ("CREATE OR REPLACE FUNCTION public.audit_view_window() RETURNS interval LANGUAGE sql STABLE "
            f"SET search_path = pg_catalog, public, pg_temp AS $f$ SELECT interval '{length}' $f$")


@contextmanager
def _short_window():
    _psql(_window_sql("3 seconds"))
    try:
        yield
    finally:
        _psql(_window_sql("10 minutes"))   # migrate (rls.sql) puts the same back
        assert _psql("SELECT public.audit_view_window()::text") == ["00:10:00"]


@E6_ONLY
def test_e6_after_the_window_the_same_view_is_written_again(fresh_admin):
    email, admin_id = fresh_admin
    mark = _mark()
    with _short_window(), _client() as admin:
        _login(admin, email)
        admin.get("/admin/audit")
        admin.get("/admin/audit")
        assert _views(admin_id, mark) == ["0"]
        time.sleep(4)
        admin.get("/admin/audit")
        assert _views(admin_id, mark) == ["0", "0"]


@E6_ONLY
def test_e6_failed_write_hides_the_journal_with_503(fresh_admin):
    email, admin_id = fresh_admin
    _psql("REVOKE EXECUTE ON FUNCTION public.record_audit_view(integer) FROM app_admin")
    try:
        with _client() as admin:
            _login(admin, email)
            page = admin.get("/admin/audit")
        assert page.status_code == 503, page.status_code
        assert "The audit log is unavailable: the view could not be recorded." in page.text
        assert "data-audit-id" not in page.text and "Log integrity" not in page.text
        assert "Traceback" not in page.text and "psycopg2" not in page.text
    finally:
        _psql("GRANT EXECUTE ON FUNCTION public.record_audit_view(integer) TO app_admin")
