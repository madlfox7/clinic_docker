docker compose up -d --build
docker compose exec api python - <<'PY'
import os, psycopg2
c = psycopg2.connect(os.environ["DATABASE_URL"])
cur = c.cursor()
cur.execute("""
SELECT current_user, rolsuper, rolbypassrls, rolcreatedb
FROM pg_roles WHERE rolname = current_user
""")
print("who:", cur.fetchone())
cur.execute("SELECT pg_get_userbyid(relowner) FROM pg_class WHERE relname = 'appointments'")
print("owner:", cur.fetchone())
try:
    cur.execute("CREATE TABLE rls_stage1_probe(id int)")
    print("FAIL: api created a table")
except Exception as exc:
    print("ddl refused:", type(exc).__name__)
c.rollback()
c.close()
PY












--------------------------

expected:
who: ('clinic_api', False, False, False) — сессия API это clinic_api, не суперюзер, не BYPASSRLS, не может создавать базы. Политика, на эту сессию действует.
owner: ('clinic',) — таблицы принадлежат мигратору. API их не владеет, значит не обходит RLS как owner.
ddl refused: InsufficientPrivilege — с учётных данных API схема не меняется. CREATE TABLE от этой роли отклонён.

 «роль приложения не обходит RLS». 


 -----