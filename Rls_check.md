# Проверка роли API и границ RLS

```bash
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
```

Ожидаемый результат:

- `who: ('clinic_api', False, False, False)` — API подключается как `clinic_api`, не суперпользователь, не `BYPASSRLS` и не может создавать базы; к сессии применяются политики.
- `owner: ('clinic',)` — таблицы принадлежат мигратору, поэтому API не обходит RLS как владелец.
- `ddl refused: InsufficientPrivilege` — роль API не может менять схему; `CREATE TABLE` отклоняется.


 