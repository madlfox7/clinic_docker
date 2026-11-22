# sec_doc — Docker secrets в clinic_docker


## 1. Почему секреты лежат в файлах, а не в env
Не храните секреты в коде, env или URL: они доступны через `docker inspect`, `/proc/<pid>/environ`, логи и `docker compose config`, а `.env` легко закоммитить. Это правило PDF (стр. 6, Secrets). Каждый секрет хранится в отдельном файле и монтируется в `/run/secrets/<имя>`.

## 2. Файлы в `secrets/`
Папка `secrets/` указана в `.gitignore` и никогда не коммитится.

| Файл | Кто его читает |
|---|---|
| `postgres_password` | `db` (через `POSTGRES_PASSWORD_FILE`) и `migrate` |
| `clinic_api_password` | `migrate` задаёт этот пароль роли clinic_api, `api` и `seed` подключаются с ним |
| `session_secret` | `api`, подпись сессионных cookie |
| `smtp_password` | `api` (mailer); в dev с mailpit файл пустой |
| `demo_password` | `seed`, один пароль для всех демо-учёток @clinic.local |
| `field_encryption_key` | только `api`: текущий ключ шифрования медполей, `<key_id>:<64 hex>` |
| `field_encryption_previous_keys` | только `api`: старые ключи для чтения, по одному `<key_id>:<64 hex>` в строке; пустой до первой ротации |
| `audit_db_password` | `migrate` задаёт пароль роли `clinic_auditor`, `audit_anchor` подключается с ним (только `SELECT` журнала и головы цепочки) |
| `audit_anchor_key` | только `audit_anchor`: HMAC-ключ якорей и реестра цепочек; `600` + ACL `u:10002:r` или от root `chown 10002` + `400`, никогда не `644`; не перезаписывается |
| `tls/ca.key` | только хост (`init_secrets.sh`): ключ учебного CA, в контейнеры не попадает |
| `tls/server.crt`, `tls/server.key` | `proxy`: серверный сертификат (в `provided` — ваша полная цепочка) и ключ |

В коде секрет читается через `read_secret(name)`. Функция берёт `/run/secrets/<name>` и падает, если файла нет. Запасного варианта через env нет. Хост, имя пользователя и имя базы не секретны и задаются через `PGHOST`, `PGUSER` и `PGDATABASE`.

## 3. Запуск на новой машине
```
git clone https://github.com/madlfox7/clinic_docker && cd clinic_docker
cp .env.example .env          # в .env только несекретные настройки
./scripts/init_secrets.sh     # создаёт недостающие secrets/*, существующие файлы не трогает
docker compose up --build -d
```

## 4. Смена секретов
- `demo_password` нужен только для первого seed пустой БД; если он отсутствует или пуст, `seed` падает без создания пользователей. `init_secrets.sh` не перезаписывает файл, а уже созданная БД сохраняет старый пароль. Чтобы сменить его, пересоздайте БД: `docker compose down -v`, затем `./scripts/init_secrets.sh` и `docker compose up -d`. В коде демо-пароля нет.
- Новые `session_secret` и `smtp_password` начинают действовать после `docker compose up -d --force-recreate api`.
- `field_encryption_key` нельзя просто заменить: записи, зашифрованные старым ключом, перестанут читаться. Ротация описана в разделе 6.
- `postgres_password` и `clinic_api_password` уже записаны в том БД. Если просто заменить файл, пароль в файле и в базе разойдутся. Есть два варианта:
  - пересоздать базу командой `docker compose down -v`, затем `./scripts/init_secrets.sh` и `docker compose up -d` (все данные удалятся);
  - или выполнить `ALTER ROLE ... PASSWORD ...` внутри базы, а потом заменить файл.

## 5. Проверка, что секреты не утекают
```
docker compose config | grep -iE 'password|secret|postgresql://'      # пароли не должны появиться
for c in $(docker compose ps -q); do docker inspect $c | grep -iE 'password|secret|postgresql://'; done   # допустимы только пути /run/secrets
docker compose exec api env                                            # секретов быть не должно
docker history --no-trunc <image>                                      # для каждого образа
git grep -n "<значение секрета>"                                       # должно быть пусто
```


## 6. Шифрование медполей
- Шифруются только `visit_notes.body` и `prescriptions.body`: AES-256-GCM (`cryptography`), случайный nonce 12 байт на запись. Код — `app/field_crypto.py`; шифрование/расшифровка только в `api`, ключ не передаётся в SQL и недоступен `db`, `migrate`, `seed`.
- Формат в колонках: `fe2:<key_id>:<nonce>:<шифротекст>:<тег>` (base64url без `=`). Associated data включает заголовок, таблицу, id строки и `appointment_id`: перенос пакета или смена `key_id` приводит к `integrity_check_failed`. Для новой записи сначала получают id из sequence, затем шифруют и вставляют с ним. CHECK `*_body_bound_check` разрешает только такие пакеты до 24000 символов; API ограничивает открытый текст 4000 символами. CHECK создан `NOT VALID` для миграции старых томов.
- Ключ `secrets/field_encryption_key` — одна строка `<key_id>:<64 hex>`; `init_secrets.sh` создаёт `v1:...` только при отсутствии файла, не перезаписывает и не печатает значение. Права — `600` плюс ACL `u:10001:r` (bind-mount сохраняет их); без `setfacl` выполните `sudo chown 10001:10001 secrets/field_encryption_key secrets/field_encryption_previous_keys`. Остальные секреты — `644`.
- Отсутствующий, пустой или неверно оформленный ключ останавливает `api`; запасного ключа в коде/env нет. При ошибке расшифровки пользователь видит «A medical record could not be decrypted», а лог содержит только причину (`unknown_key_id`, `integrity_check_failed`, `unbound_packet`, `not_encrypted`) и путь — без текста, пакета и ключа.
- При старте `api`, до uvicorn, `python -m migrate_medical_fields` вызывает `SECURITY DEFINER`-функции `medical_bodies_to_encrypt` и `medical_body_replace` (только для логина `clinic_api`, не ролей `app_*`; принимают только готовые `fe2`). Миграция шифрует открытые строки и переводит `fe1` (привязан только к таблице и `key_id`) в row-bound `fe2`; привязанные пакеты не меняет и безопасна при повторе. `api` не показывает `fe1` (`unbound_packet`), его читает только миграция. До её запуска старый текст остаётся в БД и дампе.
- Ротация:
  1. `./scripts/rotate_field_key.sh` (или `./scripts/rotate_field_key.sh <новый_key_id>`) добавляет текущий ключ в `field_encryption_previous_keys`, записывает новый (`v1` → `v2`); значения не печатаются, права и ACL сохраняются.
  2. `docker compose up -d --force-recreate api`: новые записи используют новый `key_id`, старые читаются прежним ключом.
  3. По желанию, `docker compose exec api python -m migrate_medical_fields --reencrypt` перешифровывает старые строки текущим ключом; после этого удалите старый ключ из `field_encryption_previous_keys`.
- Проверка: `docker compose exec db psql -U clinic -d clinic -c "SELECT left(body, 12) FROM visit_notes LIMIT 5"` показывает только `fe2:...`; `docker compose exec db ls /run/secrets` не содержит `field_encryption_key`.
- Ограничения: дамп вместе с ключом раскрывает записи. Владелец БД без ключа не читает и не переносит пакет, но может удалить или испортить строку; подмену журнала выявляют хеш-цепочка и внешние HMAC-якоря (раздел 8). Миграция принимает старые `fe1`-пакеты из дампов: после миграции смените ключ, выполните `--reencrypt` и удалите предыдущий ключ.

## 7. Внешний вид, статика и заголовки безопасности
- Bootstrap 5.3.8: только `dist/css/bootstrap.min.css` и `LICENSE` (MIT), без JS/CDN/шрифтов/внешних изображений. `integrity` (sha512) npm-пакета `bootstrap@5.3.8` совпал с реестром; CSS побайтно совпал с официальным GitHub-релизом `bootstrap-5.3.8-dist.zip`. Исходный SHA-256: `d85327d99c7a3ee1f9b5d0500d1370acea3ad2db39c163c2f51f232baedbdede`; удалён только комментарий `/*# sourceMappingURL=bootstrap.min.css.map */`, SHA-256 в репозитории `8f8173cb2d8f867274aeb0cb15328e60f490c7f272351e51a55f1dabb486e4ff` (проверяет `tests/test_ui_security.py`). Проверка: `sha256sum app/static/vendor/bootstrap/bootstrap.min.css`.
- `app/static/` allowlist: `.css`, `.js`, `.svg`, `LICENSE`; нет `.map`, бэкапов, `.env`, симлинков. SVG без скриптов, ссылок и `data:`. `api` отдаёт статику через `StaticFiles` без листинга/выхода из папки; MIME: `text/css`, `text/javascript` (Starlette/Python 3.12), `image/svg+xml`.
- Кеш: `static_url(...)` добавляет к `/static/...` первые 16 hex SHA-256, вычисляемого при старте `api`. nginx кеширует URL с `?v=` год как `public, max-age=31536000, immutable`, без версии — `no-cache`; для `/static/` не передаёт cookie и удаляет `Set-Cookie`. Остальные ответы API — `Cache-Control: no-store`.
- Шаблоны запрещают `style=`, `on...=`, inline `<script>/<style>`, `javascript:`, `data:` и `|safe`. Весь JS — `app/static/app.js`: Jinja-экранированный `data-confirm`, вывод через `confirm()`/`textContent`. Нет `innerHTML`, `eval`, `new Function`, строкового `setTimeout`, `document.cookie` или `localStorage`; CSRF остаётся в скрытых полях, `data-*` не содержит email, токены или медданные.
- Bootstrap использует `data:` для select/check/radio; при `img-src 'self'` они заменены SVG из `/static/img/*.svg`. Остальные компоненты с `data:`-иконками не используются (это проверяет тест): валидация, `form-switch`, `navbar-toggler`, accordion, `btn-close`, carousel.
- Заголовки nginx заданы в `docker/proxy/security_headers.conf` с `always` (включая 4xx/5xx). Из-за наследования `add_header` файл подключён в каждом `location` (`/reset-password`, `/confirm-email`, `/static/`, `/`) и на уровне `server`:
  - `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-src 'none'; worker-src 'none'; manifest-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'`
  - `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` (токены в `/reset-password` и `/confirm-email` не уходят в Referer), `X-Frame-Options: DENY`, `Permissions-Policy: camera=(), microphone=(), geolocation=()`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`.
  - Не ставим: `X-XSS-Protection` (устарел), HSTS ставится вместе с TLS: `Strict-Transport-Security: max-age=3600` на стенде, `31536000` в проде, без `includeSubDomains`/`preload`.
- Лог nginx использует формат `clinic_path` (путь без query) для всего `server` и явно для `/reset-password`, `/confirm-email`.
- Проверка: `curl -sI http://localhost:8080/`, `/reset-password?token=x`, `/static/app.css`, `/no-such-page` — везде одинаковые заголовки; `pytest tests/test_ui_security.py`.

- Выход: только `POST /logout` из формы в меню со скрытым CSRF-токеном (общая проверка `verify_csrf`). Без токена или с неверным — 403, сессия не завершается. `GET /logout` отвечает 405 и сессию не трогает, поэтому чужая страница не может разлогинить пользователя ссылкой или картинкой.
- Кнопка «Book» для гостя ведёт на `/login?doctor=<id>`. Свободного адреса возврата (`next`) нет, он игнорируется. После успешного входа сервер сам строит путь `/doctors/<id>/slots` и только если: роль — пациент, значение одно, 1–9 ASCII-цифр, в пределах int4, и врач активен (`doctor_is_active`). Иначе — обычная страница роли (`/me`). В форму входа попадает только проверенное число, сырое значение не отражается. В регистрацию и письма параметр не передаётся.

## 8. Контроли: TLS, журнал аудита, E6

| Контроль | Где | Проверка |
|---|---|---|
| TLS 1.2/1.3, свой CA с `nameConstraints` и `serverAuth` (local) или своя цепочка (provided) | `scripts/init_secrets.sh`, `scripts/tls_lib.sh`, `docker/proxy/` | `make tls-check`, `tests/test_tls.py` |
| HTTP → HTTPS 308 на `PUBLIC_BASE_URL`, HSTS | nginx (`docker/proxy/`) | `tests/test_tls.py` |
| Cookie `Secure`, `api` не стартует без `https://` в `PUBLIC_BASE_URL` | `app/` | `tests/test_tls.py`, `tests/test_session.py` |
| Журнал только дописывается (UPDATE/DELETE/TRUNCATE запрещены и суперпользователю) | `db/init.sql` (триггеры `ENABLE ALWAYS`) | `tests/test_audit_chain.py` |
| SHA-256-цепочка `seq`/`prev_hash`/`row_hash`, канон v1 | `db/init.sql`, `audit/canon.py` (независимая реализация) | `tests/test_audit_chain.py`, `make audit-verify` |
| HMAC-якоря раз в 60 с, реестр цепочек, `flock` на запись | `audit/anchor.py`, `audit/chainlib.py`, сервис `audit_anchor` | `tests/test_audit_chain.py` (20 параллельных `--once`) |
| Обнаружение подделки | `audit/verify_audit.py` | E6: `experiments/e6_report.md` (20/20) |
| Полная проверка цепочки раз в `CLINIC_AUDIT_FULL_CHECK_EVERY` (600 с) и публичный `status.json` (белый список полей, атомарная запись) | `audit/anchor.py`, том `audit_status` | `tests/test_audit_chain.py` |
| Плашка «Log integrity» на `/admin/audit` (OK только при свежих и целых проверках, после подмены цепочки — красная навсегда; индикатор, не источник истины) | `app/audit_status.py`, `app/routes_admin.py`, том `audit_status` (`ro` в `api`) | `tests/test_audit_status_ui.py` |
| Аудит просмотров журнала: `audit.view`, маска фильтров без значений, окно 10 мин, fail closed 503 | `db/rls.sql` (`record_audit_view`, только `app_admin`), `app/routes_admin.py` | `tests/test_audit_view.py` |

