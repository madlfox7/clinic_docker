# sec_doc — Docker secrets в clinic_docker

Это короткая памятка для меня о том, как устроены секреты в проекте и как его запускать.

## 1. Почему секреты лежат в файлах, а не в env
Переменные окружения видны в `docker inspect`, в `/proc/<pid>/environ`, в логах и в `docker compose config`, и их легко закоммитить через `.env`. В PDF (стр. 6, раздел Secrets) сказано: секретов не должно быть ни в коде, ни в переменных окружения, ни в URL. Поэтому каждый секрет хранится отдельным файлом и монтируется в контейнер как `/run/secrets/<имя>`.

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

В коде секрет читается через `read_secret(name)`. Функция берёт `/run/secrets/<name>` и падает, если файла нет. Запасного варианта через env нет. Хост, имя пользователя и имя базы не секретны и задаются через `PGHOST`, `PGUSER` и `PGDATABASE`.

## 3. Запуск на новой машине
```
git clone https://github.com/madlfox7/clinic_docker && cd clinic_docker
cp .env.example .env          # в .env только несекретные настройки
./scripts/init_secrets.sh     # создаёт недостающие secrets/*, существующие файлы не трогает
docker compose up --build -d
```

## 4. Смена секретов
- `demo_password` используется только при первом seed пустой базы. Если файла нет или он пуст, `seed` падает и пользователей не создаёт. `init_secrets.sh` не перезаписывает существующий файл. Известного демо-пароля в коде больше нет; в базе, созданной раньше, остаётся старый пароль, пока её не пересоздать (`docker compose down -v`, затем `./scripts/init_secrets.sh` и `docker compose up -d`).
- Новые `session_secret` и `smtp_password` начинают действовать после `docker compose up -d --force-recreate api`.
- `field_encryption_key` нельзя просто заменить: записи, зашифрованные старым ключом, перестанут читаться. Ротация описана в разделе 7.
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

## 6. Правила
- Папку `secrets/` никогда не коммитить.
- В `.env` не хранить паролей.
- Не собирать URL подключения с паролем внутри.

## 7. Шифрование медполей
- Шифруются только `visit_notes.body` и `prescriptions.body`: AES-256-GCM из библиотеки `cryptography`, случайный 12-байтовый nonce на каждую запись. Код — `app/field_crypto.py`. Шифрование и расшифровка идут только в `api`; ключ не передаётся в SQL и не попадает в `db`, `migrate` и `seed`.
- В колонке хранится пакет `fe2:<key_id>:<nonce>:<шифротекст>:<тег>` (части в base64url без `=`). В associated data входят заголовок пакета, имя таблицы, id этой строки и `appointment_id`, поэтому пакет привязан к записи: его нельзя перенести в другую строку (той же или другой таблицы) или переписать на другой `key_id` — расшифровка не проходит (`integrity_check_failed`). Новая заметка/рецепт сначала получает id из sequence, затем шифруется и вставляется с этим id. CHECK в базе (`*_body_bound_check`) принимает только такие пакеты (до 24000 символов); лимит 4000 символов проверяется в `api` на открытом тексте до шифрования. CHECK добавлен как `NOT VALID`, чтобы старый том поднимался до миграции.
- Ключ: `secrets/field_encryption_key`, одна строка `<key_id>:<64 hex>`. `init_secrets.sh` создаёт его как `v1:...` только если файла нет, не перезаписывает и не печатает значение. Права: `600` у владельца плюс ACL `u:10001:r` для пользователя api (bind-mount сохраняет владельца и права). Без `setfacl` — `sudo chown 10001:10001` на оба файла. Остальные секреты по-прежнему `644`.
- Нет файла, файл пуст или формат неверный — `api` падает при старте с понятной ошибкой; запасного ключа в коде и в env нет. Если строку не удалось расшифровать (чужой ключ, повреждённые данные), пользователь видит страницу «A medical record could not be decrypted», в лог пишется только причина (`unknown_key_id`, `integrity_check_failed`, `unbound_packet`, `not_encrypted`) и путь, без текста, пакета и ключа.
- Старые данные: при каждом старте `api` до uvicorn выполняется `python -m migrate_medical_fields`. Он через `SECURITY DEFINER`-функции `medical_bodies_to_encrypt` и `medical_body_replace` (доступны только самому логину `clinic_api`, не ролям `app_*`; принимают только готовый пакет `fe2`) шифрует открытые строки и перешифровывает пакеты первой версии `fe1` (привязаны только к таблице и `key_id`): расшифровывает их старым способом и записывает заново с привязкой к строке. Уже привязанные пакеты не трогает, повторный запуск ничего не меняет. `api` сам пакет `fe1` не показывает (`unbound_packet`), его открывает только миграция. Пока `api` с ключом не стартовал на старом томе, открытый текст остаётся в базе и дампе.
- Ротация:
  1. `./scripts/rotate_field_key.sh` (или `./scripts/rotate_field_key.sh <новый_key_id>`): текущая строка ключа дописывается в `field_encryption_previous_keys`, в `field_encryption_key` пишется новый ключ (`v1` → `v2`). Значения не печатаются, права и ACL сохраняются.
  2. `docker compose up -d --force-recreate api`: новые записи шифруются новым `key_id`, старые читаются по своему `key_id` старым ключом.
  3. По желанию: `docker compose exec api python -m migrate_medical_fields --reencrypt` перешифровывает строки со старым `key_id` текущим ключом. Только после этого старую строку можно удалить из `field_encryption_previous_keys`.
- Проверка: `docker compose exec db psql -U clinic -d clinic -c "SELECT left(body, 12) FROM visit_notes LIMIT 5"` показывает только `fe2:...`; `docker compose exec db ls /run/secrets` не содержит `field_encryption_key`.
- Чего это не закрывает: кто получит и дамп, и файл ключа, прочитает текст. Владелец БД без ключа текст не прочитает и не сможет переставить пакет в другую строку так, чтобы он открылся, но может удалить или испортить строку; подмену журнала закрывает следующий этап (хэш-цепочка аудита). Старые пакеты `fe1` из дампов, снятых до привязки, миграция при старте ещё примет; чтобы закрыть и это, после миграции можно сменить ключ (`rotate_field_key.sh`, затем `--reencrypt`) и удалить старый ключ.

## 8. Внешний вид, статика и заголовки безопасности
- Bootstrap 5.3.8, только `dist/css/bootstrap.min.css` и `LICENSE` (MIT), без Bootstrap JS, без CDN, шрифтов и внешних картинок. Источник — npm-пакет `bootstrap@5.3.8`; его `integrity` (sha512) совпал с реестром, а `bootstrap.min.css` побайтно совпал с файлом из официального релиза GitHub `bootstrap-5.3.8-dist.zip`.
  - SHA-256 исходного файла: `d85327d99c7a3ee1f9b5d0500d1370acea3ad2db39c163c2f51f232baedbdede`.
  - Единственное изменение: удалена последняя строка `/*# sourceMappingURL=bootstrap.min.css.map */` (карты в `static/` не кладём). SHA-256 файла в репозитории: `8f8173cb2d8f867274aeb0cb15328e60f490c7f272351e51a55f1dabb486e4ff` (проверяет `tests/test_ui_security.py`).
  - Проверить: `sha256sum app/static/vendor/bootstrap/bootstrap.min.css`.
- В `app/static/` только `.css`, `.js`, `.svg` и `LICENSE` (тест-allowlist): никаких `.map`, бэкапов, `.env`, симлинков. SVG без скриптов, ссылок и `data:`. Отдаёт `api` через `StaticFiles` (листинга каталогов нет, выйти из папки нельзя). Типы: `text/css`, `text/javascript` (так отдаёт Starlette/Python 3.12), `image/svg+xml`.
- Кеш: шаблоны ссылаются на `static_url(...)` → `/static/...?v=<16 hex SHA-256>`, хэши считаются при старте `api`. nginx: URL с `?v=` — `public, max-age=31536000, immutable`, без `?v=` — `no-cache`. Для `/static/` nginx не передаёт cookie в api и вырезает `Set-Cookie`, так что в кеш не попадёт сессия. Все остальные ответы api (HTML-страницы, кабинеты, медданные, JSON поиска) — `Cache-Control: no-store`.
- Шаблоны: без `style=`, обработчиков `on...=`, встроенных `<script>`/`<style>`, `javascript:`, `data:` и `|safe`. Весь JS — `app/static/app.js`: подтверждения через `data-confirm="..."` (обычное автоэкранирование Jinja, чтение через `dataset`, вывод только через `confirm()`/`textContent`). В `app.js` нет `innerHTML`, `eval`, `new Function`, строкового `setTimeout`, `document.cookie`, `localStorage`; CSRF-токены остаются скрытыми полями форм. В `data-*` нет email, токенов и медданных.
- Иконки Bootstrap (стрелка `select`, галочка/радио) в оригинале — `data:`-URI; т.к. `img-src 'self'`, они переопределены в `app.css` на файлы `/static/img/*.svg`. Остальные компоненты с `data:`-иконками (валидация форм, `form-switch`, `navbar-toggler`, accordion, `btn-close`, carousel) не используются — это тоже проверяет тест.
- Заголовки ставит nginx из одного файла `docker/proxy/security_headers.conf`, все с `always` (и на 4xx/5xx). Так как nginx не наследует `add_header` в `location` со своими `add_header`, файл подключён `include` в КАЖДОМ `location` (`/reset-password`, `/confirm-email`, `/static/`, `/`) и на уровне `server`:
  - `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-src 'none'; worker-src 'none'; manifest-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'`
  - `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` (токены в `/reset-password` и `/confirm-email` не уходят в Referer), `X-Frame-Options: DENY`, `Permissions-Policy: camera=(), microphone=(), geolocation=()`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`.
  - Не ставим: `X-XSS-Protection` (устарел), HSTS (будет вместе с TLS).
- Лог nginx — формат `clinic_path` (путь без query string) по умолчанию для всего `server` и явно в `/reset-password`, `/confirm-email`.
- Проверка: `curl -sI http://localhost:8080/`, `.../reset-password?token=x`, `.../static/app.css`, `.../no-such-page` — везде те же заголовки; `pytest tests/test_ui_security.py`.

- Выход: только `POST /logout` из формы в меню со скрытым CSRF-токеном (общая проверка `verify_csrf`). Без токена или с неверным — 403, сессия не завершается. `GET /logout` отвечает 405 и сессию не трогает, поэтому чужая страница не может разлогинить пользователя ссылкой или картинкой.
- Кнопка «Book» для гостя ведёт на `/login?doctor=<id>`. Свободного адреса возврата (`next`) нет, он игнорируется. После успешного входа сервер сам строит путь `/doctors/<id>/slots` и только если: роль — пациент, значение одно, 1–9 ASCII-цифр, в пределах int4, и врач активен (`doctor_is_active`). Иначе — обычная страница роли (`/me`). В форму входа попадает только проверенное число, сырое значение не отражается. В регистрацию и письма параметр не передаётся.
