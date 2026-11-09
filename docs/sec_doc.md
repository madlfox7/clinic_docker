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

В коде секрет читается через `read_secret(name)`. Функция берёт `/run/secrets/<name>` и падает, если файла нет. Запасного варианта через env нет. Хост, имя пользователя и имя базы не секретны и задаются через `PGHOST`, `PGUSER` и `PGDATABASE`.

## 3. Запуск на новой машине
```
git clone https://github.com/madlfox7/clinic_docker && cd clinic_docker
cp .env.example .env          # в .env только несекретные настройки
./scripts/init_secrets.sh     # создаёт secrets/* с правами 600, существующие файлы не трогает
docker compose up --build -d
```

## 4. Смена секретов
- `demo_password` используется только при первом seed пустой базы. Если файла нет или он пуст, `seed` падает и пользователей не создаёт. `init_secrets.sh` не перезаписывает существующий файл. Известного демо-пароля в коде больше нет; в базе, созданной раньше, остаётся старый пароль, пока её не пересоздать (`docker compose down -v`, затем `./scripts/init_secrets.sh` и `docker compose up -d`).
- Новые `session_secret` и `smtp_password` начинают действовать после `docker compose up -d --force-recreate api`.
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
