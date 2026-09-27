# Clinic Appointment Application

## 1. Назначение проекта

Это учебное веб-приложение клиники. Пользователь может войти в систему, посмотреть врачей, посмотреть свободные слоты и записаться на прием. В системе есть отдельные сценарии для пациента, врача, регистратора и администратора.

Интерфейс сайта написан на английском языке. Имена демонстрационных врачей и специальности также используют латинские символы.

## 2. Структура проекта

```text
clinic_24_9/
|-- docker-compose.yml
|-- README.md
|-- PROJECT_DOCUMENTATION.md
|-- .env.example
|-- .gitignore
|-- api/
|   |-- Dockerfile
|   |-- requirements.txt
|   |-- main.py
|   `-- templates/
|       |-- base.html
|       |-- home.html
|       |-- login.html
|       |-- me.html
|       |-- doctors.html
|       |-- slots.html
|       |-- my_appointments.html
|       |-- doctor_appointments.html
|       |-- admin_users.html
|       `-- admin_schedule.html
|-- tests/
|   |-- requirements.txt
|   |-- run_tests.sh
|   `-- test_stage4.py
|-- experiments/
|   |-- concurrent_book.py
|   `-- concurrent_book_results.md
|-- db/
|   `-- init.sql
`-- proxy/
    `-- nginx.conf
```

## 3. Docker-архитектура

Compose запускает три сервиса:

### `db`

- PostgreSQL 16.
- Доступен внутри Compose по имени `db`.
- Данные хранятся в named volume `db_data`.
- `db/init.sql` подключается в `/docker-entrypoint-initdb.d/init.sql`.
- Имеет healthcheck через `pg_isready`.

### `api`

- Собирается из `api/Dockerfile`.
- Использует Python 3.12 и Uvicorn.
- Запускает FastAPI-приложение из `api/main.py`.
- Папка `./api` монтируется в `/app`, поэтому изменения Python и шаблонов доступны контейнеру.
- Подключен к сетям `frontend` и `backend`.
- Ждет состояние `healthy` у PostgreSQL.

### `proxy`

- Nginx `1.27-alpine`.
- Публикует порт `8080`.
- Перенаправляет запросы на `api:8000`.
- Конфигурация находится в `proxy/nginx.conf`.

Сеть `backend` объявлена `internal: true`, поэтому она предназначена для внутреннего общения API и базы. Сеть `frontend` соединяет proxy и API.

## 4. Настройка и запуск

Из корня проекта:

```bash
cp .env.example .env
docker compose up --build -d
```

В Windows через WSL можно использовать:

```bash
cd /mnt/c/Users/User/clinic_24_9
docker compose up --build -d
```

Сайт:

```text
http://localhost:8080
```

Проверка состояния:

```bash
docker compose ps
docker compose logs --tail=100 api
```

После изменения Python-кода обычно достаточно пересобрать API:

```bash
docker compose up -d --build api
```

После изменения только смонтированного кода можно также перезапустить API:

```bash
docker compose restart api
```

### Запуск автоматических тестов этапа 4

Из WSL в корне проекта:

```bash
./tests/run_tests.sh
```

Если текущая директория уже `tests/`, запускай:

```bash
./run_tests.sh
```

Скрипт сам определяет корень репозитория, поднимает Compose без удаления volume, дожидается ответа `http://localhost:8080`, затем запускает `pytest -v tests/test_stage4.py`. Тестовые зависимости закреплены в `tests/requirements.txt`. Для окружений без `python3-venv` скрипт использует доступный `pip --user`; обычное окружение с venv использует отдельный `.venv-tests/`, игнорируемый Git.

Тесты проверяют роли, вход, Book/Cancel, overlap, registrar и admin block. Они временно создают и отменяют appointments, а admin-тест блокирует и затем разблокирует `pat@clinic.local`. Запускай их только против локальной dev-БД, не production. Volume не удаляется, но отдельные записи тестов и последовательности ID в таблице могут измениться.

### Эксперимент конкурентного бронирования

Найди свободный слот, у которого нет `scheduled` appointment:

```sql
SELECT s.id, d.full_name, s.starts_at
FROM slots s
JOIN doctors d ON d.id = s.doctor_id
LEFT JOIN appointments a
    ON a.slot_id = s.id AND a.status = 'scheduled'
WHERE a.id IS NULL
ORDER BY s.id;
```

Из WSL в корне проекта запусти 10, затем 50 одновременных POST-запросов на выбранный slot ID:

```bash
python3 experiments/concurrent_book.py 2 10
python3 experiments/concurrent_book.py 2 50
```

Замени `2` на реально свободный ID. Между прогонами отмени winner (или поменяй status его записи на `cancelled`), иначе второй прогон проверит только уже занятый слот. После каждого прогона SQL `GROUP BY slot_id, status` должен показать ровно одну строку `scheduled` для проверяемого slot. Скрипт синхронизирует POST-запросы барьером; отчёт двух проверенных прогонов сохранён в `experiments/concurrent_book_results.md`.

Эксперимент изменяет локальную БД и оставляет cancelled history, поэтому запускай его только на dev-данных. Не удаляй volume ради этого теста.

### Stage 5 — конкурентность и ограничения слотов

- `appointments_one_scheduled_per_slot` гарантирует не более одной активной записи на один `slot_id`.
- `slots_no_overlap_per_doctor` — PostgreSQL `EXCLUDE USING gist` по `doctor_id` и generated `time_range`; два слота одного врача не могут пересекаться.
- Диапазон слота полуоткрытый (`[)`) — начало включено, конец исключён, поэтому соседние визиты встык разрешены.
- Overlap одного пациента между слотами разных врачей по-прежнему проверяется в Python в `book_slot()`.

Результаты одновременного бронирования одного свободного slot `2` (Anna, 2026-10-01 10:00), дата проверки — 2026-09-27:

| Одновременные POST-запросы | Accepted | Rejected | `scheduled` после прогона |
|---:|---:|---:|---:|
| 10 | 1 | 9 | 1 |
| 50 | 1 | 49 | 1 |

После каждого прогона тестовую запись отменяли; текущее состояние БД не содержит активной записи на slot `2`.

Регрессионный набор этапов 4/5a запускать из корня проекта:

```bash
python3 -m pytest -v tests/test_stage4.py
```

Последний полный прогон завершился результатом `16 passed, 1 skipped`. Generator/time-off regression можно запустить отдельно: `python3 -m pytest -v tests/test_stage4.py::test_admin_slot_generator_respects_time_off_and_role`.

## 5. Переменные окружения

Файл `.env` не должен добавляться в Git. Шаблон находится в `.env.example`:

```env
POSTGRES_USER=clinic
POSTGRES_PASSWORD=change_me
POSTGRES_DB=clinic
SESSION_SECRET=dev-secret-change-me
HOST_UID=1000
HOST_GID=1000
```

Для реального окружения необходимо заменить пароль базы и `SESSION_SECRET` на секретные значения.

## 6. Инициализация приложения

При старте FastAPI выполняется:

```text
ensure_schema()
seed_users()
seed_clinic()
```

### `ensure_schema()`

Добавляет колонку `users.blocked`, если ее еще нет, создает таблицы и применяет ограничения слотов/appointments. При старте также удаляется прежнее глобальное `appointments_slot_id_key`, создаётся partial unique index по активным appointments и мигрируется `slots.time_range` с exclusion constraint. Эта миграция применяется и к существующему volume без удаления данных. В `db/init.sql` описана та же схема для новой базы.

### `seed_users()`

Идемпотентно добавляет отсутствующих пользователей по email. Уже существующие записи не дублируются.

Тестовые аккаунты:

| Email | Password | Role |
|---|---|---|
| `admin@clinic.local` | `password123` | `admin` |
| `doc@clinic.local` | `password123` | `doctor` |
| `doc2@clinic.local` | `password123` | `doctor` |
| `pat@clinic.local` | `password123` | `patient` |
| `pat2@clinic.local` | `password123` | `patient` |
| `reg@clinic.local` | `password123` | `registrar` |

### `seed_clinic()`

Если таблица `doctors` пуста, создаются:

- `Anna Ohanyan`, `Therapist`, 8 years;
- `Levon Petrosyan`, `Dentist`, 5 years.

Создаются обычные 30-минутные слоты и дополнительные интервалы для проверки overlap:

- Anna, 2026-10-01: `09:00-09:30`, `10:00-10:30`, `11:00-11:30`;
- Anna, 2026-10-02: `09:00-09:30`;
- Levon, 2026-10-01: `09:00-09:30`, `10:00-10:30`;
- Anna, 2026-10-03: `10:00-11:00`;
- Levon, 2026-10-03: `10:30-11:30`.

Интервалы 3 октября частично пересекаются. Слота `10:15-10:45` и пары соседних интервалов в seed-данных нет; вложение и правило «встык разрешено» требуют добавить тестовые слоты вручную.

Сидовые слоты 1–3 октября и генератор из `work_hours` — разные механизмы: сиды нужны для overlap-тестов и не пересобираются кнопкой Generate.

Важно: seed врачей и слотов срабатывает только при пустой таблице `doctors`. Если volume уже содержит базу, новые seed-слоты автоматически не добавятся.

Чтобы получить полностью свежие тестовые данные:

```bash
docker compose down --volumes --remove-orphans
docker compose up --build -d
```

Эта команда удаляет PostgreSQL volume и все данные базы.

## 7. Роли и права

### Гость

- Может открыть главную страницу.
- Видит публичные адрес, телефон и часы работы клиники.
- Может открыть список врачей.
- Может открыть форму входа.
- Не может бронировать слот.
- При попытке открыть слоты врача перенаправляется на `/login`.

### Patient

- Может открыть список врачей.
- Может открыть слоты врача.
- Может забронировать свободный слот.
- Может открыть `/my` и увидеть свои записи.
- Может отменить только собственную запись со статусом `scheduled`, если её `starts_at` ещё впереди.
- На странице слотов видит `Your appointment` и ссылку `/my` для собственной активной записи, `Unavailable` для слота с записью другого пациента и `Book appointment` для свободного слота.
- Не может видеть записи другого пациента.

### Doctor

- Может войти в кабинет.
- Может открыть `/doctor/appointments`.
- Видит записи только пациентов, записанных к этому врачу.
- Видит время начала и окончания визита и пометку `account blocked` у заблокированного пациента.
- Не может бронировать слот как пациент.

### Registrar

- Может открывать слоты врачей.
- Видит `Booked` на занятом слоте и форму `Book for patient` на свободном.
- Может указать email пациента и забронировать для него свободный слот.
- Может отменить любую запись со статусом `scheduled` с экрана слотов; пациент записи не обязан быть тем, кто вошёл.
- Для бронирования registrar применяется тот же overlap-check, что и для пациента.
- На странице слотов не показываются имя или email пациента, занявшего слот.

### Admin

- Может войти в систему и открыть кабинет.
- Может открыть `/admin/users`.
- Ссылка `Admin` доступна в общей навигации и в кабинете администратора.
- Может блокировать и разблокировать пользователей с ролью `patient`.
- Видит количество будущих appointments со статусом `scheduled` для каждого пациента.
- Может отдельно отменить все будущие `scheduled` appointments пациента. Эта команда не связана с Block.
- Заблокированный пациент не может войти и не может получить новое бронирование; форма входа показывает `Account is blocked`.
- Block не меняет статус существующих визитов; врач видит `account blocked` рядом с визитом.

## 8. HTTP-маршруты

| Method | Path | Назначение | Доступ |
|---|---|---|---|
| GET | `/` | Главная страница | Все |
| GET | `/login` | Форма входа. Если сессия уже есть, перенаправление на `/me` без запроса пароля | Гость |
| POST | `/login` | Авторизация. Повторный POST при активной сессии не меняет её и возвращает в `/me` | Гость |
| GET | `/logout` | Очистка сессии | Авторизованные |
| GET | `/me` | Кабинет текущего пользователя | Авторизованные |
| GET | `/doctors` | Список врачей | Все |
| GET | `/doctors/{doctor_id}/slots` | Слоты выбранного врача | Patient, Registrar |
| POST | `/slots/{slot_id}/book` | Бронирование слота. Прошедший слот (`starts_at <= CURRENT_TIMESTAMP`) отклоняется как `error=past` | Patient, Registrar |
| POST | `/appointments/{appointment_id}/cancel` | Отмена записи | Patient (только своя будущая), Registrar (любая scheduled) |
| GET | `/my` | Записи текущего пациента | Patient |
| GET | `/doctor/appointments` | Записи к текущему врачу | Doctor |
| GET | `/admin/users` | Список пациентов для admin | Admin |
| GET | `/admin/schedule` | Графики врачей, time off и holidays | Admin |
| POST | `/admin/work-hours` | Добавить/обновить график на weekday | Admin |
| POST | `/admin/time-off` | Добавить период отсутствия врача | Admin |
| POST | `/admin/holidays` | Добавить/обновить общий holiday | Admin |
| POST | `/admin/users/{user_id}/block` | Заблокировать пациента | Admin |
| POST | `/admin/users/{user_id}/unblock` | Разблокировать пациента | Admin |
| POST | `/admin/users/{user_id}/cancel-future-appointments` | Отменить будущие scheduled appointments пациента | Admin |
| POST | `/admin/doctors/{doctor_id}/generate` | Идемпотентно сгенерировать слоты на период | Admin |
| POST | `/admin/doctors/{doctor_id}/apply-hours` | Удалить свободные слоты вне текущего окна `work_hours`. Scheduled не отменяет | Admin |

## 9. База данных

### `users`

- `id` — primary key.
- `email` — unique email.
- `password_hash` — bcrypt-хеш пароля.
- `role` — `admin`, `doctor`, `patient` или `registrar`.
- `blocked` — флаг блокировки пациента, по умолчанию `FALSE`.

### `doctors`

- `id` — primary key.
- `user_id` — unique reference на `users`.
- `full_name` — имя врача.
- `specialty` — специальность.
- `experience_years` — стаж.

### `slots`

- `id` — primary key.
- `doctor_id` — reference на `doctors`.
- `starts_at` — начало приема.
- `ends_at` — конец приема.
- `time_range` — generated `tsrange(starts_at, ends_at, '[)')`; конец интервала не включается.

Constraint `slots_no_overlap_per_doctor` использует `EXCLUDE USING gist (doctor_id WITH =, time_range WITH &&)`: временные слоты одного врача не могут пересекаться. Интервалы встык разрешены благодаря границам `[)`. Для работы равенства integer при GiST в `ensure_schema()` и `db/init.sql` включается extension `btree_gist`.

### `work_hours`, `time_off` и `holidays`

- `work_hours`: одна смена врача на weekday; `0 = Monday`, `6 = Sunday`; хранит start/end и `slot_minutes`.
- `time_off`: включительный период отсутствия конкретного врача (`starts_on`–`ends_on`). Повтор одинакового периода для врача предотвращается уникальным индексом.
- `holidays`: общие для клиники праздничные даты и подписи (`day`, `name`).

### `appointments`

- `id` — primary key.
- `slot_id` — reference на `slots`; повторные строки разрешены для истории отмен.
- `patient_user_id` — reference на `users`.
- `status` — по умолчанию `scheduled`.

Индекс `appointments_one_scheduled_per_slot` уникален по `slot_id` только при `status = 'scheduled'`. Он запрещает две живые записи на одном слоте, но позволяет сохранить cancelled-историю и снова использовать освободившийся слот.

## 10. Защита от двойного бронирования

В `book_slot()` выполняются проверки в следующем порядке:

1. Проверяется сессия: бронировать может пациент или registrar.
2. Проверяется существование слота. Если `starts_at <= CURRENT_TIMESTAMP` (часы Postgres, не `datetime.now()` контейнера), возвращается `error=past`.
3. Для patient целевой аккаунт берётся из сессии; registrar указывает email пациента в форме. Находится пользователь с ролью `patient`.
4. Проверяется, что целевой пациент не заблокирован.
5. Выполняется PostgreSQL advisory lock для `patient_id`, чтобы сериализовать его одновременные бронирования.
6. Сначала проверяется, нет ли записи `scheduled` на выбранном `slot_id`. Если слот уже занят, возвращается `error=unavailable`, в том числе при повторном POST или двойном нажатии.
7. Затем проверяется пересечение времени с другими запланированными записями этого пациента. Для конфликта возвращается `error=overlap`.
8. Создаётся `INSERT` со статусом `scheduled` и фиксируется транзакция.

Частичный unique index по `scheduled` остаётся защитой БД от конкурентной записи на один слот. При гонке только один INSERT пройдёт; `UniqueViolation` и `ExclusionViolation` показываются как `unavailable`. Любая другая ошибка INSERT логируется и возвращается как `error=could_not_book`, а не маскируется под занятый слот.

Формула пересечения:

```text
existing.starts_at < requested.ends_at
AND existing.ends_at > requested.starts_at
```

Она блокирует:

- одинаковые интервалы;
- частичное пересечение слева или справа;
- полное вложение одного интервала в другой;
- одинаковое начало у двух врачей;
- одновременные попытки бронирования одного пациента.

Соседние интервалы без общего времени разрешены. Например, `10:00-10:30` и `10:30-11:00` не пересекаются.

Проверяются только записи со статусом `scheduled`. Отменённая запись не блокирует новое время.

Python-overlap пациента остаётся отдельным правилом: один пациент не может записаться на пересекающиеся интервалы у разных врачей. Exclusion constraint ограничивает только расписание одного врача, а partial unique index — две живые записи на один slot_id.

Важно: после отмены слот считается свободным немедленно. Проверки доступности и списка слотов исключают записи со статусом `cancelled`, поэтому другой пациент может забронировать тот же слот после успешной отмены, не встречая ложного `unavailable` или `taken` статуса.

## 10a. Генерация расписания (этап 5a)

`work_hours` хранит по одной рабочей смене врача на день недели: `weekday` использует Python convention, где `0 = Monday`, `6 = Sunday`; `start_time`/`end_time` задают окно смены, `slot_minutes` — длину одного слота. `time_off` задаёт включительный диапазон дат отсутствия врача (`starts_on`–`ends_on`). `holidays` хранит общие для клиники выходные (`day`, `name`). В seed-графике Anna работает понедельник–пятница `09:00–12:00`, Levon — понедельник/среда/пятница `09:00–11:00`; у Anna есть time off `2026-10-12`–`2026-10-18`, holiday — `2026-11-26`.

Только Admin может открыть `/admin/schedule`, добавлять или обновлять work hours через `POST /admin/work-hours`, добавлять периоды отсутствия через `POST /admin/time-off`, сохранять общий holiday через `POST /admin/holidays` и запускать Generate через `POST /admin/doctors/{doctor_id}/generate`. Registrar и врач не имеют этих операций.

Для генерации выбираются врач, `from_date` и `to_date` (включительно); endpoint ограничивает диапазон 90 днями. Для каждого дня генератор пропускает time off, holidays и дни без графика, затем нарезает `[start_time, end_time)` с шагом `slot_minutes`. Слоты в прошлом пропускаются по `CURRENT_TIMESTAMP` базы; Compose фиксирует `TZ=UTC` и у `db`, и у `api`. Повтор одинакового `work_hours` обновляет интервал этого weekday и сам слоты не удаляет. Кнопка `Apply schedule: remove free slots outside hours` отдельно удаляет свободные слоты вне нового окна; scheduled остаются в списке для ручной отмены. Повтор одинакового time-off периода не плодит запись, а holiday на тот же день обновляет название. Закрытие дня не отменяет scheduled: список `Needs manual cancellation` виден на `/admin/schedule`, пока визит не отменят вручную. Слот без scheduled удаляется, даже если на нём осталась только cancelled-история.

Генерация идемпотентна по unique index `slots_doctor_start (doctor_id, starts_at)`. Дубликаты, конфликты с существующими слотами и срабатывания `slots_no_overlap_per_doctor` учитываются как skipped; savepoint позволяет продолжить генерацию остальных интервалов. В результате выводятся `Created N slots, skipped M`. Существующие seed-слоты не удаляются.

Time off и holidays могут быть добавлены после того, как на даты уже сгенерированы слоты. При сохранении закрытого периода приложение удаляет только слоты без appointment history; scheduled визиты сохраняются, их отмена не выполняется автоматически. Admin получает отчёт `Removed N free slots; M scheduled visits still need staff cancellation` со списком пациента, врача и времени и отдельной кнопкой Cancel у каждого визита. Registrar может отменить scheduled-визит из расписания. После Cancel слот остаётся закрытым по календарному правилу и не может быть забронирован повторно; слот с исторической appointment-строкой остаётся в БД из-за FK, но отображается как closed.

Ручная проверка закрытия после генерации: создать будущие слоты, добавить на их дату time off/holiday, убедиться, что свободные слоты удалены, а scheduled визиты перечислены и остались scheduled. Отменить визит отдельным действием и проверить, что закрытый слот не предлагает Book. Block пациента не запускает эту процедуру.

Проверка этапа 5a:

```bash
python3 -m pytest -v tests/test_stage4.py::test_admin_slot_generator_respects_time_off_and_role
python3 -m pytest -v tests/test_stage4.py::test_admin_schedule_configuration_is_admin_only_and_repeatable
```

Для seeded Anna на 2026-10-12 ожидается `Created 0 slots, skipped 6`; Generate на её рабочий день 2026-10-05 создаёт 6 слотов, а повторный запуск — 0 новых и 6 skipped.

### Состояние слотов на странице врача

Запрос списка слотов вычисляет два признака только по appointments со статусом `scheduled`:

- `taken` — слот занят кем-либо;
- `mine` — слот занят пациентом из текущей сессии.

Для patient применяется приоритет `mine` → `taken` → свободный: собственная запись отображается как `Your appointment` со ссылкой на `/my`, чужая — как `Unavailable` без кнопки Book, свободная — с кнопкой `Book appointment`. Registrar видит `Booked` для занятого слота и форму `Book for patient` для свободного. Идентифицирующие данные другого пациента в этом представлении не выводятся. Проверка доступности при POST Book остаётся обязательной: состояние страницы может устареть, пока пользователь её просматривает.

## 11. Ошибки бронирования

При конфликте времени API перенаправляет на `/doctors/{doctor_id}/slots` с параметрами `error=overlap` и `conflict_appointment_id`. Для registrar также передаётся `conflict_patient_id`, чтобы показать конфликт выбранного пациента.

Страница слотов показывает:

- что бронирование не выполнено;
- существующего врача;
- начало и конец уже существующей записи;
- причину: `appointment times overlap`.

Также показывается browser popup.

Если слот уже занят другим пациентом, используется `error=unavailable`. Пользователь видит:

- `This slot is no longer available`;
- причину: другой пациент забронировал слот раньше;
- browser popup.

Конфликтная запись показывается только после проверки, что она принадлежит текущему patient либо выбранному registrar-пациенту и всё ещё имеет статус `scheduled`.

### Отмена

- Patient может отменить только собственную запись со статусом `scheduled`, если `starts_at > CURRENT_TIMESTAMP`; registrar может отменить любую запись со статусом `scheduled`.
- Успешная отмена меняет статус на `cancelled`. Patient возвращается на `/my?cancelled=1`, registrar — на страницу врача со свободным слотом.
- Чужая запись и повторная отмена patient не меняют данные; пользователь получает `/my?cancel_error=1` и сообщение об отказе.
- Если scheduled-визит уже прошёл, patient не видит кнопку Cancel, а прямой POST также отклоняется. Registrar по-прежнему может отменить любую scheduled-запись по решению персонала.
- Cancelled-записи остаются в `/my` как история и отображаются серым цветом. В расписании врача cancelled также отображается серым цветом.
- Cancelled-запись не занимает слот и не участвует в overlap-проверке; слот разрешено забронировать повторно.

Admin может выполнить отдельное действие `Cancel future appointments` для пациента. Оно отменяет только appointments этого пациента со статусом `scheduled`, у которых `starts_at > CURRENT_TIMESTAMP`. Block/Unblock не отменяют appointments. После Block визит остаётся `scheduled`, не исчезает из расписания врача, а показывается с пометкой `account blocked`.

## 12. Сценарий ручной проверки

1. Открыть `http://localhost:8080`.
2. Войти как `pat@clinic.local` / `password123`.
3. Открыть `Doctors`.
4. Открыть слоты Anna.
5. Забронировать Anna `2026-10-01 10:00-10:30`.
6. Открыть слоты Levon и попытаться забронировать `2026-10-01 10:00-10:30`.
7. Должен появиться overlap popup и подробная информация о существующей записи Anna.
8. Для частичного пересечения использовать слоты `2026-10-03 10:00-11:00` у Anna и `2026-10-03 10:30-11:30` у Levon.
9. Проверить `/my`: запись должна показывать и начало, и конец процедуры.
10. Отменить запись из `/my`: она должна стать `cancelled`, остаться серой историей и освободить слот.
11. Повторно отменить ту же запись и попробовать отменить запись другого пациента: оба запроса должны отказать без изменения статуса. Для прошедшей scheduled-записи patient не должен видеть кнопку Cancel, а прямой POST должен отказать.
12. Забронировать освободившийся слот сначала тем же patient, отменить, затем забронировать его как `pat2`.
13. Убедиться, что занятый слот, включая повторный POST на него, даёт `unavailable`; свободный слот с пересечением времени даёт `overlap` и показывает врача/интервал.
14. Для одного активного слота проверить представление: владелец видит `Your appointment` и ссылку на `/my`; другой patient видит только `Unavailable`; registrar видит `Booked`. Для свободного слота проверить кнопки соответствующей роли. Убедиться, что email пациента на странице слотов не отображается.
15. Для 3 октября проверить overlap в обоих направлениях: Anna `10:00-11:00` и Levon `10:30-11:30`.
16. Войти как registrar и забронировать за `pat2@clinic.local`; проверить строку в `/my` пациента и расписании врача. Проверить overlap, пустой email, email врача и несуществующий email.
17. Проверить, что registrar может отменить scheduled-запись пациента со страницы занятого слота; статус должен стать `cancelled`, слот освободиться.
18. Войти как admin и проверить будущий счётчик. Отдельно нажать `Cancel future appointments`: будущие scheduled станут cancelled, а Block/Unblock остаётся отдельным действием.
19. Заблокировать пациента: login должен отказать, но его существующий визит остаётся `scheduled` и виден врачу с пометкой `account blocked`. Затем разблокировать.
20. В Admin сгенерировать слоты Anna на `2026-10-05`: ожидаются 6 созданных слотов; повторить диапазон и убедиться, что дубликаты не появляются.
21. Сгенерировать Anna на `2026-10-12`, который попадает в seeded time off: ожидается 0 созданных слотов.
22. Выполнить `docker compose down` и `docker compose up -d` без `--volumes`; убедиться, что appointments сохранились.

## 13. Проверка базы через psql

Открыть psql:

```bash
docker compose exec db psql -U clinic -d clinic
```

Проверить врачей и слоты:

```sql
SELECT id, full_name, specialty, experience_years
FROM doctors
ORDER BY id;

SELECT id, doctor_id, starts_at, ends_at
FROM slots
ORDER BY starts_at;
```

Проверить записи:

```sql
SELECT a.id, u.email, d.full_name, s.starts_at, s.ends_at, a.status
FROM appointments a
JOIN users u ON u.id = a.patient_user_id
JOIN slots s ON s.id = a.slot_id
JOIN doctors d ON d.id = s.doctor_id
ORDER BY s.starts_at;
```

Удалить одну ошибочную старую запись можно так:

```sql
DELETE FROM appointments
WHERE id = <appointment_id>;
```

Выйти из psql:

```sql
\\q
```

Приёмочные SQL-инварианты: оба запроса должны вернуть пустой результат.

```sql
SELECT slot_id, count(*)
FROM appointments
WHERE status = 'scheduled'
GROUP BY slot_id
HAVING count(*) > 1;

SELECT a1.id, a2.id
FROM appointments a1
JOIN appointments a2
    ON a1.patient_user_id = a2.patient_user_id AND a1.id < a2.id
JOIN slots s1 ON s1.id = a1.slot_id
JOIN slots s2 ON s2.id = a2.slot_id
WHERE a1.status = 'scheduled'
    AND a2.status = 'scheduled'
    AND s1.starts_at < s2.ends_at
    AND s1.ends_at > s2.starts_at;
```

## 14. Git и данные базы

В Git попадут только добавленные в staging файлы проекта:

```bash
git add .
git commit -m "Add clinic booking and overlap validation"
git push
```

Docker containers, images, networks и PostgreSQL volume в Git не попадут. Named volume `db_data` хранится отдельно от рабочей папки.

`.env` исключен через `.gitignore` и не должен коммититься.

Проверить staging:

```bash
git status
git diff --cached
```

Предупреждение `LF will be replaced by CRLF` связано с окончаниями строк Windows и обычно не является ошибкой.

## 15. Известные ограничения

- `seed_clinic()` заполняет врачей и слоты только при пустой таблице `doctors`.
- Если база уже существует, новые seed-слоты не добавятся автоматически.
- Cancelled appointments сохраняются как история; используйте Cancel или отдельный чистый volume для повторного тестирования.
- Все seed-аккаунты, включая `doc2@clinic.local` и `pat2@clinic.local`, перечислены в login-шаблоне.
- Внешний вид остается минимальным учебным HTML без отдельной дизайн-системы.
- В приложении нет CSRF-защиты для POST-бронирования и admin-действий.
- Блокировка пациента запрещает вход и новые бронирования, но не отменяет автоматически уже существующие записи.
- В seed-данных нет короткого слота внутри длинного интервала и пары интервалов встык; эти проверки требуют добавить тестовые слоты вручную.
- График и time off на учебном стенде задаются в БД/seed; редактирование work hours и time off через отдельный UI не входит в этот этап.
- Для production нужны безопасные секреты, миграции схемы, обработка ошибок подключения к БД, структурированное логирование и более строгая модель авторизации.

## 16. Быстрый reset и запуск с нуля

```bash
cd /mnt/c/Users/User/clinic_24_9
docker compose down --volumes --remove-orphans
docker compose up --build -d
docker compose ps
```

После успешного запуска открыть:

```text
http://localhost:8080
```
