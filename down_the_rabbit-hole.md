# Clinic Appointment Application

## 1. Назначение проекта

Это учебное веб-приложение клиники: пользователи могут войти, просмотреть врачей и свободные слоты, а затем записаться на приём. Предусмотрены роли пациента, врача, регистратора и администратора.

Интерфейс, имена демонстрационных врачей и специальности — на английском языке, латиницей.

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
|   |-- db.py
|   |-- routes_auth.py
|   |-- routes_booking.py
|   |-- routes_admin.py
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

PostgreSQL 16, адрес внутри Compose — `db`, данные в named volume `db_data`. `db/init.sql` монтируется в `/docker-entrypoint-initdb.d/init.sql`; healthcheck — `pg_isready`.

### `api`

Собирается из `api/Dockerfile` (Python 3.12, Uvicorn, приложение из `api/main.py`); `./api` монтируется в `/app`. Подключён к `frontend` и `backend`, ждёт `healthy` от PostgreSQL.

### `proxy`

Nginx `1.27-alpine`, порт `8080` → `api:8000`; конфигурация — `proxy/nginx.conf`.

Сеть `backend` объявлена `internal: true` и соединяет API с базой; `frontend` соединяет proxy и API.

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

Сайт: `http://localhost:8080`. Проверка:

```bash
docker compose ps
docker compose logs --tail=100 api
```

После изменения Python-кода пересоберите API:

```bash
docker compose up -d --build api
```

Для изменений только в смонтированном коде достаточно перезапустить API:

```bash
docker compose restart api
```

### Запуск автоматических тестов этапа 4

Из WSL в корне проекта:

```bash
./tests/run_tests.sh
```

Из `tests/`:

```bash
./run_tests.sh
```

Скрипт находит корень, запускает Compose без удаления volume, ждёт `http://localhost:8080` и запускает `pytest -v tests/test_stage4.py`. Зависимости закреплены в `tests/requirements.txt`; без `python3-venv` используется `pip --user`, иначе — `.venv-tests/` (в `.gitignore`).

Тесты проверяют роли, вход, Book/Cancel, overlap, registrar и admin block. Они создают и отменяют appointments; admin-тест также блокирует и разблокирует `pat@clinic.local`. Запускайте только на локальной dev-БД, не production: volume сохраняется, но тестовые записи и последовательности ID могут измениться.

### Эксперимент конкурентного бронирования

Найдите свободный слот:

```sql
SELECT s.id, d.full_name, s.starts_at
FROM slots s
JOIN doctors d ON d.id = s.doctor_id
LEFT JOIN appointments a
    ON a.slot_id = s.id AND a.status = 'scheduled'
WHERE a.id IS NULL
ORDER BY s.id;
```

Из WSL, из корня проекта, отправьте на выбранный slot ID сначала 10, затем 50 одновременных POST-запросов:

```bash
python3 experiments/concurrent_book.py 2 10
python3 experiments/concurrent_book.py 2 50
```

Замените `2` на свободный ID. Между прогонами отмените winner (или смените status на `cancelled`), иначе второй проверит занятый слот. `GROUP BY slot_id, status` должен показать ровно одну строку `scheduled`. Скрипт синхронизирует POST барьером; результаты — в `experiments/concurrent_book_results.md`.

Эксперимент меняет локальную БД и оставляет cancelled history. Запускайте только на dev-данных; удалять volume не нужно.

### Stage 5 — конкурентность и ограничения слотов

Результаты одновременного бронирования одного свободного slot `2` (Anna, 2026-10-01 10:00), дата проверки — 2026-09-27:

| Одновременные POST-запросы | Accepted | Rejected | `scheduled` после прогона |
|---:|---:|---:|---:|
| 10 | 1 | 9 | 1 |
| 50 | 1 | 49 | 1 |

Тестовую запись отменяли после каждого прогона; активной записи на slot `2` в БД нет.

Регрессия этапов 4/5a (из корня):

```bash
python3 -m pytest -v tests/test_stage4.py
```

Последний полный прогон: `16 passed, 1 skipped`. Отдельный generator/time-off тест: `python3 -m pytest -v tests/test_stage4.py::test_admin_slot_generator_respects_time_off_and_role`.

## 5. Переменные окружения

Файл `.env` не должен добавляться в Git. Шаблон находится в `.env.example`:

```env
POSTGRES_USER=clinic
POSTGRES_PASSWORD=change_me
POSTGRES_DB=clinic
CLINIC_API_PASSWORD=change_me_api
SESSION_SECRET=dev-secret-change-me
HOST_UID=1000
HOST_GID=1000
```

Для реального окружения необходимо заменить пароли базы и API, а также `SESSION_SECRET` на секретные значения.

## 6. Инициализация приложения

До запуска API сервис `migrate` подключается как `POSTGRES_USER`, применяет `db/init.sql`, создаёт `clinic_api` и выдаёт ей ограниченные права. На новом volume стандартный PostgreSQL entrypoint также выполняет `db/init.sql` и `db/roles.sql`; на существующем их повторно применяет `migrate`, не удаляя данные.

API и `seed` используют `clinic_api` (не суперпользователь, без `BYPASSRLS`, не может создавать объекты в `public`). Его пароль берётся из `CLINIC_API_PASSWORD` в локальном `.env`; пароль владельца БД получает только `migrate`.

RLS включён для `appointments`, `visit_notes`, `prescriptions` и `users`; прямого `SELECT` на `password_hash` у `clinic_api` нет. Вход проверяет функция `SECURITY DEFINER`. `seed` создаёт первого администратора отдельной функцией, доступной только `clinic_api` и только при пустой таблице `users`; остальные тестовые записи создаются через `app_guest` и `app_admin`. Защищённые API-запросы используют отдельное соединение `db_as(user)` с транзакционными `SET LOCAL ROLE` и `app.user_id`.

При старте FastAPI выполняются только сиды:

```text
seed_users()
seed_clinic()
seed_work_schedule()
```

### `seed_users()`

Идемпотентно добавляет отсутствующих пользователей по email.

Тестовые аккаунты (пароль у всех один, из Docker secret `secrets/demo_password`):

| Email | Role |
|---|---|
| `admin@clinic.local` | `admin` |
| `doc@clinic.local` | `doctor` |
| `doc2@clinic.local` | `doctor` |
| `pat@clinic.local` | `patient` |
| `pat2@clinic.local` | `patient` |
| `reg@clinic.local` | `registrar` |

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

Интервалы 3 октября частично пересекаются. Для проверки вложения и правила «встык разрешено» вручную добавьте слот `10:15-10:45` и пару смежных интервалов.

Сидовые слоты 1–3 октября предназначены для overlap-тестов и не пересобираются кнопкой Generate; генератор использует `work_hours`.

Seed врачей и слотов срабатывает только при пустой таблице `doctors`; в существующую базу новые seed-слоты не добавятся.

Чтобы получить полностью свежие тестовые данные:

```bash
docker compose down --volumes --remove-orphans
docker compose up --build -d
```

Команда удаляет PostgreSQL volume и все данные базы.

## 7. Роли и права

| Роль | Возможности и ограничения |
|---|---|
| Гость | Главная с публичными адресом, телефоном и часами работы; список врачей и вход. Не бронирует; при открытии слотов перенаправляется на `/login`. |
| Patient | Врачи, слоты, бронирование и `/my`; видит только свои записи, может отменить собственную будущую `scheduled`. |
| Doctor | Кабинет и `/doctor/appointments`; видит только своих пациентов, начало/конец визита и `account blocked`. Не бронирует как patient. |
| Registrar | Бронирует по email пациента с тем же overlap-check, может отменить любую `scheduled` со страницы слотов. Имена и email пациентов не показываются. |
| Admin | Кабинет, `/admin/users`, ссылка `Admin` в навигации; блокирует/разблокирует пациентов, видит счётчик будущих `scheduled` и отдельно отменяет их через `Cancel future appointments`. Block запрещает вход и новые записи (`Account is blocked`), но не меняет существующие визиты; врач видит `account blocked`. |

## 8. HTTP-маршруты

| Method | Path | Назначение | Доступ |
|---|---|---|---|
| GET | `/` | Главная страница | Все |
| GET | `/login` | Форма входа. Если сессия уже есть, перенаправление на `/me` без запроса пароля | Гость |
| POST | `/login` | Авторизация. Повторный POST при активной сессии не меняет её и возвращает в `/me` | Гость |
| POST | `/logout` | Очистка сессии (нужен CSRF-токен формы; `GET /logout` -> 405, сессия остаётся) | Авторизованные |
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

`id` — primary key; `email` — unique; `password_hash` — bcrypt-хеш; `role` — `admin`, `doctor`, `patient` или `registrar`; `blocked` — флаг блокировки пациента, по умолчанию `FALSE`.

### `doctors`

`id` — primary key; `user_id` — unique reference на `users`; `full_name`, `specialty`, `experience_years` — имя, специальность и стаж врача.

### `slots`

`id` — primary key; `doctor_id` — reference на `doctors`; `starts_at`/`ends_at` — границы; `time_range` — generated `tsrange(starts_at, ends_at, '[)')` (конец не включён).

`slots_no_overlap_per_doctor` запрещает пересечение слотов врача: `EXCLUDE USING gist (doctor_id WITH =, time_range WITH &&)`. Смежные слоты разрешены благодаря `[)`. Для сравнения integer в GiST `ensure_schema()` и `db/init.sql` включают `btree_gist`.

### `work_hours`, `time_off` и `holidays`

- `work_hours`: смена врача на weekday (`0 = Monday`, `6 = Sunday`), start/end и `slot_minutes`.
- `time_off`: включительный диапазон отсутствия врача (`starts_on`–`ends_on`); одинаковый период предотвращает уникальный индекс.
- `holidays`: общие праздничные даты и подписи (`day`, `name`).

### `appointments`

`id` — primary key; `slot_id` — reference на `slots` (повторы сохраняют историю отмен); `patient_user_id` — reference на `users`; `status` по умолчанию `scheduled`.

Частичный unique index `appointments_one_scheduled_per_slot` по `slot_id` действует только при `status = 'scheduled'`: он исключает две активные записи на слот, сохраняя историю `cancelled` и возможность повторной записи.

## 10. Защита от двойного бронирования

`book_slot()` выполняет проверки в таком порядке:

1. Проверяется сессия: бронировать могут пациент и registrar.
2. Проверяется наличие слота и его время. При `starts_at <= CURRENT_TIMESTAMP` (часы Postgres, не `datetime.now()` контейнера) возвращается `error=past`.
3. Целевой аккаунт patient берётся из сессии; registrar вводит email. Проверяется роль `patient`.
4. Проверяется, что пациент не заблокирован.
5. Выполняется PostgreSQL advisory lock для `patient_id`, чтобы сериализовать его одновременные бронирования.
6. Сначала проверяется, нет ли записи `scheduled` на выбранном `slot_id`. Если слот уже занят, возвращается `error=unavailable`, в том числе при повторном POST или двойном нажатии.
7. Затем проверяется пересечение времени с другими запланированными записями этого пациента. Для конфликта возвращается `error=overlap`.
8. Создаётся запись `scheduled` (`INSERT`) и фиксируется транзакция.

Частичный unique index по `scheduled` защищает от конкурентной записи на слот: при гонке проходит только один `INSERT`. `UniqueViolation` и `ExclusionViolation` отображаются как `unavailable`; другие ошибки `INSERT` логируются и возвращаются как `error=could_not_book`.

Формула пересечения:

```text
existing.starts_at < requested.ends_at
AND existing.ends_at > requested.starts_at
```

Проверка обнаруживает одинаковые и частично пересекающиеся интервалы, вложение, одинаковое начало у разных врачей и параллельные бронирования пациента. Смежные интервалы разрешены: `10:00-10:30` и `10:30-11:00` не пересекаются.

Учитываются только записи `scheduled`; отменённые не блокируют новое время.

Python-проверка overlap в `book_slot()` возвращает `error=overlap`; БД дублирует её через `appointments_no_overlap_per_patient` — `EXCLUDE USING gist` по `patient_user_id` и `period` для `scheduled`. `ExclusionViolation` этого constraint даёт `error=overlap`, прочие exclusion/unique — `unavailable`, без 500. Сессия хранит `user_id`; роль и `blocked` на защищённых маршрутах читаются из `users`, не из cookie.

После отмены слот сразу доступен: проверки исключают `cancelled`, поэтому новый пациент не получит ложный `unavailable` или статус `taken`.

## 10a. Генерация расписания (этап 5a)

`work_hours` хранит одну смену врача на день недели: `weekday` следует Python convention (`0 = Monday`, `6 = Sunday`), `start_time`/`end_time` задают окно, `slot_minutes` — длину слота. `time_off` задаёт включительный диапазон отсутствия (`starts_on`–`ends_on`); `holidays` — общий выходной (`day`, `name`). В seed-графике Anna работает пн–пт `09:00–12:00`, Levon — пн/ср/пт `09:00–11:00`; у Anna time off `2026-10-12`–`2026-10-18`, holiday — `2026-11-26`.

Только Admin может открыть `/admin/schedule`, редактировать график (`POST /admin/work-hours`), добавить отсутствие (`POST /admin/time-off`) или holiday (`POST /admin/holidays`) и запустить Generate (`POST /admin/doctors/{doctor_id}/generate`). Registrar и врач этих прав не имеют.

Для генерации выбирают врача и включительный диапазон `from_date`–`to_date` (не более 90 дней). Генератор пропускает time off, holidays и дни без графика; остальные окна нарезает на слоты длиной `slot_minutes` в пределах `[start_time, end_time)`. Прошедшие слоты отсеиваются по `CURRENT_TIMESTAMP` БД; Compose задаёт `TZ=UTC` для `db` и `api`.

Повторное сохранение `work_hours` обновляет смену weekday, но не удаляет слоты. `Apply schedule: remove free slots outside hours` удаляет свободные слоты за пределами нового окна; `scheduled` остаются для ручной отмены. Повторный time-off период не создаёт дубликат, а повторный holiday на тот же день обновляет название. Закрытие дня не отменяет `scheduled`: `/admin/schedule` показывает их в `Needs manual cancellation` до ручной отмены. Слот без `scheduled` удаляется, даже если сохранилась только `cancelled`-история.

Unique index `slots_doctor_start (doctor_id, starts_at)` делает генерацию идемпотентной. Дубликаты, конфликты с существующими слотами и нарушения `slots_no_overlap_per_doctor` считаются skipped; savepoint позволяет продолжить остальные интервалы. Результат: `Created N slots, skipped M`. Seed-слоты не удаляются.

Time off и holidays можно добавить после генерации слотов. При сохранении закрытого периода удаляются только слоты без appointment history; `scheduled` визиты сохраняются и не отменяются автоматически. Admin видит отчёт `Removed N free slots; M scheduled visits still need staff cancellation` со списком пациента, врача и времени, а также отдельную кнопку Cancel для каждого визита. Registrar тоже может отменить `scheduled` из расписания. После отмены слот остаётся закрытым и недоступным для повторного бронирования; из-за FK он остаётся в БД, если у него есть история appointment, но отображается как closed.

Ручная проверка: создать будущие слоты, закрыть их дату через time off/holiday, проверить удаление свободных слотов и сохранение `scheduled` с отображением в отчёте. Отменить визит отдельно и убедиться, что закрытый слот не предлагает Book. Block пациента эту процедуру не запускает.

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

При overlap API перенаправляет на `/doctors/{doctor_id}/slots?error=overlap&service_id=…`; для registrar сохраняется введённый `patient_email`. ID пациента и записи в URL не попадают: страница находит ближайший конфликт по сессии patient или указанному email.

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

Конфликтная запись отображается, только если она принадлежит текущему patient или выбранному registrar-пациенту и имеет статус `scheduled`.

### Отмена

- Patient может отменить только свою будущую (`starts_at > CURRENT_TIMESTAMP`) запись `scheduled`; registrar — любую `scheduled`.
- Успешная отмена меняет статус на `cancelled`. Patient возвращается на `/my?cancelled=1`, registrar — на страницу врача со свободным слотом.
- Чужая запись и повторная отмена patient не меняют данные; ответ — `/my?cancel_error=1` с сообщением об отказе.
- Для прошедшего `scheduled` визита patient не видит Cancel, а прямой POST отклоняется. Registrar может отменить любую `scheduled` запись по решению персонала.
- Cancelled-записи остаются в `/my` как история и отображаются серым цветом. В расписании врача cancelled также отображается серым цветом.
- `Cancelled` не занимает слот и не участвует в overlap-проверке; его можно забронировать повторно.

Действие Admin `Cancel future appointments` отменяет только `scheduled` appointments пациента с `starts_at > CURRENT_TIMESTAMP`. Block/Unblock их не отменяют: визит остаётся в расписании врача со статусом `scheduled` и пометкой `account blocked`.

## 12. Сценарий ручной проверки

1. Открыть `http://localhost:8080`, войти как `pat@clinic.local` (пароль из `secrets/demo_password`), выбрать Doctors → Anna.
2. Забронировать Anna `2026-10-01 10:00-10:30`; у Levon попробовать то же время. Проверить overlap popup с данными записи Anna.
3. Проверить частичный overlap в обоих направлениях: Anna `2026-10-03 10:00-11:00`, Levon `2026-10-03 10:30-11:30`.
4. В `/my` проверить начало/конец записи; отменить её и проверить серую историю и освобождение слота. Повторная отмена и отмена чужой записи не должны менять данные; для прошедшего визита patient не видит Cancel, прямой POST отклоняется.
5. Забронировать освобождённый слот тем же patient, отменить и забронировать как `pat2`.
6. Проверить: занятый слот (включая повторный POST) возвращает `unavailable`; свободный с overlap показывает врача/интервал. На активном слоте владелец видит `Your appointment` и `/my`, другой patient — `Unavailable`, registrar — `Booked`. Проверить кнопки свободного слота и отсутствие email пациента.
7. Registrar бронирует для `pat2@clinic.local`: проверить `/my`, расписание врача, overlap, пустой email, email врача и неизвестный email. Проверить отмену registrar со страницы занятого слота: статус `cancelled`, слот свободен.
8. Admin проверяет будущий счётчик и запускает `Cancel future appointments` (будущие `scheduled` становятся `cancelled`); Block/Unblock остаётся отдельным действием. После Block login отклоняется, но визит остаётся `scheduled` и виден врачу с `account blocked`; затем разблокировать.
9. В Admin сгенерировать Anna на `2026-10-05` (6 слотов), повторить без дубликатов; на `2026-10-12` (seeded time off) ожидается 0 слотов.
10. Выполнить `docker compose down`, затем `docker compose up -d` без `--volumes`; проверить сохранность appointments.

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

В Git входят файлы проекта из staging; контейнеры, образы, сети и volume `db_data` хранятся отдельно. `.env` исключён через `.gitignore`.

```bash
git add .
git commit -m "Add clinic booking and overlap validation"
git push
```

```bash
git status
git diff --cached
```

`LF will be replaced by CRLF` обычно лишь предупреждает об окончаниях строк Windows.

## 15. Известные ограничения

- Все seed-аккаунты, включая `doc2@clinic.local` и `pat2@clinic.local`, перечислены в login-шаблоне.
- Интерфейс — минимальный учебный HTML без дизайн-системы.
- В приложении нет CSRF-защиты для POST-бронирования и admin-действий.
- График и time off на учебном стенде задаются в БД/seed; редактирование work hours и time off через отдельный UI не входит в этот этап.
- Для production нужны безопасные секреты, миграции схемы, обработка ошибок подключения к БД, структурированное логирование и более строгая авторизация.

## 16. Быстрый reset и запуск с нуля

```bash
cd /mnt/c/Users/User/clinic_24_9
docker compose down --volumes --remove-orphans
docker compose up --build -d
docker compose ps
```

После запуска откройте:

```text
http://localhost:8080
```

## Заметки о RLS

Выступление Пола Копплстоуна на *POSETTE: An Event for Postgres 2024* посвящено PostgreSQL Row Level Security (RLS).

- **Назначение (02:11–04:24):** RLS ограничивает доступ к строкам на уровне БД, как неявное условие `WHERE`.
- **Польза:** безопасность за счёт контроля в БД (04:25–05:24); потенциально меньше сетевых запросов между приложением и БД (05:25–06:38).
- **Включение (06:39–07:44):** `ALTER TABLE table_name ENABLE ROW LEVEL SECURITY;`
- **Политики (08:29–09:09):** отдельная политика для каждой операции (`SELECT`, `INSERT`, `UPDATE`, `DELETE`) даёт более точный контроль.
- **`USING` и `WITH CHECK` (09:41–11:41):** `USING` проверяет существующие строки (например, при `SELECT`), `WITH CHECK` — данные `INSERT`/`UPDATE`.
- **Оптимизация:** вызывать функции в политиках через `SELECT`, чтобы планировщик выполнял их один раз, а не на каждую строку (12:56–13:47); предпочитать `STABLE` функциям `VOLATILE` (14:06–14:46); добавлять явный `WHERE` для предварительной фильтрации и при включённом RLS (15:47–16:26).
