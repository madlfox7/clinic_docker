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
|       `-- admin_users.html
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

Добавляет колонку `users.blocked`, если ее еще нет, и создает таблицы `doctors`, `slots` и `appointments`, если их еще нет. В `db/init.sql` также описана актуальная схема, поэтому новая база и существующий volume поддерживаются при старте API.

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

После этого создаются обычные 30-минутные слоты и дополнительные интервалы для проверки overlap:

- Anna: `2026-10-03 10:00-11:00`;
- Levon: `2026-10-03 10:30-11:30`.

Эти два интервала частично пересекаются.

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
- Может открыть список врачей.
- Может открыть форму входа.
- Не может бронировать слот.
- При попытке открыть слоты врача перенаправляется на `/login`.

### Patient

- Может открыть список врачей.
- Может открыть слоты врача.
- Может забронировать свободный слот.
- Может открыть `/my` и увидеть свои записи.
- Может отменить только свои записи со статусом `scheduled`.
- Не может видеть записи другого пациента.

### Doctor

- Может войти в кабинет.
- Может открыть `/doctor/appointments`.
- Видит записи только пациентов, записанных к этому врачу.
- Не может бронировать слот как пациент.

### Registrar

- Может открывать слоты врачей.
- Может видеть свободные и занятые слоты.
- Может указать email пациента и забронировать для него свободный слот.
- Для бронирования registrar применяется тот же overlap-check, что и для пациента.

### Admin

- Может войти в систему и открыть кабинет.
- Может открыть `/admin/users`.
- Может блокировать и разблокировать пользователей с ролью `patient`.
- Заблокированный пациент не может войти и не может получить новое бронирование.

## 8. HTTP-маршруты

| Method | Path | Назначение | Доступ |
|---|---|---|---|
| GET | `/` | Главная страница | Все |
| GET | `/login` | Форма входа | Все |
| POST | `/login` | Авторизация | Все |
| GET | `/logout` | Очистка сессии | Авторизованные |
| GET | `/me` | Кабинет текущего пользователя | Авторизованные |
| GET | `/doctors` | Список врачей | Все |
| GET | `/doctors/{doctor_id}/slots` | Слоты выбранного врача | Patient, Registrar |
| POST | `/slots/{slot_id}/book` | Бронирование слота для текущего пациента или указанного registrar-пациента | Patient, Registrar |
| POST | `/appointments/{appointment_id}/cancel` | Отмена собственной записи | Patient |
| GET | `/my` | Записи текущего пациента | Patient |
| GET | `/doctor/appointments` | Записи к текущему врачу | Doctor |
| GET | `/admin/users` | Список пациентов для admin | Admin |
| POST | `/admin/users/{user_id}/block` | Заблокировать пациента | Admin |
| POST | `/admin/users/{user_id}/unblock` | Разблокировать пациента | Admin |

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

### `appointments`

- `id` — primary key.
- `slot_id` — unique reference на `slots`.
- `patient_user_id` — reference на `users`.
- `status` — по умолчанию `scheduled`.

`UNIQUE(slot_id)` не позволяет двум пациентам одновременно занять один и тот же слот одного врача.

## 10. Защита от двойного бронирования

В `book_slot()` выполняются проверки в следующем порядке:

1. Проверяется сессия: бронировать может пациент или registrar.
2. Для patient берётся его email, для registrar — email из формы; находится `patient_id` целевого пациента.
3. Выполняется PostgreSQL advisory lock для этого пациента. Это сериализует одновременные попытки бронирования одного пациента.
4. Проверяется существование выбранного слота.
5. Ищется уже запланированная запись этого пациента с пересекающимся временем.
6. Используется стандартная проверка `UNIQUE(slot_id)` для занятого слота.
7. Выполняется `INSERT` в `appointments` внутри транзакции.

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

Проверяются только записи со статусом `scheduled`. Отмененная запись не блокирует новое время.

## 11. Ошибки бронирования

При конфликте времени API перенаправляет на:

```text
/doctors/{doctor_id}/slots?error=overlap&conflict_appointment_id=...
```

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

Конфликтная запись загружается только для текущего пациента: переданный ID дополнительно проверяется через его email.

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
10. Нажать `Cancel appointment` в `/my`. Запись должна перейти в `cancelled` и перестать блокировать время.
11. Войти как `pat2@clinic.local` / `password123` и попробовать занять уже забронированный слот. Должно появиться сообщение `unavailable`.
12. Войти как `reg@clinic.local` / `password123`, открыть слоты и ввести `pat@clinic.local` в поле `Patient email`. Registrar должен создать запись для пациента.
13. Повторить registrar-бронирование на пересекающееся время. Должно появиться сообщение `overlap`.
14. Войти как `doc@clinic.local` и открыть `My appointments`. Врач должен видеть только записи к себе.
15. Войти как `admin@clinic.local`, открыть `Manage patients` и заблокировать `pat2@clinic.local`.
16. Проверить вход и бронирование под `pat2@clinic.local`: вход должен быть запрещен, а registrar должен получить `patient_blocked`.
17. Разблокировать `pat2@clinic.local` и убедиться, что вход снова разрешен.

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
- Старые дублирующиеся записи не удаляются автоматически; их нужно проверить и удалить вручную.
- Все seed-аккаунты, включая `doc2@clinic.local` и `pat2@clinic.local`, перечислены в login-шаблоне.
- Внешний вид остается минимальным учебным HTML без отдельной дизайн-системы.
- В приложении нет CSRF-защиты для POST-бронирования и admin-действий.
- Блокировка пациента запрещает вход и новые бронирования, но не отменяет автоматически уже существующие записи.
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
