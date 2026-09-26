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
|-- tests/
|   |-- requirements.txt
|   |-- run_tests.sh
|   `-- test_stage4.py
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

Добавляет колонку `users.blocked`, если ее еще нет, и создает таблицы `doctors`, `slots` и `appointments`, если их еще нет. При старте удаляется прежнее глобальное ограничение `appointments_slot_id_key` и создается частичный unique index только для `status = 'scheduled'`. Эта миграция применяется и к существующему volume без удаления данных. В `db/init.sql` описана та же схема для новой базы.

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
- На странице слотов видит `Your appointment` и ссылку `/my` для собственной активной записи, `Unavailable` для слота с записью другого пациента и `Book appointment` для свободного слота.
- Не может видеть записи другого пациента.

### Doctor

- Может войти в кабинет.
- Может открыть `/doctor/appointments`.
- Видит записи только пациентов, записанных к этому врачу.
- Не может бронировать слот как пациент.

### Registrar

- Может открывать слоты врачей.
- Видит `Booked` на занятом слоте и форму `Book for patient` на свободном.
- Может указать email пациента и забронировать для него свободный слот.
- Для бронирования registrar применяется тот же overlap-check, что и для пациента.
- На странице слотов не показываются имя или email пациента, занявшего слот.

### Admin

- Может войти в систему и открыть кабинет.
- Может открыть `/admin/users`.
- Ссылка `Admin` доступна в общей навигации и в кабинете администратора.
- Может блокировать и разблокировать пользователей с ролью `patient`.
- Заблокированный пациент не может войти и не может получить новое бронирование; форма входа показывает `Account is blocked`.

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
- `slot_id` — reference на `slots`; повторные строки разрешены для истории отмен.
- `patient_user_id` — reference на `users`.
- `status` — по умолчанию `scheduled`.

Индекс `appointments_one_scheduled_per_slot` уникален по `slot_id` только при `status = 'scheduled'`. Он запрещает две живые записи на одном слоте, но позволяет сохранить cancelled-историю и снова использовать освободившийся слот.

## 10. Защита от двойного бронирования

В `book_slot()` выполняются проверки в следующем порядке:

1. Проверяется сессия: бронировать может пациент или registrar.
2. Проверяется существование слота.
3. Для patient целевой аккаунт берётся из сессии; registrar указывает email пациента в форме. Находится пользователь с ролью `patient`.
4. Проверяется, что целевой пациент не заблокирован.
5. Выполняется PostgreSQL advisory lock для `patient_id`, чтобы сериализовать его одновременные бронирования.
6. Сначала проверяется, нет ли записи `scheduled` на выбранном `slot_id`. Если слот уже занят, возвращается `error=unavailable`, в том числе при повторном POST или двойном нажатии.
7. Затем проверяется пересечение времени с другими запланированными записями этого пациента. Для конфликта возвращается `error=overlap`.
8. Создаётся `INSERT` со статусом `scheduled` и фиксируется транзакция.

Частичный unique index по `scheduled` остаётся защитой БД от конкурентной записи на один слот. При гонке только один INSERT пройдёт; проигравший запрос получает `unavailable`.

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

Важно: после отмены слот считается свободным немедленно. Проверки доступности и списка слотов исключают записи со статусом `cancelled`, поэтому другой пациент может забронировать тот же слот после успешной отмены, не встречая ложного `unavailable` или `taken` статуса.

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

- Отменить может только patient-владелец записи со статусом `scheduled`.
- Успешная отмена меняет статус на `cancelled` и перенаправляет на `/my?cancelled=1`.
- Чужая запись и повторная отмена не меняют данные; пользователь получает `/my?cancel_error=1` и сообщение об отказе.
- Cancelled-записи остаются в `/my` как история и отображаются серым цветом. В расписании врача cancelled также отображается серым цветом.
- Cancelled-запись не занимает слот и не участвует в overlap-проверке; слот разрешено забронировать повторно.

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
11. Повторно отменить ту же запись и попробовать отменить запись другого пациента: оба запроса должны отказать без изменения статуса.
12. Забронировать освободившийся слот сначала тем же patient, отменить, затем забронировать его как `pat2`.
13. Убедиться, что занятый слот, включая повторный POST на него, даёт `unavailable`; свободный слот с пересечением времени даёт `overlap` и показывает врача/интервал.
14. Для одного активного слота проверить представление: владелец видит `Your appointment` и ссылку на `/my`; другой patient видит только `Unavailable`; registrar видит `Booked`. Для свободного слота проверить кнопки соответствующей роли. Убедиться, что email пациента на странице слотов не отображается.
15. Для 3 октября проверить overlap в обоих направлениях: Anna `10:00-11:00` и Levon `10:30-11:30`.
16. Войти как registrar и забронировать за `pat2@clinic.local`; проверить строку в `/my` пациента и расписании врача. Проверить overlap, пустой email, email врача и несуществующий email.
17. Войти как admin, заблокировать `pat2`, проверить запрет входа и registrar-booking, затем разблокировать. Блокировка не должна удалять существующие записи.
18. Выполнить `docker compose down` и `docker compose up -d` без `--volumes`; убедиться, что appointments сохранились.

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
