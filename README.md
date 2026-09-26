# Clinic Appointment Application

Учебное приложение клиники на FastAPI, PostgreSQL и Nginx.

## Запуск

В WSL из корня проекта:

```bash
cp .env.example .env
docker compose up --build -d
```

Открыть: http://localhost:8080

Проверить контейнеры:

```bash
docker compose ps
docker compose logs --tail=100 api
```

## Автотесты

Из WSL в корне проекта:

```bash
./tests/run_tests.sh
```

Если уже находишься в `tests/`, команда короче:

```bash
./run_tests.sh
```

Скрипт устанавливает зависимости из `tests/requirements.txt`, поднимает приложение и запускает stage 4 тесты. Он не удаляет Docker volume. Тесты временно создают/отменяют бронирования и блокируют/разблокируют `pat`, поэтому запускай их только против локальной dev-БД, не production.

## Тестовые аккаунты

Пароль для всех аккаунтов: `password123`.

| Email | Role |
|---|---|
| `admin@clinic.local` | admin |
| `doc@clinic.local` | doctor |
| `doc2@clinic.local` | doctor |
| `pat@clinic.local` | patient |
| `pat2@clinic.local` | patient |
| `reg@clinic.local` | registrar |

## Основные возможности

- просмотр врачей и свободных слотов;
- отображение состояния слота отдельно для пациента: своя запись, чужая активная запись или свободно;
- бронирование пациентом или registrar от имени пациента;
- защита от двойного бронирования: один активный appointment на слот;
- overlap-проверка scheduled appointments одного пациента, включая слоты разных врачей;
- отмена собственной записи пациентом;
- повторное бронирование слота после отмены; cancelled-записи сохраняются в истории, но не блокируют слот;
- просмотр своих записей пациентом;
- просмотр приёмов врача;
- блокировка пациентов администратором.

Для быстрой проверки этапа 4 используйте сценарий `Book -> Cancel -> Book` сначала тем же пациентом, затем `pat2`. Занятый слот должен вернуть `unavailable`; другой свободный слот с пересечением времени должен вернуть `overlap`.

На странице слотов пациент видит `Your appointment` для своей записи, `Unavailable` для занятого другим пациентом слота и кнопку `Book appointment` для свободного. Registrar видит `Booked` для занятого слота и форму `Book for patient` для свободного. Имя или email другого пациента на странице слотов не показывается.

Подробная документация находится в [PROJECT_DOCUMENTATION.md](PROJECT_DOCUMENTATION.md).


api/
  Dockerfile
  requirements.txt
  main.py
  templates/
    base.html
    home.html
    login.html
    me.html
    doctors.html
    slots.html
    my_appointments.html
    doctor_appointments.html
    admin_users.html