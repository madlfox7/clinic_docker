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
- бронирование пациентом или registrar от имени пациента;
- защита от двойного бронирования и пересечения времени;
- отмена собственной записи пациентом;
- просмотр своих записей пациентом;
- просмотр приёмов врача;
- блокировка пациентов администратором.

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