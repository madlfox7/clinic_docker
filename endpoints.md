# Доступ к API

| Метод и путь | Доступ |
|---|---|
| `GET /`, `GET /doctors`, `GET /login`, `POST /logout` (CSRF; `GET /logout` → 405) | Все, включая `guest` |
| `POST /login` | Все; вошедший пользователь не может войти повторно |
| `GET /me` | Любая сессия; иначе редирект на `/login` |
| `GET /doctors/{id}/slots` | `patient`, `registrar` |
| `POST /slots/{id}/book` | `patient` (только для себя), `registrar` (по `patient_email`) |
| `GET /my` | `patient` |
| `GET /doctor/appointments` | `doctor`; только строки с его `doctors.user_id` |
| `POST /appointments/{id}/cancel` | `patient` — только своя будущая запись; `registrar` и `admin` — любая `scheduled` |
| `GET`, `POST /appointments/{id}/reschedule` | `patient` — только своя будущая `scheduled`; `registrar` — любая будущая `scheduled` незаблокированного пациента; `doctor` и `admin` — 403 |
| `GET /admin/users`, `GET /admin/schedule` | `admin` |
| `POST /admin/work-hours-bulk`, `apply-hours`, `time-off`, `holidays`, `generate`, `block`, `unblock`, `cancel-future-appointments` | `admin`, если тело запроса уже распарсилось |



