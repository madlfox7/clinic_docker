
GET /, GET /doctors, GET /login, POST /logout (CSRF; GET /logout -> 405)	все, включая guest
POST /login	все; уже вошедший не перелогинивается
GET /me	любая сессия, иначе /login
GET /doctors/{id}/slots	patient, registrar
POST /slots/{id}/book	patient (только себя), registrar (по patient_email)
GET /my	patient
GET /doctor/appointments	doctor, только строки своего doctors.user_id
POST /appointments/{id}/cancel	patient — только своя будущая; registrar и admin — любая scheduled
GET, POST /appointments/{id}/reschedule	patient — только своя будущая scheduled; registrar — любая будущая scheduled незаблокированного пациента; doctor и admin — 403
GET /admin/users, GET /admin/schedule	admin
POST /admin/work-hours-bulk, apply-hours, time-off, holidays, generate, block, unblock, cancel-future-appointments	admin, если тело запроса уже распарсилось



