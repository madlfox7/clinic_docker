# Clinic Appointment Application

FastAPI, PostgreSQL и Nginx.

API подключается к PostgreSQL ролью `clinic_api`; `POSTGRES_USER` остаётся для миграций и администрирования. Одноразовый сервис `migrate` применяет схему, роли и RLS-политики до запуска API. Роли `app_guest`, `app_patient`, `app_doctor`, `app_registrar` и `app_admin` используются как контексты доступа.

RLS включён для `appointments`, `visit_notes` и `prescriptions`; `users` пока не защищена RLS, чтобы работали вход и проверка сессии. Для защищённых запросов API использует `db_as(user)`: на отдельном соединении транзакционно устанавливаются `SET ROLE` и `app.user_id`. Вход, проверка сессии и публичный список врачей продолжают использовать `clinic_api`. Врач получает данные пациентов только через ограниченную функцию `doctor_patients()`, а не прямым чтением `users`.



```bash
cp .env.example .env
# Замените CLINIC_API_PASSWORD на случайный URL-safe пароль, например:
openssl rand -hex 32
docker compose up --build -d
```

Скопируйте сгенерированный пароль в `CLINIC_API_PASSWORD` внутри `.env`. Не добавляйте `.env` в Git и не передавайте `POSTGRES_PASSWORD` контейнеру API. На существующем `db_data` миграция создаёт роль и выдаёт права без удаления тома.

 http://localhost:8080

(nginx only, for now without tls)


```bash
docker compose ps
docker compose logs --tail=100 api
```

./tests/run_tests.sh

current tree:

├── README.md
├── app
│   ├── db.py
│   ├── main.py
│   ├── requirements.txt
│   ├── routes_admin.py
│   ├── routes_auth.py
│   ├── routes_booking.py
│   └── templates
│       ├── admin_schedule.html
│       ├── admin_users.html
│       ├── base.html
│       ├── doctor_appointments.html
│       ├── doctors.html
│       ├── home.html
│       ├── login.html
│       ├── me.html
│       ├── my_appointments.html
│       └── slots.html
├── db
│   └── init.sql
├── docker
│   ├── api
│   │   └── Dockerfile
│   ├── db
│   │   └── Dockerfile
│   └── proxy
│       ├── Dockerfile
│       └── nginx.conf
├── docker-compose.yml
├── down_the_rabbit-hole.md
├── experiments
│   └── concurrent_book.py
└── tests
    ├── requirements.txt
    ├── run_tests.sh
    └── test_stage4.py

Q1: TRAEFIK? (maybe, but instead of nginx, or with nginx(but why two proxies?)
The lab uses Traefik for routing by hostname. I have a single hostname and one app.
Is Nginx enough as reverse proxy or should I use Traefik? 
If Traefik is required, should it replace nginx rather than sit in front of it?

q2: Two Nginx containers (front / admin) ref: lab1
In the lab, front and admin are two Nginx containers and two hostnames.
Here done by application roles in Python, not by two web roots.
Is role-based admin inside one application acceptable or I need  separate admin container/hostname?

q3:PHP
FastApi instead of PHP.... (+)




Todo: retest app logic, rls implementation + test again(all the time) + some polishment and then backup, docker socket proxy .... 
+ DOCCUMENTATION (in armenian)

TODO DRAFT for business logic: all is ok in working hours graffic and slot generation, but in api, I have work hours, and it can be changed with save work hours and input of start end hours for each day, its fine, but I also want a small thing in admin like general work hours apply, or one thing taht apply for all days, or weekends? 
so you can set days like its doen and hours and also with general like all 7 days mon-sat or sun, or where week ends and like option for general schedule time changer , so mon - fri(or sun or sat) start input as for one day and end as like in one day case.


TODO: RLS and clean  up
