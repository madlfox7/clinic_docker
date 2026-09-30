Логин и сессия

Верный email, неверный пароль → только «Invalid…»  & vice versa check
admin@clinic.local + пустой пароль (del required в DevTools и отправьте) → сервер не пускает и empty login, pass
login , pass + error sym length parsing test like extrasymbols add 
SQL в поле: ' OR 1=1 -- и admin@clinic.local'-- → снова invalid.

Очень длинная строка в email/password (10–50 KB) → не падение api.-

После успешного входа скопировать Cookie session, выйти, подставить cookie 
(too lazy for this one, later)

Войти как pat, в том же браузере /admin/users и /admin/schedule → login.

Войти как doctor, POST /admin/work-hours из DevTools (?)



----------------

Chrome / Edge
http://localhost:8080/login.
F12 → вкладка Elements (Элементы).
Клик по полю Email или Password на странице (или в дереве найдите <input name="email" / password).

Бронирование

Book один слот дважды подряд (две вкладки, две сессии pat и pat2) → один scheduled.+
Подставить чужой slot_id (999999) → не 500.
Registrar book без patient_email / с несуществующим email.
Patient POST book на слот в прошлом / на closed day.
Менять patient_email в форме пациента на чужой → должен писать только себя.

Роли с URL
Без логина и под каждой ролью открыть:
/, /doctors, /doctors/1/slots, /my, /doctor/appointments, /admin/users, /admin/schedule
Гость не видит чужие записи. Admin не должен из URL стать врачом.
Парсинг полей графика

range, len + trailing witespace error testing
slot_minutes=0, -1, 999999
end_time раньше start_time
weekday 7 или -1
date 2026-02-31
Generate диапазон > 90 дней


Заголовки / прокси
Bashcurl -i http://localhost:8080/login
curl -i http://127.0.0.1:5432  (port test)


Bashcurl -i http://localhost:8000/
good one: connection refused 