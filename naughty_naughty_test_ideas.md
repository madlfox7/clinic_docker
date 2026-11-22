# Негативные проверки

## Вход / роли

- Верный email с неверным паролем и наоборот → `Invalid…`. Удалить `required` у `admin@clinic.local`, отправить пустые поля через DevTools → сервер отклоняет запрос.
- Спецсимволы и строки email/пароля 10–50 KB → API не падает. SQL в email: `' OR 1=1 --`, `admin@clinic.local'--` → `Invalid`.
- Cookie (отложено): войти, скопировать cookie, выйти, подставить повторно.
- Под `pat` открыть `/admin/users`, `/admin/schedule`; под doctor отправить POST `/admin/work-hours` из DevTools.
- Chrome/Edge: `http://localhost:8080/login` → F12 → Elements → выбрать поле или найти `<input name="email">` / `<input name="password">`.

## Бронирование

- Два одновременных бронирования в разных вкладках (`pat`, `pat2`) → одна запись `scheduled`; чужой `slot_id` (`999999`) → не 500.
- Проверить registrar без `patient_email` и с неизвестным email.
- Patient: прошедший слот, закрытый день, чужой `patient_email` → может записать только себя.

## Маршруты и расписание

- Без входа и под каждой ролью открыть `/`, `/doctors`, `/doctors/1/slots`, `/my`, `/doctor/appointments`, `/admin/users`, `/admin/schedule`: гость не видит чужие записи; admin не становится врачом подменой URL.
- Ошибки разбора диапазона, длины и trailing spaces; `slot_minutes` `0/-1/999999`; `end_time < start_time`; `weekday` `7/-1`; дата `2026-02-31`; диапазон >90 дней.

## Заголовки и прокси

```bash
curl -i http://localhost:8080/login
curl -i http://127.0.0.1:5432
curl -i http://localhost:8000/
```

Для последней команды ожидается `connection refused`.
