# E6: обнаружение подделки журнала аудита (план 17 §10.1, A10)

Дата: 16.11.2026, 19:10–19:16 (Asia/Yerevan, UTC+4). База: HEAD `8f8f312` (коммиты 7–11 части B) плюс сам скрипт.
Скрипт: `experiments/e6_tamper.py --disposable-stand e6 --perf 100000`, seed `1794841837`.
Сырой лог: `experiments/e6_20261116-1910.log`, данные: `experiments/e6_20261116-1910.json` (только seq/id/тип, без секретов и содержимого событий).

## Стенд

- Одноразовый `docker compose --env-file .env.e6 -p e6 -f docker-compose.yml -f docker-compose.e6.yml` (явные `-f`, локальный `docker-compose.override.yml` не подхватывается). Каждую команду собирает одна функция `compose()`.
- Порты: HTTP 8086, HTTPS 8456, Mailpit 8030 / SMTP 1030 (все `127.0.0.1`), перед стартом проверены `ss -ltn` и `docker ps` — свободны. Стенды Fixer (8082/8452) и Planera (8083/8453) не затрагивались.
- Предохранитель: без `--disposable-stand e6` скрипт не запускается; `CLINIC_AUDIT_ANCHOR_DIR` в `.env.e6` обязателен и не равен `./audit_anchors` и не внутри него; порты из списка чужих стендов запрещены — всё до первой docker-команды.
- Каталог якорей: `./audit_anchors_e6/20261116-1910` (литеральная строка в `.env.e6`), создан тем же `scripts/init_secrets.sh` до первого `up`: `700` + ACL `u:10002:rwx` (проверяется `getfacl`, без ACL и не от root — выход ≠ 0). Каталог оставлен как приложение к отчёту (в `.gitignore`, не в git).
- Свежий том, `up --build`, интервал якорей 60 с. После эксперимента — `down -v`.

## Контроль Б3 (первым, до правок)

Остановлены `proxy api`, `anchor.py --retire` → `retire … normal`; триггеры отключены, `TRUNCATE audit_events`, голова удалена; `up` → новый genesis.
Результат: реестр `open → retire → open` **без `switch`**, healthcheck `healthy`, `verify_audit` код 0 (`OK … rows=0`). Контроль пройден.

## Данные

520 событий на новой цепочке: 40 успешных входов (+ выходы) и 15 неудачных входов через HTTPS, 425 строк через `INSERT` (смесь действий, `reason`/`source`/`target_id` то NULL, то значение; цепочку считает триггер). Контрольный прогон без правок: `OK chain=2a752c29-e169-46f4-a96a-808243e70042 rows=520 anchors=22 last_anchor_age=0 retired_forced=0 retired_offline=0`.

Тесты только для e6 на этом стенде (`tests/test_audit_chain.py`): свежий том (genesis 0, 6 триггеров в режиме `A`) и 20 параллельных `--once` рядом с работающим циклом (Б-B1) — `2 passed, 90 deselected in 1.31s`; отказ `migrate` без головы при наличии строк (A7, в самом конце) — `1 passed, 91 deselected in 1.06s`.

## 20 правок

Перед каждой: принудительный якорь `anchor.py --once`, дамп `audit_events` и `audit_chain_head` (копии таблиц в схеме `e6`). Правка — суперпользователем: `DISABLE TRIGGER USER`, изменение, `ENABLE ALWAYS TRIGGER` для каждого из 6 триггеров, `COMMIT` (так режим триггеров не выдаёт правку, ловит только цепочка). Затем `verify_audit`, восстановление из дампа (тоже `DISABLE` → `ENABLE ALWAYS`), проверка `tgenabled = 'A'` у 6 триггеров и контрольный `verify_audit` = OK.

| № | Тип | Что | seq правки | Ожидалось | verify_audit | Найдено | Восстановлено |
|---|---|---|---|---|---|---|---|
| 1 | update | created_at | 124 | `row_hash` seq=124 | `row_hash` seq=124 id=124 | да | OK, режим A |
| 2 | update | action | 501 | `row_hash` seq=501 | `row_hash` seq=501 id=501 | да | OK, режим A |
| 3 | update | actor_user_id | 135 | `row_hash` seq=135 | `row_hash` seq=135 id=135 | да | OK, режим A |
| 4 | update | reason NULL->value | 502 | `row_hash` seq=502 | `row_hash` seq=502 id=502 | да | OK, режим A |
| 5 | update | reason value->NULL | 444 | `row_hash` seq=444 | `row_hash` seq=444 id=444 | да | OK, режим A |
| 6 | update | source NULL->value | 135 | `row_hash` seq=135 | `row_hash` seq=135 id=135 | да | OK, режим A |
| 7 | update | target_id value->NULL | 55 | `row_hash` seq=55 | `row_hash` seq=55 id=55 | да | OK, режим A |
| 8 | update | target_id NULL->value | 161 | `row_hash` seq=161 | `row_hash` seq=161 id=161 | да | OK, режим A |
| 9 | delete | middle row | 353 | `gap` seq=353 | `gap` seq=353 | да | OK, режим A |
| 10 | delete | middle row | 170 | `gap` seq=170 | `gap` seq=170 | да | OK, режим A |
| 11 | delete | middle row | 250 | `gap` seq=250 | `gap` seq=250 | да | OK, режим A |
| 12 | delete | middle row | 193 | `gap` seq=193 | `gap` seq=193 | да | OK, режим A |
| 13 | delete | tail 1 rows | 520 | `truncated` seq=520 | `truncated` seq=520 | да | OK, режим A |
| 14 | delete | tail 17 rows | 504 | `truncated` seq=504 | `truncated` seq=504 | да | OK, режим A |
| 15 | delete | tail 1 rows + head | 520 | `truncated` seq=520 | `truncated` seq=520 | да | OK, режим A |
| 16 | delete | tail 15 rows + head | 506 | `truncated` seq=506 | `truncated` seq=506 | да | OK, режим A |
| 17 | recompute | SHA suffix + head | 228 | `anchor_mismatch` seq=520 | `anchor_mismatch` seq=520 id=520 | да | OK, режим A |
| 18 | recompute | SHA suffix + head | 485 | `anchor_mismatch` seq=520 | `anchor_mismatch` seq=520 id=520 | да | OK, режим A |
| 19 | truncate | TRUNCATE (triggers off) | 1 | `truncated` seq=1 | `truncated` seq=1 | да | OK, режим A |
| 20 | swap | seq 493<->509 | 493 | `prev_hash` seq=493 | `prev_hash` seq=493 id=509 | да | OK, режим A |

**Итог: 20/20 найдено с точным `seq`, 20/20 восстановлено (OK, все триггеры `A`).**

Пояснения:
- Пересчёт суффикса (17, 18): суперпользователь меняет строку и пересчитывает `prev_hash`/`row_hash` до конца и голову — цепочка внутренне сходится, ловит её только якорь. Указан первый не совпавший якорь (`seq` 520, якорь перед правкой); более ранних якорей с `seq ≥` места правки не было (после генерации якоря были только на 0 и 520).
- Удаление хвоста (13–16), с правкой головы и без: `truncated` с первым пропавшим `seq` (якорь на 520).
- Обмен `seq` (20): на месте 493 стоит строка id 509, её `prev_hash` не совпадает.

## После правок (Б6, Б3)

- **Б6, режим триггера:** `DISABLE` + `ENABLE` без `ALWAYS` у `zz_audit_chain` → `BROKEN type=trigger_mode name=zz_audit_chain mode=O` (код 1); повторный `migrate` вернул режим `A` → `OK chain=2a752c29-e169-46f4-a96a-808243e70042 …` (код 0).
- **Подмена цепочки целиком:** триггеры отключены, `TRUNCATE`, голова удалена, `up` (новый genesis) → в реестре `switch new`, healthcheck `unhealthy`, `verify_audit` код 1: `BROKEN type=chain_replaced kind=new old=2a752c29-e169-46f4-a96a-808243e70042 new=0fe09a23-eb61-4da0-8645-f06d1169d4dc`.
- **Дамп старой цепочки поверх:** в реестре `switch reused`, `verify_audit` код 1. `verify_audit` печатает первую неразрешённую подмену реестра (`kind=new`), строка `switch … reused` в реестре есть.
- Вариант «полный пересчёт хешей под новым `chain_id`» и `retired_reused` на стенде не делались: `retired_reused` покрыт юнит-тестом (§8 тест 7, `tests/test_audit_chain.py`).
- Финальный `verify_audit --strict`: код 1 (ожидаемо ≠ 0 из-за `switch`): `BROKEN type=chain_replaced kind=new old=2a752c29-e169-46f4-a96a-808243e70042 new=0fe09a23-eb61-4da0-8645-f06d1169d4dc`.

## Ограничение (честно): окно до 60 с

Якорь пишется раз в `CLINIC_AUDIT_ANCHOR_INTERVAL` (60 с). Правка, сделанная суперпользователем БД **после** последнего якоря, этим якорем не покрыта: если он за время до следующего цикла отключит триггеры и пересчитает хвост от последнего якоря, следующий якорь подпишет уже подделанное состояние. В эксперименте перед каждой правкой ставился принудительный якорь, поэтому все правки были «до якоря». Окно можно сжать до 10 с (`CLINIC_AUDIT_ANCHOR_INTERVAL=10`). Против root хоста (БД + ключ + файлы якорей) помогают только якоря, вынесенные за пределы хоста (README).

## Производительность (часть §10.2)

См. `experiments/chain_perf.md`.
