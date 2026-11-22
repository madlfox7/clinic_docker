# E6: обнаружение подделки журнала аудита (план 17, §10.1, A10)

16.11.2026, 19:10–19:16 (Asia/Yerevan, UTC+4); база HEAD `8f8f312` (коммиты 7–11 части B). Скрипт: `experiments/e6_tamper.py --disposable-stand e6 --perf 100000`; seed `1794841837`.
Лог: `experiments/e6_20261116-1910.log`; JSON `experiments/e6_20261116-1910.json` содержит только seq/id/тип, без секретов и содержимого событий.

## Стенд

- Запуск: `docker compose --env-file .env.e6 -p e6 -f docker-compose.yml -f docker-compose.e6.yml`. Явные `-f` исключают локальный `docker-compose.override.yml`; команды собирает `compose()`.
- HTTP 8086, HTTPS 8456, Mailpit 8030 / SMTP 1030 на `127.0.0.1`; `ss -ltn` и `docker ps` подтвердили, что порты свободны. Fixer (8082/8452) и Planera (8083/8453) не затрагивались.
- До первой Docker-команды проверяются `--disposable-stand e6`, `CLINIC_AUDIT_ANCHOR_DIR` из `.env.e6` (не `./audit_anchors` и не внутри него) и порты; чужие порты запрещены.
- До первого `up` `scripts/init_secrets.sh` создал `./audit_anchors_e6/20261116-1910` с правами `700` и ACL `u:10002:rwx`. `getfacl` возвращает код ≠ 0 без ACL или при запуске не от root. Каталог оставлен приложением к отчёту, в `.gitignore`, не в Git.
- Свежий том, `up --build`, якорь каждые 60 с; после опыта — `down -v`.

## Контроль Б3 (до правок)

Остановлены `proxy api`; `anchor.py --retire` → `retire … normal`. Триггеры отключены, `TRUNCATE audit_events`, голова удалена, `up` создал genesis. Реестр `open → retire → open` **без `switch`**; healthcheck `healthy`, `verify_audit` код 0 (`OK … rows=0`). Контроль пройден.

## Данные и тесты

Цепочка: 520 событий — 40 успешных входов (и выходов), 15 неудачных через HTTPS, 425 строк через `INSERT`; действия смешанные, `reason`/`source`/`target_id` — `NULL` или значение. Цепочку считает триггер. Контроль: `OK chain=2a752c29-e169-46f4-a96a-808243e70042 rows=520 anchors=22 last_anchor_age=0 retired_forced=0 retired_offline=0`.

Только тесты e6 (`tests/test_audit_chain.py`): свежий том (genesis 0, 6 триггеров `A`) и 20 параллельных `--once` с работающим циклом (Б-B1) — `2 passed, 90 deselected in 1.31s`; отказ `migrate` без головы при наличии строк (A7, в конце) — `1 passed, 91 deselected in 1.06s`.

## 20 правок

Перед каждой правкой запускался `anchor.py --once` и копировались `audit_events`/`audit_chain_head` в схему `e6`. Суперпользователь выполнял `DISABLE TRIGGER USER`, правку, `ENABLE ALWAYS TRIGGER` для всех 6 триггеров, `COMMIT`; так режим триггеров не выдавал правку. После `verify_audit` таблицы восстанавливались из дампа тем же циклом; проверялись `tgenabled = 'A'` у 6 триггеров и контрольный `verify_audit` (`OK`).

Ожидалось: `row_hash` для updates, `gap` для удалений средних строк, `truncated` для хвоста и `TRUNCATE`, `anchor_mismatch` для пересчёта суффикса (seq 520), `prev_hash` для swap (seq 493); ожидаемый seq для остальных правок совпадал с seq изменения.

| № | Тип / правка (seq) | Фактический `verify_audit` |
|---:|---|---|
| 1 | update `created_at` (124) | `row_hash` seq=124 id=124 |
| 2 | update `action` (501) | `row_hash` seq=501 id=501 |
| 3 | update `actor_user_id` (135) | `row_hash` seq=135 id=135 |
| 4 | update `reason` NULL→value (502) | `row_hash` seq=502 id=502 |
| 5 | update `reason` value→NULL (444) | `row_hash` seq=444 id=444 |
| 6 | update `source` NULL→value (135) | `row_hash` seq=135 id=135 |
| 7 | update `target_id` value→NULL (55) | `row_hash` seq=55 id=55 |
| 8 | update `target_id` NULL→value (161) | `row_hash` seq=161 id=161 |
| 9 | delete middle row (353) | `gap` seq=353 |
| 10 | delete middle row (170) | `gap` seq=170 |
| 11 | delete middle row (250) | `gap` seq=250 |
| 12 | delete middle row (193) | `gap` seq=193 |
| 13 | delete tail 1 row (520) | `truncated` seq=520 |
| 14 | delete tail 17 rows (504) | `truncated` seq=504 |
| 15 | delete tail 1 row + head (520) | `truncated` seq=520 |
| 16 | delete tail 15 rows + head (506) | `truncated` seq=506 |
| 17 | recompute SHA suffix + head (228) | `anchor_mismatch` seq=520 id=520 |
| 18 | recompute SHA suffix + head (485) | `anchor_mismatch` seq=520 id=520 |
| 19 | `TRUNCATE` (seq=1, triggers off) | `truncated` seq=1 |
| 20 | swap seq 493↔509 | `prev_hash` seq=493 id=509 |

**Все 20 правок найдены с точным `seq` и восстановлены (`OK`; все триггеры в режиме `A`).**

Пересчёт суффикса (17–18) менял строку, пересчитывал `prev_hash`/`row_hash` до конца и голову. Цепочка сходилась, поэтому обнаруживал только якорь: первый несовпавший — `seq` 520, созданный перед правкой. Более ранних якорей с `seq ≥` позиции правки не было; после генерации якоря стояли только на 0 и 520. Удаление хвоста (13–16), с правкой головы и без неё, давало `truncated` с первым пропавшим `seq` (якорь на 520). При перестановке seq (20) на месте 493 оказалась строка id 509 с несовпадающим `prev_hash`.

## После правок (Б6, Б3)

- **Б6, режим триггера:** `DISABLE` + `ENABLE` без `ALWAYS` у `zz_audit_chain` → `BROKEN type=trigger_mode name=zz_audit_chain mode=O` (код 1). Повторный `migrate` восстановил `A` → `OK chain=2a752c29-e169-46f4-a96a-808243e70042 …` (код 0).
- **Подмена всей цепочки:** отключены триггеры, выполнены `TRUNCATE`, удаление головы и `up` с новым genesis. Реестр: `switch new`; healthcheck `unhealthy`; `verify_audit` код 1: `BROKEN type=chain_replaced kind=new old=2a752c29-e169-46f4-a96a-808243e70042 new=0fe09a23-eb61-4da0-8645-f06d1169d4dc`.
- **Дамп старой цепочки поверх:** реестр `switch reused`, `verify_audit` код 1. Проверка печатает первую неразрешённую подмену (`kind=new`), хотя `switch … reused` есть в реестре.
- Полный пересчёт хешей под новым `chain_id` и `retired_reused` на стенде не проверялись; `retired_reused` покрыт юнит-тестом (§8, тест 7, `tests/test_audit_chain.py`).
- Финальный `verify_audit --strict`: код 1 (ожидаемо из-за `switch`): `BROKEN type=chain_replaced kind=new old=2a752c29-e169-46f4-a96a-808243e70042 new=0fe09a23-eb61-4da0-8645-f06d1169d4dc`.

## Ограничение: окно до 60 с

Якорь пишется каждые `CLINIC_AUDIT_ANCHOR_INTERVAL` (60 с). Правка суперпользователя после последнего якоря им не покрыта: если до следующего цикла он отключит триггеры и пересчитает хвост от последнего якоря, новый якорь подпишет подделанное состояние. В опыте перед каждой правкой ставился принудительный якорь, поэтому все правки были «до якоря». Окно можно сократить до 10 с (`CLINIC_AUDIT_ANCHOR_INTERVAL=10`). От root хоста (БД, ключ и файлы якорей) защищают только якоря вне хоста (README).

## Производительность (§10.2)

См. `experiments/chain_perf.md`.
