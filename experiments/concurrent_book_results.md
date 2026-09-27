# Concurrent booking experiment

Environment: local Docker Compose app at `http://localhost:8080`, PostgreSQL volume retained.

Free slot selected from the database before each run: slot `2`, Anna Ohanyan, `2026-10-01 10:00-10:30`.

## 10 simultaneous requests

Command:

```bash
python3 experiments/concurrent_book.py 2 10
```

Result:

```text
accepted 1
rejected 9
```

SQL after the run showed exactly one `scheduled` appointment for `slot_id = 2`.

## 50 simultaneous requests

The first test booking was changed to `cancelled` before reusing slot 2.

Command:

```bash
python3 experiments/concurrent_book.py 2 50
```

Result:

```text
accepted 1
rejected 49
```

SQL after the run again showed exactly one `scheduled` appointment for `slot_id = 2`.

## Cleanup

The winning test booking was cancelled. Final SQL showed zero `scheduled` rows for slot 2; three historical `cancelled` rows remain from the two experiments and earlier local tests.

The test only exercises concurrent HTTP booking. PostgreSQL's scheduled-only unique index is the final protection against duplicate bookings for one slot.
