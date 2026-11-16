"""A fake journal for the unit tests of audit/anchor.py and verify_audit.py:
rows, head and trigger modes in memory, hashed with audit/canon.py."""
import datetime as dt
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "audit"))
import canon  # noqa: E402
import chainlib  # noqa: E402

KEY = bytes(range(32))


class FakeSource:
    def __init__(self, chain_id=None, rows=0, genesis_rows=0):
        self.chain_id = chain_id or str(uuid.uuid4())
        self.rows = []
        self.genesis_rows = genesis_rows
        self.genesis_at = dt.datetime(2026, 11, 16, 10, 0, tzinfo=dt.timezone.utc)
        self.modes = {key: "A" for key in chainlib.TRIGGERS}
        self.head_override = None
        self.add(rows)

    def add(self, count=1):
        for _ in range(count):
            seq = len(self.rows) + 1
            prev = self.rows[-1]["row_hash"] if self.rows else canon.genesis_prev_hash(self.chain_id)
            row = {"seq": seq, "id": seq + 100, "actor_user_id": 1, "actor_role": "admin",
                   "action": "test.chain", "target_type": "test", "target_id": seq, "reason": None,
                   "source": None, "old_value": None, "new_value": None, "hash_version": 1,
                   "created_at": self.genesis_at + dt.timedelta(seconds=seq), "prev_hash": prev}
            row["row_hash"] = canon.row_hash(prev, row)
            self.rows.append(row)
        return self

    def head(self):
        if self.head_override is not None:
            return self.head_override
        last = self.rows[-1]["row_hash"] if self.rows else canon.genesis_prev_hash(self.chain_id)
        return {"chain_id": self.chain_id, "last_seq": len(self.rows), "last_hash": last,
                "genesis_at": self.genesis_at, "genesis_rows": self.genesis_rows}

    def row(self, seq):
        return next((dict(r) for r in self.rows if r["seq"] == seq), None)

    def rows_from(self, seq):
        return iter([dict(r) for r in self.rows if r["seq"] >= seq])

    def trigger_modes(self):
        return dict(self.modes)
