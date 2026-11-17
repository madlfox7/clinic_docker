"""Test order on the disposable stand -p e6 only.

Some e6-only tests change the stand for good: make reset (a new empty
journal), a replaced chain, a changed row, or no chain head at all
(test_missing_head_stops_migrate leaves migrate refusing to start, which is
what it checks). Tests that expect the stand as make start left it (for
example an anchor on seq >= 1 of the seeded journal) would fail after them in
a cascade. On -p e6 these tests therefore run at the very end, in this order;
elsewhere they are skipped and the order does not change."""
import os

LAST_ON_E6 = (
    "test_audit_chain.py::test_live_reset_after_stop_closes_the_chain_with_run",
    "test_audit_chain.py::test_live_reset_after_chain_replaced_needs_retire_force",
    "test_audit_chain.py::test_live_start_without_anchor_directory_is_registry_missing_until_it_is_back",
    "test_audit_chain.py::test_live_reset_without_anchor_directory_needs_force_and_leaves_a_record",
    "test_audit_status_ui.py::test_e6_changed_row_before_the_last_anchor_turns_the_banner_red",
    "test_audit_status_ui.py::test_e6_banner_stays_red_after_chain_replaced_and_a_forced_reset",
    "test_audit_chain.py::test_missing_head_stops_migrate_instead_of_a_new_chain",
)


def _rank(item) -> int:
    for rank, suffix in enumerate(LAST_ON_E6):
        if item.nodeid.endswith(suffix):
            return rank
    return -1


def pytest_collection_modifyitems(config, items):
    if os.environ.get("COMPOSE_PROJECT_NAME", "") != "e6":
        return
    last = sorted((item for item in items if _rank(item) >= 0), key=_rank)
    if last:
        items[:] = [item for item in items if _rank(item) < 0] + last
