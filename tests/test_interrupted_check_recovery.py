from copy import deepcopy
from unittest.mock import patch

import pytest
from core import db


@pytest.mark.parametrize("kind", ["plan", "live"])
@pytest.mark.parametrize("status", ["queued", "running"])
def test_restart_finalizes_task_without_rechecking_or_changing_credentials(kind, status):
    prefix = f"{kind}_check"
    checked = "plan_checked_at" if kind == "plan" else "live_checked_at"
    row = {"id": 1, f"{prefix}_status": status, checked: "2026-10-20T10:00:00",
           "access_token": "fixture-token", "password": "fixture-password",
           "token_expired": False, "plus_trial_eligible": True}
    before = deepcopy(row)
    now = "2026-10-24T12:00:00"
    recover = getattr(db, f"recover_interrupted_{kind}_checks")
    with patch.object(db, "_load_accounts", return_value=[row]), \
         patch.object(db, "_save_accounts") as save, patch.object(db, "_now", return_value=now):
        assert recover() == 1
        assert recover() == 0
    save.assert_called_once()
    assert row[f"{prefix}_status"] == "failed"
    assert row[f"{prefix}_completed_at"] == now
    for key in (checked, "access_token", "password", "token_expired", "plus_trial_eligible"):
        assert row[key] == before[key]


@pytest.mark.parametrize("kind", ["plan", "live"])
@pytest.mark.parametrize("status", ["success", "live", "failed", "blocked", "deactivated", ""])
def test_restart_does_not_touch_terminal_or_idle_accounts(kind, status):
    row = {"id": 2, f"{kind}_check_status": status}
    before = deepcopy(row)
    with patch.object(db, "_load_accounts", return_value=[row]), patch.object(db, "_save_accounts") as save:
        assert getattr(db, f"recover_interrupted_{kind}_checks")() == 0
    save.assert_not_called()
    assert row == before


def test_recovery_does_not_invent_a_first_check_timestamp():
    row = {"id": 3, "live_check_status": "queued"}
    with patch.object(db, "_load_accounts", return_value=[row]), patch.object(db, "_save_accounts"):
        assert db.recover_interrupted_live_checks() == 1
    assert "live_checked_at" not in row
    assert "live_check_completed_at" in row
