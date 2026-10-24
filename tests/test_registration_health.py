from datetime import datetime, timezone

from core.registration_health import classify_registration_health, summarize_registration_health

def test_checkpoint_waiting_and_stale_classification():
    now = datetime(2026, 10, 16, 2, 0, tzinfo=timezone.utc)
    waiting = {"id": 1, "email": "a@example.test", "status": "registering", "password_setup_ok": True, "updated_at": "2026-10-16T01:50:00+00:00"}
    result = classify_registration_health(waiting, now=now, stale_after_minutes=15)
    assert result["pending"] is True
    assert result["password_checkpoint_saved"] is True
    assert result["stale"] is False
    assert result["recommended_action"] == "wait_or_resume"

    stale = {**waiting, "updated_at": "2026-10-16T01:30:00+00:00"}
    result = classify_registration_health(stale, now=now, stale_after_minutes=15)
    assert result["stale"] is True
    assert result["recommended_action"] == "inspect_stale_task"

def test_interrupted_and_summary():
    now = datetime(2026, 10, 16, 2, 0, tzinfo=timezone.utc)
    accounts = [
        {"id": 1, "email": "a@example.test", "status": "interrupted", "updated_at": "2026-10-16T01:59:00+00:00"},
        {"id": 2, "email": "b@example.test", "status": "", "updated_at": "2026-10-16T01:59:00+00:00"},
    ]
    snapshot = summarize_registration_health(accounts, now=now)
    assert snapshot["counts"] == {"pending": 1, "registering": 0, "interrupted": 1, "stale": 0, "password_checkpoint_saved": 0}
    assert snapshot["items"][0]["recommended_action"] == "review_or_resume"
