from datetime import datetime, timedelta
from unittest.mock import patch

from core import live_check_service, plan_check_service


def test_periodic_status_check_only_queues_stale_accounts():
    now = datetime(2026, 10, 4, 12, 0, 0)
    accounts = [
        {"id": 1, "email": "stale@example.com", "access_token": "a", "plan_checked_at": (now - timedelta(hours=7)).isoformat(), "plan_check_status": "success"},
        {"id": 2, "email": "fresh@example.com", "access_token": "b", "plan_checked_at": (now - timedelta(hours=1)).isoformat(), "plan_check_status": "success"},
        {"id": 3, "email": "busy@example.com", "access_token": "c", "plan_checked_at": "", "plan_check_status": "running"},
    ]
    with patch.object(plan_check_service.proxy_cfg, "ACCOUNT_STATUS_CHECK_INTERVAL_MINUTES", 360), patch.object(
        plan_check_service.proxy_cfg, "ACCOUNT_STATUS_CHECK_BATCH_SIZE", 10
    ), patch.object(plan_check_service.db, "list_accounts", return_value=accounts), patch.object(
        plan_check_service, "enqueue_account_plan_check", return_value={"accepted": True}
    ) as enqueue:
        result = plan_check_service.enqueue_due_account_status_checks(now=now)

    assert result["queued"] == 1
    assert enqueue.call_count == 1
    assert enqueue.call_args.kwargs["account_id"] == 1
    assert enqueue.call_args.kwargs["trigger"] == "account_status_periodic"


def test_periodic_status_check_recovers_orphaned_queued_task_immediately():
    now = datetime(2026, 10, 23, 22, 44, 0)
    account = {
        "id": 206,
        "email": "orphan@example.com",
        "access_token": "token",
        "plan_checked_at": (now - timedelta(minutes=20)).isoformat(),
        "plan_check_status": "queued",
        "plan_check_queued_at": (now - timedelta(minutes=20)).isoformat(),
        "live_check_status": "live",
    }
    with patch.object(plan_check_service.proxy_cfg, "ACCOUNT_STATUS_CHECK_INTERVAL_MINUTES", 1440), patch.object(
        plan_check_service.proxy_cfg, "ACCOUNT_STATUS_CHECK_BATCH_SIZE", 10
    ), patch.object(plan_check_service.db, "list_accounts", return_value=[account]), patch.object(
        plan_check_service.db, "update_account_plan_check", return_value=True
    ) as recover, patch.object(
        plan_check_service, "enqueue_account_plan_check", return_value={"accepted": True}
    ) as enqueue:
        result = plan_check_service.enqueue_due_account_status_checks(now=now)

    assert result["queued"] == 1
    recover.assert_called_once()
    assert "超过 90 秒" in recover.call_args.kwargs["result"]["error"]
    enqueue.assert_called_once()
    assert enqueue.call_args.kwargs["account_id"] == 206


def test_periodic_status_check_keeps_recent_queued_task():
    now = datetime(2026, 10, 23, 22, 44, 0)
    account = {
        "id": 207,
        "email": "recent@example.com",
        "access_token": "token",
        "plan_check_status": "queued",
        "plan_check_queued_at": (now - timedelta(seconds=30)).isoformat(),
    }
    with patch.object(plan_check_service.proxy_cfg, "ACCOUNT_STATUS_CHECK_INTERVAL_MINUTES", 360), patch.object(
        plan_check_service.db, "list_accounts", return_value=[account]
    ), patch.object(plan_check_service.db, "update_account_plan_check") as recover, patch.object(
        plan_check_service, "enqueue_account_plan_check"
    ) as enqueue:
        result = plan_check_service.enqueue_due_account_status_checks(now=now)

    assert result["queued"] == 0
    recover.assert_not_called()
    enqueue.assert_not_called()


def test_plan_worker_observability_failure_never_leaves_account_queued():
    with patch.object(plan_check_service, "ProbeSession", side_effect=OSError("probe directory unavailable")), patch.object(
        plan_check_service.db, "update_account_plan_check", return_value=True
    ) as update, patch.object(plan_check_service._QUEUE_SLOTS, "release") as release:
        result = plan_check_service._run_plan_check(
            account_id=208,
            email="probe@example.com",
            access_token="token",
            trigger="manual",
            proxy=None,
            timezone_offset_min="-",
        )

    assert result["ok"] is False
    assert "probe directory unavailable" in result["error"]
    update.assert_called_once()
    assert update.call_args.kwargs["acc_id"] == 208
    release.assert_called_once()


def test_periodic_status_check_can_be_disabled():
    with patch.object(plan_check_service.proxy_cfg, "ACCOUNT_STATUS_CHECK_INTERVAL_MINUTES", 0), patch.object(
        plan_check_service.db, "list_accounts"
    ) as list_accounts:
        result = plan_check_service.enqueue_due_account_status_checks()

    assert result == {"enabled": False, "queued": 0}
    list_accounts.assert_not_called()


def test_periodic_plan_refresh_skips_account_while_live_check_is_active():
    account = {
        "id": 4,
        "email": "live-running@example.com",
        "access_token": "d",
        "plan_checked_at": "",
        "plan_check_status": "success",
        "live_check_status": "running",
    }
    with patch.object(plan_check_service.proxy_cfg, "ACCOUNT_STATUS_CHECK_INTERVAL_MINUTES", 360), patch.object(
        plan_check_service.db, "list_accounts", return_value=[account]
    ), patch.object(plan_check_service, "enqueue_account_plan_check") as enqueue:
        result = plan_check_service.enqueue_due_account_status_checks()

    assert result["queued"] == 0
    enqueue.assert_not_called()


def test_periodic_live_check_only_queues_stale_accounts():
    now = datetime(2026, 10, 4, 12, 0, 0)
    accounts = [
        {"id": 10, "email": "stale-live@example.com", "live_checked_at": (now - timedelta(hours=7)).isoformat(), "live_check_status": "live"},
        {"id": 11, "email": "fresh-live@example.com", "live_checked_at": (now - timedelta(hours=1)).isoformat(), "live_check_status": "live"},
        {"id": 12, "email": "busy-live@example.com", "live_checked_at": "", "live_check_status": "queued"},
    ]
    with patch.object(live_check_service.proxy_cfg, "ACCOUNT_LIVE_CHECK_INTERVAL_MINUTES", 360), patch.object(
        live_check_service.proxy_cfg, "ACCOUNT_LIVE_CHECK_BATCH_SIZE", 3
    ), patch.object(live_check_service.db, "mark_expired_access_tokens", return_value=0), patch.object(live_check_service.db, "list_accounts", return_value=accounts), patch.object(
        live_check_service, "enqueue_account_live_check", return_value={"accepted": True}
    ) as enqueue:
        result = live_check_service.enqueue_due_account_live_checks(now=now)

    assert result["queued"] == 1
    assert enqueue.call_count == 1
    assert enqueue.call_args.kwargs["account_id"] == 10
    assert enqueue.call_args.kwargs["trigger"] == "account_live_periodic"
    assert enqueue.call_args.kwargs["proxy"] is None


def test_periodic_live_check_can_be_disabled():
    with patch.object(live_check_service.proxy_cfg, "ACCOUNT_LIVE_CHECK_INTERVAL_MINUTES", 0), patch.object(
        live_check_service.proxy_cfg, "AUTO_REFRESH_EXPIRED_AT", False), patch.object(live_check_service.db, "mark_expired_access_tokens", return_value=0), patch.object(
        live_check_service.db, "list_accounts"
    ) as list_accounts:
        result = live_check_service.enqueue_due_account_live_checks()

    assert result["enabled"] is False and result["queued"] == 0
    list_accounts.assert_not_called()


def test_expired_at_auto_queues_first_with_cooldown_even_if_periodic_disabled():
    now = datetime(2026, 10, 4, 12, 0, 0)
    accounts = [
        {"id": 1, "email": "expired@example.com", "token_expired": True, "token_expires_at": "2026-10-04T11:00:00Z", "live_checked_at": ""},
        {"id": 2, "email": "retry@example.com", "token_expired": True, "token_expires_at": "2026-10-04T11:00:00Z", "live_checked_at": (now-timedelta(minutes=30)).isoformat()},
        {"id": 3, "email": "unknown@example.com", "token_expired": True, "token_expires_at": None, "live_checked_at": ""},
    ]
    with patch.object(live_check_service.proxy_cfg, "ACCOUNT_LIVE_CHECK_INTERVAL_MINUTES", 0), patch.object(
        live_check_service.proxy_cfg, "AUTO_REFRESH_EXPIRED_AT", True
    ), patch.object(live_check_service.db, "mark_expired_access_tokens", return_value=2) as mark, patch.object(
        live_check_service.db, "list_accounts", return_value=accounts
    ), patch.object(live_check_service, "enqueue_account_live_check", return_value={"accepted": True}) as enqueue:
        result = live_check_service.enqueue_due_account_live_checks(now=now)
    assert result["queued"] == 1 and result["marked_expired"] == 2
    mark.assert_called_once()
    assert enqueue.call_args.kwargs["account_id"] == 1
    assert enqueue.call_args.kwargs["trigger"] == "expired_at_auto_refresh"


def test_expiry_scheduler_respects_in_flight_limit_across_ticks():
    now = datetime(2026, 10, 4, 12, 0, 0)
    accounts = [{"id": n, "email": f"{n}@example.com", "token_expired": True,
                 "token_expires_at": "2026-10-04T11:00:00Z", "live_checked_at": "",
                 "live_check_status": "running" if n <= 3 else ""} for n in range(1, 7)]
    with patch.object(live_check_service.proxy_cfg, "ACCOUNT_LIVE_CHECK_BATCH_SIZE", 3), patch.object(
        live_check_service.db, "mark_expired_access_tokens", return_value=0
    ), patch.object(live_check_service.db, "list_accounts", return_value=accounts), patch.object(
        live_check_service, "enqueue_account_live_check"
    ) as enqueue:
        result = live_check_service.enqueue_due_account_live_checks(now=now)
    assert result["queued"] == 0
    enqueue.assert_not_called()
