from unittest.mock import Mock, patch

from core import plan_check_service as service
from core.proxy_utils import mask_proxy_url


def test_submission_failure_finalizes_claim_and_releases_slot():
    items = [{"id": 17, "email": "fixture@example.test", "access_token": "fixture"}]
    slots = Mock()
    slots.acquire.return_value = True
    with patch.object(service.db, "claim_account_plan_checks_batch", return_value={17}), \
         patch.object(service.db, "update_account_plan_check") as update, \
         patch.object(service, "_QUEUE_SLOTS", slots), \
         patch.object(service, "_submit_plan_check", side_effect=RuntimeError("executor stopped")):
        started, busy, failed = service.enqueue_account_plan_checks_batch(items, "manual")
    assert started == [] and busy == []
    assert failed[0]["id"] == 17
    slots.release.assert_called_once_with()
    update.assert_called_once()
    result = update.call_args.kwargs["result"]
    assert update.call_args.kwargs["acc_id"] == 17
    assert result["ok"] is False and result["checked_at"]
    assert "executor stopped" in result["error"]
    assert "token_expired" not in result


def test_proxy_log_mask_covers_http_and_socks():
    for scheme in ("http", "socks5"):
        masked = mask_proxy_url(f"{scheme}://fixture-user:fixture-pass@localhost:8080")
        assert "fixture-user" not in masked and "fixture-pass" not in masked
        assert "localhost:8080" in masked
