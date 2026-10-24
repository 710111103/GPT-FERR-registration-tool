from unittest.mock import patch

from core.chatgpt_plan import check_account_plan_regions, classify_plan_failure
from core.plan_check_service import _queue_auth_refresh_if_needed


def test_failure_categories_do_not_mislabel_403_as_token_or_proxy():
    assert classify_plan_failure({"http_status": 401})[0] == "token"
    assert classify_plan_failure({"http_status": 407})[0] == "proxy"
    assert classify_plan_failure({"error": "curl: (7) CONNECT tunnel failed, response 403"})[0] == "proxy"
    assert classify_plan_failure({"http_status": 403})[0] == "access"
    assert classify_plan_failure({"error": "ConnectTimeout: timed out"})[0] == "timeout"
    assert classify_plan_failure({"error": "HTTP 429"})[0] == "rate_limit"
    assert classify_plan_failure({"error": "some unexplained failure"})[0] == "unknown"


def test_region_failure_summary_preserves_per_region_causes():
    errors = {"JP": {"ok": False, "http_status": 403, "error": "HTTP 403"},
              "US": {"ok": False, "error": "ProxyError: tunnel connection failed"}}
    with patch("core.chatgpt_plan.rotate_proxy_session", side_effect=lambda proxy: (proxy, None)), \
         patch("core.chatgpt_plan.check_account_plan", side_effect=lambda token, proxy, billing_country: errors[billing_country]):
        result = check_account_plan_regions("fixture", [("JP", "proxy-jp"), ("US", "proxy-us")])
    assert result["ok"] is False
    assert result["token_expired"] is False
    assert [item["category"] for item in result["region_failure_summary"]] == ["access", "proxy"]
    assert "HTTP 403" in result["error"] and "代理" in result["error"]


def test_plan_401_queues_live_check_but_ordinary_failures_do_not():
    with patch("core.live_check_service.enqueue_account_live_check", return_value={"accepted": True}) as enqueue:
        queued = _queue_auth_refresh_if_needed(
            account_id=7, email="a@example.test", trigger="manual",
            result={"ok": False, "http_status": 401, "needs_live_check": True},
        )
        assert queued == {"accepted": True}
        enqueue.assert_called_once_with(
            account_id=7, email="a@example.test", trigger="plan_401_auto_refresh", proxy=None,
        )

        assert _queue_auth_refresh_if_needed(
            account_id=7, email="a@example.test", trigger="manual",
            result={"ok": False, "http_status": 403, "error": "HTTP 403"},
        ) is None
        assert _queue_auth_refresh_if_needed(
            account_id=7, email="a@example.test", trigger="live_check_refresh",
            result={"ok": False, "http_status": 401, "token_expired": True},
        ) is None
        assert enqueue.call_count == 1
