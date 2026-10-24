from core.live_check_service import _fallback_failure_result, _worker_failure_result


def test_final_browser_error_replaces_prior_403_without_invalidating_password():
    prior = {"ok": False, "error": "HTTP 403", "token_expired": True,
             "access_token": "old-secret", "status": "blocked"}
    result = _fallback_failure_result(prior, RuntimeError("Target page has been closed"))
    assert result["status"] == "failed"
    assert "Target page" in result["error"]
    assert result["previous_error"] == "HTTP 403"
    assert result["failure_stage"] == "browser_fallback"
    assert result["token_expired"] is True
    assert "access_token" not in result
    assert "password_valid" not in result
    assert prior["status"] == "blocked"


def test_final_explicit_challenge_remains_blocked():
    result = _fallback_failure_result({}, RuntimeError("HTTP 403"))
    assert result["status"] == "blocked"
    assert "token_expired" not in result


def test_failure_message_redacts_named_credentials():
    result = _worker_failure_result(RuntimeError("password=fixture-password access_token=fixture-token"))
    assert "fixture-password" not in result["error"]
    assert "fixture-token" not in result["error"]


def test_no_token_does_not_reuse_prior_403():
    result = _fallback_failure_result({"error": "HTTP 403"}, RuntimeError("未返回 accessToken"))
    assert result["status"] == "failed"
    assert "403" not in result["error"]
