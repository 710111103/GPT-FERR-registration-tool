# -*- coding: utf-8 -*-
from core import live_check_service
from core.task_observability import classify_error


def test_generic_verification_page_word_is_not_fabricated_as_http_403():
    result = live_check_service._worker_failure_result(
        RuntimeError("邮箱提交后未进入密码页或邮箱验证码页")
    )
    assert result["status"] == "failed"
    assert "HTTP 403" not in result["error"]


def test_email_submit_stalled_has_precise_result_and_observation_category():
    exc = RuntimeError(
        "email_submit_stalled: 邮箱提交后未进入密码页或邮箱验证码页，最后状态={'state': 'email_page'}"
    )
    result = live_check_service._worker_failure_result(exc)
    assert result["status"] == "failed"
    assert "邮箱提交停滞" in result["error"]
    assert classify_error(result["error"]) == "email_submit_stalled"


def test_explicit_http_403_remains_blocked():
    result = live_check_service._worker_failure_result(
        RuntimeError("authorize returned HTTP 403 cf-mitigated challenge")
    )
    assert result["status"] == "blocked"
    assert "HTTP 403" in result["error"]


def test_chinese_cloudflare_challenge_is_blocked():
    result = live_check_service._worker_failure_result(
        RuntimeError("Cloudflare 验证页等待超时；密码尚未验证")
    )
    assert result["status"] == "blocked"
    assert "HTTP 403" in result["error"]
