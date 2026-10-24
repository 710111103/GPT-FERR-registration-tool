# -*- coding: utf-8 -*-
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from core import antbrowser_liveness


def test_retry_proxy_rotates_only_after_first_attempt():
    with patch("core.chatgpt_plan.rotate_proxy_session", return_value=("http://rotated-proxy", "new-sid")) as rotate:
        assert antbrowser_liveness._rotate_retry_proxy("http://original-proxy", 1) == "http://original-proxy"
        assert antbrowser_liveness._rotate_retry_proxy("http://original-proxy", 2) == "http://rotated-proxy"
    rotate.assert_called_once_with("http://original-proxy")


def test_browser_login_timeout_closes_and_cleans_both_attempts():
    drivers = [MagicMock(), MagicMock()]
    opened = [
        SimpleNamespace(profile_id="timeout-1", raw={"proxy": "http://proxy-1"}),
        SimpleNamespace(profile_id="timeout-2", raw={"proxy": "http://proxy-2"}),
    ]

    def blocked_fill(*_args, **_kwargs):
        time.sleep(0.08)

    with patch.object(antbrowser_liveness, "_login_attempt_timeout", return_value=0.02), \
         patch.object(antbrowser_liveness, "_rotate_retry_proxy", side_effect=lambda proxy, attempt: f"{proxy}-{attempt}"), \
         patch.object(antbrowser_liveness, "build_ant_driver", side_effect=list(zip(drivers, opened))) as build, \
         patch.object(antbrowser_liveness, "_fill_email_and_otp", side_effect=blocked_fill), \
         patch.object(antbrowser_liveness, "cleanup_ant_profile") as cleanup:
        with pytest.raises(RuntimeError, match="ant_login_timeout"):
            antbrowser_liveness.refresh_recent_login_browser(
                "timeout@example.com", proxy="http://requested-proxy"
            )

    assert build.call_count == 2
    assert build.call_args_list[0].kwargs["proxy"] == "http://requested-proxy-1"
    assert build.call_args_list[1].kwargs["proxy"] == "http://requested-proxy-2"
    for driver in drivers:
        assert driver.quit.call_count >= 1
    assert [call.args[0] for call in cleanup.call_args_list] == opened


def test_liveness_applies_bounded_browser_waits_without_changing_global_defaults():
    driver = MagicMock()
    driver.page.context.cookies.return_value = []
    opened = SimpleNamespace(profile_id="bounded", raw={"proxy": "http://effective-proxy"})
    captured = {}

    def fill(received_driver, *_args, **_kwargs):
        captured["auth_attempts"] = received_driver._auth_open_attempts
        captured["submit_attempts"] = received_driver._email_submit_attempts
        captured["input_timeout"] = received_driver._email_input_wait_timeout

    with patch.object(antbrowser_liveness, "build_ant_driver", return_value=(driver, opened)), \
         patch.object(antbrowser_liveness, "_fill_email_and_otp", side_effect=fill), \
         patch.object(antbrowser_liveness, "_fetch_chatgpt_session", return_value={"accessToken": "fresh-token"}), \
         patch.object(antbrowser_liveness, "cleanup_ant_profile"):
        result = antbrowser_liveness.refresh_recent_login_browser("bounded@example.com")

    assert result["accessToken"] == "fresh-token"
    assert captured == {"auth_attempts": 1, "submit_attempts": 2, "input_timeout": 30}


def test_browser_login_progress_renews_watchdog_deadline():
    driver = MagicMock()
    driver.page.context.cookies.return_value = []
    opened = SimpleNamespace(profile_id="progress", raw={"proxy": "http://effective-proxy"})

    def progressing_fill(*_args, **kwargs):
        callback = kwargs["progress_callback"]
        time.sleep(0.03)
        callback("email_submitted", "邮箱已提交", {})
        time.sleep(0.03)
        callback("reauthenticated", "密码已接受", {})

    with patch.object(antbrowser_liveness, "_login_attempt_timeout", return_value=0.05), \
         patch.object(antbrowser_liveness, "build_ant_driver", return_value=(driver, opened)), \
         patch.object(antbrowser_liveness, "_fill_email_and_otp", side_effect=progressing_fill), \
         patch.object(antbrowser_liveness, "_fetch_chatgpt_session", return_value={"accessToken": "fresh-token"}), \
         patch.object(antbrowser_liveness, "cleanup_ant_profile") as cleanup:
        result = antbrowser_liveness.refresh_recent_login_browser("progress@example.com", progress_callback=lambda _message: None)

    assert result["accessToken"] == "fresh-token"
    cleanup.assert_called_once_with(opened)


def test_empty_loading_login_page_rotates_proxy_and_retries():
    drivers = [MagicMock(), MagicMock()]
    drivers[1].page.context.cookies.return_value = []
    opened = [
        SimpleNamespace(profile_id="loading-1", raw={"proxy": "http://proxy-1"}),
        SimpleNamespace(profile_id="loading-2", raw={"proxy": "http://proxy-2"}),
    ]
    attempts = [
        RuntimeError(
            "邮箱登录入口未就绪或未被识别；尚未提交邮箱，未验证密码，"
            "state={'url':'https://chatgpt.com/auth/login','readyState':'loading',"
            "'bodyPresent':False,'inputCount':0}"
        ),
        None,
    ]

    def fill(*_args, **_kwargs):
        outcome = attempts.pop(0)
        if outcome is not None:
            raise outcome

    with patch.object(antbrowser_liveness, "_rotate_retry_proxy", side_effect=lambda proxy, attempt: f"{proxy}-{attempt}"), \
         patch.object(antbrowser_liveness, "build_ant_driver", side_effect=list(zip(drivers, opened))) as build, \
         patch.object(antbrowser_liveness, "_fill_email_and_otp", side_effect=fill), \
         patch.object(antbrowser_liveness, "_fetch_chatgpt_session", return_value={"accessToken": "fresh-token"}), \
         patch.object(antbrowser_liveness, "cleanup_ant_profile") as cleanup:
        result = antbrowser_liveness.refresh_recent_login_browser(
            "loading@example.com", proxy="http://requested-proxy"
        )

    assert result["accessToken"] == "fresh-token"
    assert build.call_count == 2
    assert build.call_args_list[0].kwargs["proxy"] == "http://requested-proxy-1"
    assert build.call_args_list[1].kwargs["proxy"] == "http://requested-proxy-2"
    assert [call.args[0] for call in cleanup.call_args_list] == opened
