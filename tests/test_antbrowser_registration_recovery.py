from __future__ import annotations

import os

import core.antbrowser_registration as module


def test_recoverable_errors_are_classified():
    assert module._is_recoverable_registration_error(
        "TargetClosedError: Page.evaluate_handle: Target page, context or browser has been closed"
    )
    assert module._is_recoverable_registration_error("等待 /api/auth/session accessToken 超时")
    assert module._is_recoverable_registration_error("找不到 OTP 输入框")
    assert module._is_recoverable_registration_error(
        "[navigation_error] OTP 页面浏览器导航失败: url=chrome-error://chromewebdata/"
    )
    assert not module._is_recoverable_registration_error("邮箱验证码连续错误/过期")
    assert not module._is_recoverable_registration_error("account_creation_failed")


def test_transient_error_rebuilds_once(monkeypatch):
    calls = []

    def flaky(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("TargetClosedError: browser has been closed")
        return {"ok": True}

    monkeypatch.setattr(module, "_run_ant_registration_once", flaky)
    monkeypatch.setenv("ANT_REGISTRATION_RECOVERY_RETRIES", "1")
    assert module.run_ant_registration("fixture") == {"ok": True}
    assert len(calls) == 2


def test_business_error_is_not_retried(monkeypatch):
    calls = []

    def hard_failure(*args, **kwargs):
        calls.append(1)
        raise RuntimeError("account_creation_failed")

    monkeypatch.setattr(module, "_run_ant_registration_once", hard_failure)
    monkeypatch.setenv("ANT_REGISTRATION_RECOVERY_RETRIES", "1")
    try:
        module.run_ant_registration("fixture")
    except RuntimeError as exc:
        assert "account_creation_failed" in str(exc)
    else:
        raise AssertionError("business error unexpectedly succeeded")
    assert len(calls) == 1
