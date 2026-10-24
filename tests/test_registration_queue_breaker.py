from core import registration_service as service


def test_browser_target_closed_error_is_a_queue_breaker():
    assert service._is_browser_target_closed_error(
        "TargetClosedError: Page.evaluate_handle: Target page, context or browser has been closed"
    )
    assert not service._is_browser_target_closed_error("验证码等待超时")


def test_queue_breaker_cancels_pending_jobs(monkeypatch):
    calls = []

    def fake_cancel_pending_jobs(reason="用户手动取消"):
        calls.append(reason)
        return 7

    from config import register as _register_cfg
    monkeypatch.setattr(_register_cfg, "ENABLE_QUEUE_BREAKER_ON_TARGET_CLOSED", True)
    monkeypatch.setattr(service, "cancel_pending_jobs", fake_cancel_pending_jobs)

    cancelled = service._trip_browser_queue_breaker(1190, "TargetClosedError: browser has been closed")

    assert cancelled == 7
    assert calls and "任务 #1190" in calls[0]
    assert "阻止继续打开新窗口" in calls[0]
