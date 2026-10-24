from unittest.mock import patch
import pytest
from core import password_setup_protocol_job as job
from core import password_setup_service as service

ACCOUNT = {"email": "someone@example.com"}


def test_protocol_login_is_the_only_success_path():
    with patch.object(job.password_setup_service, "_verify_password_via_liveness", return_value={"ok": True, "password_accepted": True, "access_token": "new", "session": {"user": {"email": "someone@example.com"}}}) as protocol, patch.object(job.password_setup_service, "_verify_password_login") as browser:
        assert job._verify_submitted_password(ACCOUNT, "pw", 1) == "protocol"
    protocol.assert_called_once_with(ACCOUNT, "pw", 1, protocol_only=True)
    browser.assert_not_called()


def test_challenge_does_not_fall_back_to_browser():
    with patch.object(job.password_setup_service, "_verify_password_via_liveness", side_effect=RuntimeError("HTTP 403")), patch.object(job.password_setup_service, "_verify_password_login") as browser:
        with pytest.raises(RuntimeError, match="403"):
            job._verify_submitted_password(ACCOUNT, "pw", 1)
    browser.assert_not_called()


def test_browser_receipt_cannot_count_as_protocol_success():
    with patch.object(job.password_setup_service, "_verify_password_via_liveness", return_value={"proxy_used": "fingerprint_browser"}), patch.object(job.password_setup_service, "_verify_password_login") as browser:
        with pytest.raises(RuntimeError, match="浏览器会话"):
            job._verify_submitted_password(ACCOUNT, "pw", 1)
    browser.assert_not_called()


def test_protocol_only_403_stays_pending_without_browser():
    with patch("core.account_liveness.check_account_liveness", return_value={"ok": False, "error": "HTTP 403"}) as protocol, patch.object(service, "_password_proxy_for_attempt", return_value="http://proxy.test:8080"), patch.object(service, "_verify_password_login") as browser, patch.object(service, "_append_log"):
        with pytest.raises(RuntimeError, match="待重试"):
            service._verify_password_via_liveness(ACCOUNT, "pw", 1, protocol_only=True)
    assert protocol.call_count == 3
    browser.assert_not_called()
