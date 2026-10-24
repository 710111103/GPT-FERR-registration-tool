from unittest.mock import MagicMock, patch

from core.roxy_registration import _read_chatgpt_session_once


def test_403_is_logged_as_status_without_response_body():
    driver = MagicMock()
    driver.execute_async_script.return_value = {"ok": False, "status": 403, "contentType": "text/html", "data": {}}
    with patch("core.roxy_registration.logger.info") as log:
        assert _read_chatgpt_session_once(driver) is None
    assert any(403 in call.args for call in log.call_args_list)
    assert "fetch('/api/auth/session'" in driver.execute_async_script.call_args.args[0]


def test_200_token_is_returned_without_logging_its_value():
    driver = MagicMock()
    driver.execute_async_script.return_value = {"ok": True, "status": 200, "data": {"accessToken": "secret-test-token"}}
    with patch("core.roxy_registration.logger.info") as log:
        assert _read_chatgpt_session_once(driver)["accessToken"] == "secret-test-token"
    assert "secret-test-token" not in repr(log.call_args_list)
