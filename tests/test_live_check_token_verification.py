from unittest.mock import Mock, patch

import pytest
from core import live_check_service as service


@pytest.mark.parametrize("probe", [
    {"valid": None, "status_code": 403, "error": "HTTP 403"},
    {"valid": False, "status_code": 401, "error": "expired"},
])
def test_new_token_is_not_accepted_without_http_200(probe):
    session = Mock()
    with patch("core.session.BrowserSession", return_value=session), \
         patch("core.account_liveness.probe_access_token_liveness", return_value=probe):
        with pytest.raises(RuntimeError, match="旧 AT 保持不变"):
            service._verify_browser_token("new", {"user": {"email": "a@example.com"}}, {}, "a@example.com", "socks5://example:1080")
    session.session.close.assert_called_once()


def test_new_token_rejects_wrong_account_without_network():
    with patch("core.session.BrowserSession") as ctor:
        with pytest.raises(RuntimeError, match="邮箱缺失或不匹配"):
            service._verify_browser_token("new", {"user": {"email": "other@example.com"}}, {}, "a@example.com", "proxy")
    ctor.assert_not_called()


def test_new_token_accepts_matching_identity_and_http_200():
    session = Mock()
    probe = {"valid": True, "status_code": 200, "user_id": "same"}
    with patch("core.session.BrowserSession", return_value=session), \
         patch("core.account_liveness.probe_access_token_liveness", return_value=probe):
        assert service._verify_browser_token("new", {"user": {"email": "a@example.com", "id": "same"}}, {}, "a@example.com", "proxy") == probe
    session.session.close.assert_called_once()
