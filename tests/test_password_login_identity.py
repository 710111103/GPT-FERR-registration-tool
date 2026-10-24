from unittest.mock import patch
from core import password_setup_service as service


def test_candidate_is_not_verified_without_matching_session_identity():
    result = {
        "ok": True, "password_accepted": True,
        "access_token": "new-token",
        "session": {"user": {"email": "other@example.com"}},
    }
    with patch("core.account_liveness.check_account_liveness", return_value=result) as check, \
         patch.object(service, "_password_proxy_for_attempt", return_value="http://proxy.test:8080"), \
         patch.object(service, "_append_log"):
        try:
            service._verify_password_via_liveness({"email": "user@example.com"}, "candidate", 1)
        except RuntimeError as exc:
            assert "验收证据不足" in str(exc)
        else:
            assert False, "mismatched identity was promoted"
    assert check.call_count == 3
    assert all(call.kwargs["force_password_login"] and call.kwargs["skip_existing_token_probe"] for call in check.call_args_list)


def test_candidate_is_verified_with_fresh_matching_session():
    result = {
        "ok": True, "password_accepted": True,
        "access_token": "new-token",
        "session": {"user": {"email": "user@example.com"}},
    }
    with patch("core.account_liveness.check_account_liveness", return_value=result), \
         patch.object(service, "_password_proxy_for_attempt", return_value="http://proxy.test:8080"), \
         patch.object(service, "_append_log"):
        assert service._verify_password_via_liveness({"email": "USER@example.com"}, "candidate", 1) is result

def test_candidate_is_not_verified_when_existing_user_id_differs():
    result = {
        "ok": True, "password_accepted": True,
        "access_token": "new-token",
        "session": {"user": {"email": "user@example.com", "id": "other-id"}},
    }
    with patch("core.account_liveness.check_account_liveness", return_value=result), \
         patch.object(service, "_password_proxy_for_attempt", return_value="http://proxy.test:8080"), \
         patch.object(service, "_append_log"):
        try:
            service._verify_password_via_liveness({
                "email": "user@example.com", "extra_json": '{"user": {"id": "expected-id"}}',
            }, "candidate", 1)
        except RuntimeError as exc:
            assert "验收证据不足" in str(exc)
        else:
            assert False, "mismatched account ID was promoted"

def test_navigation_failure_is_pending_not_password_wrong():
    result = {"ok": False, "error": "无头浏览器未能完成 Signin 导航"}
    with patch("core.account_liveness.check_account_liveness", return_value=result), \
         patch.object(service, "_password_proxy_for_attempt", return_value="http://proxy.test:8080"), \
         patch.object(service, "_append_log"):
        try:
            service._verify_password_via_liveness({"email": "user@example.com"}, "candidate", 1)
        except RuntimeError as exc:
            assert "密码验证待重试" in str(exc)
            assert service._is_password_verification_network_error(str(exc))
        else:
            assert False, "navigation failure treated as success"


def test_candidate_verification_fails_closed_when_proxy_missing():
    with patch.object(service, "_password_proxy_for_attempt", return_value=None), \
         patch("core.account_liveness.check_account_liveness") as check:
        try:
            service._verify_password_via_liveness({"email": "user@example.com"}, "candidate", 1)
        except RuntimeError as exc:
            assert "需要代理" in str(exc)
        else:
            assert False, "missing proxy must not reach login"
        check.assert_not_called()
