# -*- coding: utf-8 -*-
from unittest.mock import patch

from core import roxy_codex_oauth as oauth
from webui.app import _compact_account_for_list


class _OtpDriver:
    current_url = "https://auth.openai.com/email-verification"

    def execute_script(self, script):
        if "__codexEmailOtpValidateResponses" in script:
            return []
        return False


def test_japanese_incorrect_code_is_detected_immediately():
    state = {
        "inputs": [{"ariaInvalid": "false"}],
        "errors": [],
        "text": "受信箱を確認してください 不正確なコード メールを再送信",
    }
    with patch.object(oauth, "_email_otp_page_state", return_value=state), \
         patch.object(oauth, "_has_strict_add_phone_form", return_value=False), \
         patch.object(oauth, "_is_phone_code_page", return_value=False):
        assert oauth._wait_after_email_otp_submit(_OtpDriver(), timeout=1) == "invalid"


def test_login_url_still_gets_three_otp_attempts():
    assert oauth._email_otp_retry_policy("https://chatgpt.com/auth/login?email=x") == (3, 60)
    assert oauth._email_otp_retry_policy("https://auth.openai.com/authorize") == (3, 90)


def test_failed_code_is_forwarded_to_provider_exclusion():
    calls = []

    def provider(email, after_ts=None, exclude_codes=None):
        calls.append(set(exclude_codes or set()))
        return "654321"

    code = oauth._wait_for_fresh_email_otp(
        provider, "a@example.com", after_ts=123.0, used_codes={"313431"}, timeout=1,
    )
    assert code == "654321"
    assert calls == [{"313431"}]


def test_unverified_password_is_not_exposed_in_account_list():
    row = {
        "id": 1,
        "email": "a@example.com",
        "registration_password": "wrong-candidate",
        "password_setup_candidate": "wrong-candidate",
        "password_setup_status": "verification_failed",
        "password_setup_login_verified": False,
        "extra_json": '{"registration_password":"wrong-candidate","registration_password_verified":false}',
    }
    item = _compact_account_for_list(row)
    assert "password" not in item
    assert item["password_saved"] is False
    assert item["password_status"] == "验证失败"


def test_pending_password_is_visible_but_not_counted_as_verified():
    row = {
        "id": 2, "email": "pending@example.com", "password_setup_candidate": "Candidate-123!",
        "password_setup_status": "verification_pending", "password_setup_login_verified": False,
        "extra_json": "{}",
    }
    item = _compact_account_for_list(row)
    assert item["password_candidate"] == "Candidate-123!"
    assert item["password_status"] == "待验证"
    assert item["password_saved"] is False
    assert "password" not in item
    row["password_setup_status"] = "verifying"
    assert _compact_account_for_list(row)["password_candidate"] == "Candidate-123!"
    from pathlib import Path
    html = (Path(__file__).resolve().parents[1] / "webui/templates/index.html").read_text(encoding="utf-8")
    assert "status === '待验证' && r.password_candidate" in html
    assert "待验证</span>" in html



def test_paged_account_api_keeps_pending_candidate_separate_from_verified_password():
    from webui.app import create_app
    app = create_app(auth_code="test-auth")
    row = {
        "id": 2, "email": "pending@example.com", "password_setup_candidate": "Candidate-123!",
        "password_setup_status": "verification_pending", "password_setup_login_verified": False,
        "extra_json": "{}",
    }
    with patch("webui.app.db.list_accounts_page", return_value={"items": [row], "total": 1}):
        response = app.test_client().get("/api/accounts?paged=1", headers={"X-Auth-Code": "test-auth"})
    assert response.status_code == 200
    item = response.get_json()["items"][0]
    assert item["password_candidate"] == "Candidate-123!"
    assert item["password_status"] == "待验证"
    assert item["password_saved"] is False
    assert "password" not in item
