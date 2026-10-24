from types import SimpleNamespace
from unittest.mock import Mock
import pytest
from core.browser_environment import _require_email_login_form, _signin_diagnostics

def test_challenge_403_does_not_wait_for_nonexistent_email_input():
    page = Mock()
    page.title.return_value = "Just a moment..."
    with pytest.raises(RuntimeError, match="HTTP Error 403"):
        _require_email_login_form(page, SimpleNamespace(status=403))
    page.locator.assert_not_called()

def test_normal_login_form_returns_email_input():
    page = Mock()
    page.title.return_value = "Log in"
    form = page.locator.return_value.first
    assert _require_email_login_form(page, SimpleNamespace(status=200)) is form
    form.wait_for.assert_called_once_with(state="visible", timeout=5000)

def test_missing_form_reports_page_state_not_wrong_password():
    page = Mock()
    page.title.return_value = "Service unavailable"
    page.locator.return_value.first.wait_for.side_effect = TimeoutError("missing form")
    with pytest.raises(RuntimeError, match="missing email input.*HTTP 200"):
        _require_email_login_form(page, SimpleNamespace(status=200))


def test_diagnostics_do_not_log_email_or_full_urls():
    page = Mock()
    page.title.return_value = "Log in"
    page.locator.return_value.first.is_enabled.return_value = True
    input_field = Mock()
    input_field.input_value.return_value = "user@example.com"
    report = _signin_diagnostics(page, input_field, "user@example.com", [
        {"stage": "signin", "status": 403, "challenge": True},
    ])
    assert "email_matches=True" in report
    assert "signin:403:True" in report
    assert "user@example.com" not in report
