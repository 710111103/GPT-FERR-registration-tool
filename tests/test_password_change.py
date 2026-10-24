# -*- coding: utf-8 -*-
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch
from types import SimpleNamespace

from core import db, password_change_service
from webui.app import create_app
from core.roxy_registration import _click_forgot_password_if_present


def _patches(root: Path) -> dict:
    missing = root / "missing.json"
    return {
        "_ACCOUNTS_JSON": root / "accounts.json", "_OUTLOOK_JSON": missing,
        "_GENERIC_API_EMAIL_JSON": missing, "_DOMAIN_EMAIL_JSON": missing,
        "_JOBS_JSON": missing, "_LEGACY_ACCOUNTS_JSON": missing,
        "_LEGACY_OUTLOOK_JSON": missing, "_LEGACY_JOBS_JSON": missing,
        "_LEGACY_SQLITE": root / "legacy.db", "_CODEX_DIR": root / "codex",
        "_CODEX_AGENT_DIR": root / "agents", "_LEGACY_CODEX_EXPORT_STATE": missing,
        "_SQLITE_READY": False, "_SQLITE_READY_PATH": None,
        "_VIEWER_HTML": root / "viewer.html", "_ACCOUNTS_TXT": root / "accounts.txt",
        "_TOKENS_TXT": root / "tokens.txt",
    }


def _verified_account(password="Old-Password-123!"):
    return {
        "id": 1, "email": "a@example.com", "registration_password": password,
        "password_setup_login_verified": True,
        "extra_json": json.dumps({
            "registration_password": password,
            "registration_password_verified": True,
        }),
    }


def test_password_change_failure_preserves_verified_old_password():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        root.joinpath("accounts.json").write_text(json.dumps([_verified_account()]), encoding="utf-8")
        with patch.multiple(db, **_patches(root)):
            assert db.claim_account_password_change(1, "New-Password-456!", "test")
            assert db.update_account_password_change(1, {
                "ok": False, "status": "verification_failed", "login_verified": False,
                "error": "new password login failed",
            })
            account = db.get_account(1)
            assert db.get_registration_password(account) == "Old-Password-123!"
            assert account["password_change_candidate"] == "New-Password-456!"
            assert account["password_change_ok"] is False


def test_password_change_success_atomically_promotes_verified_new_password():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        root.joinpath("accounts.json").write_text(json.dumps([_verified_account()]), encoding="utf-8")
        with patch.multiple(db, **_patches(root)):
            assert db.claim_account_password_change(1, "New-Password-456!", "test")
            assert db.get_registration_password(db.get_account(1)) == "Old-Password-123!"
            assert db.update_account_password_change(1, {
                "ok": True, "status": "success", "password": "New-Password-456!",
                "login_verified": True,
            })
            account = db.get_account(1)
            assert db.get_registration_password(account) == "New-Password-456!"
            assert account["password_change_candidate"] is None
            assert account["password_change_login_verified"] is True


def test_enqueue_rejects_account_when_remote_password_is_not_confirmed():
    with patch.object(db, "get_account", return_value={"id": 1, "email": "a@example.com"}), \
         patch.object(db, "get_registration_password", return_value=""):
        result = password_change_service.enqueue(1, "New-Password-456!")
    assert result["accepted"] is False
    assert "远端尚未确认存在密码" in result["error"]


def test_enqueue_allows_password_reset_when_remote_password_exists_but_local_password_is_invalid():
    account = {
        "id": 117,
        "email": "a@example.com",
        "password_setup_remote_password_present": True,
        "password_setup_candidate": "Invalid-Old-Password-123!",
    }
    future = object()
    with patch.object(db, "get_account", return_value=account), \
         patch.object(db, "get_registration_password", return_value=""), \
         patch.object(db, "claim_account_password_change", return_value=True), \
         patch.object(password_change_service._EXECUTOR, "submit", return_value=future):
        result = password_change_service.enqueue(117, "New-Password-456!", trigger="test")
    try:
        assert result["accepted"] is True
        assert result["future"] is future
    finally:
        with password_change_service._LOCK:
            password_change_service._QUEUED.discard(117)
        password_change_service._QUEUE.release()


def test_start_password_reset_retries_when_page_navigates_during_evaluate():
    driver = MagicMock()
    expected = "https://auth.openai.com/authorize?post_login_password_reset=true"
    driver.page.evaluate.side_effect = [
        RuntimeError("Execution context was destroyed"),
        {"ok": True, "stage": "signin", "status": 200, "url": expected, "text": "{}"},
    ]
    with patch("core.password_setup_service.time.sleep"):
        actual = password_change_service._start_add_password_flow(
            driver, "a@example.com", "did-1", reset=True,
        )
    assert actual == expected
    assert driver.page.evaluate.call_count == 2


def test_start_password_reset_retries_when_csrf_endpoint_temporarily_returns_html():
    driver = MagicMock()
    expected = "https://auth.openai.com/authorize?post_login_password_reset=true"
    driver.page.evaluate.side_effect = [
        {"ok": False, "stage": "csrf", "status": 200, "text": "<html>edge warmup</html>"},
        {"ok": True, "stage": "signin", "status": 200, "url": expected, "text": "{}"},
    ]
    with patch("core.password_setup_service.time.sleep"):
        actual = password_change_service._start_add_password_flow(
            driver, "a@example.com", "did-1", reset=True,
        )
    assert actual == expected
    assert driver.page.evaluate.call_count == 2
    assert driver.get.call_count == 2


def test_forgot_password_uses_native_clickable_target():
    driver = MagicMock()
    locator = MagicMock()
    button = SimpleNamespace(locator=locator)
    driver.forgot_password_target_native.return_value = {
        "ok": True,
        "reason": "playwright_native_forgot_password",
        "button": button,
        "href": "https://auth.openai.com/reset-password",
        "text": "Forgot password?",
    }
    driver.current_url = "https://auth.openai.com/reset-password"
    result = _click_forgot_password_if_present(driver)
    assert result["ok"] is True
    assert result["reason"] == "clicked_forgot_password"
    locator.click.assert_called_once()

def test_run_only_commits_after_fresh_login_verification():
    account = _verified_account()
    driver = MagicMock()
    opened = {"profile": "test"}
    with patch.object(db, "get_account", return_value=account), \
         patch.object(db, "update_account_password_change", return_value=True) as update, \
         patch.object(password_change_service, "_open_password_reauth_with_proxy_rotation", return_value=(driver, opened, "https://auth.openai.com/x")), \
         patch.object(password_change_service, "_fill_email_and_otp"), \
         patch.object(password_change_service, "_submit_new_password"), \
         patch.object(password_change_service, "_verify_password_login", return_value={"user": {"email": "a@example.com"}}) as verify, \
         patch.object(password_change_service, "cleanup_ant_profile"), \
         patch.object(password_change_service, "_append_log"):
        # _run owns one semaphore slot in production.
        password_change_service._QUEUE.acquire()
        result = password_change_service._run(1, "New-Password-456!", "test")
    assert result["ok"] is True
    verify.assert_called_once_with(account, "New-Password-456!")
    success = [call.args[1] for call in update.call_args_list if call.args[1].get("status") == "success"]
    assert success and success[-1]["login_verified"] is True
    assert success[-1]["password"] == "New-Password-456!"


def test_password_change_api_queues_real_remote_change_service():
    td = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    try:
        root = Path(td.name)
        root.joinpath("accounts.json").write_text(json.dumps([_verified_account()]), encoding="utf-8")
        with patch.multiple(db, **_patches(root)):
            app = create_app(auth_code="test-auth")
            client = app.test_client()
            with patch("core.password_change_service.enqueue", return_value={
                "accepted": True, "future": object(), "log_path": "x", "generated": False,
            }) as enqueue:
                response = client.post(
                    "/api/accounts/1/password-change",
                    json={"new_password": "New-Password-456!"},
                    headers={"X-Auth-Code": "test-auth"},
                )
        assert response.status_code == 202
        assert response.get_json()["ok"] is True
        assert "future" not in response.get_json()
        enqueue.assert_called_once_with(1, new_password="New-Password-456!", trigger="manual")
    finally:
        try:
            td.cleanup()
        except Exception:
            pass




def test_compact_account_api_never_exposes_unverified_change_candidate():
    account = _verified_account()
    account.update({
        "password_change_status": "verification_failed",
        "password_change_candidate": "Hidden-New-Password-789!",
        "password_change_login_verified": False,
    })
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        root.joinpath("accounts.json").write_text(json.dumps([account]), encoding="utf-8")
        with patch.multiple(db, **_patches(root)):
            app = create_app(auth_code="test-auth")
            client = app.test_client()
            response = client.get(
                "/api/accounts?paged=1&page=1&page_size=10",
                headers={"X-Auth-Code": "test-auth"},
            )
    assert response.status_code == 200
    item = response.get_json()["items"][0]
    assert item["password"] == "Old-Password-123!"
    assert "password_change_candidate" not in item
    assert "Hidden-New-Password-789!" not in response.get_data(as_text=True)

