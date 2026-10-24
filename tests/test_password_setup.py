# -*- coding: utf-8 -*-
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from core import db
from webui.app import create_app


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


def test_candidate_is_only_promoted_after_verified_success():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "accounts.json").write_text(json.dumps([{"id": 1, "email": "a@example.com", "extra_json": "{}"}]), encoding="utf-8")
        with patch.multiple(db, **_patches(root)):
            assert db.update_account_password_setup(1, {
                "status": "verifying", "candidate_password": "Candidate-123!",
                "remote_password_present": True,
            })
            pending = db.get_account(1)
            assert pending.get("registration_password") in (None, "")
            assert pending["password_setup_candidate"] == "Candidate-123!"
            assert db.update_account_password_setup(1, {
                "ok": True, "status": "success", "password": "Candidate-123!",
                "login_verified": True,
            })
            done = db.get_account(1)
            assert done["registration_password"] == "Candidate-123!"
            assert done.get("password_setup_candidate") is None


def test_password_setup_endpoint_queues_task():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "accounts.json").write_text(json.dumps([{"id": 1, "email": "a@example.com"}]), encoding="utf-8")
        with patch.multiple(db, **_patches(root)):
            app = create_app(auth_code="test-auth")
            client = app.test_client()
            with patch("core.password_setup_service.enqueue", return_value={"accepted": True, "future": object(), "log_path": "x"}) as enqueue:
                response = client.post("/api/accounts/1/password-setup", headers={"X-Auth-Code": "test-auth"})
            enqueue.assert_called_once_with(1, trigger="manual", missing_only=False)
            assert response.status_code == 202
            body = response.get_json()
            assert body["ok"] is True
            assert "future" not in body


def test_password_setup_bulk_queues_selected_accounts():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "accounts.json").write_text(json.dumps([
            {"id": 1, "email": "a@example.com"},
            {"id": 2, "email": "b@example.com"},
            {"id": 3, "email": ""},
        ]), encoding="utf-8")
        with patch.multiple(db, **_patches(root)):
            app = create_app(auth_code="test-auth")
            client = app.test_client()
            def enqueue(acc_id, *args, **kwargs):
                if acc_id == 2:
                    return {"accepted": False, "busy": True, "error": "进行中", "future": object()}
                return {"accepted": True, "future": object(), "log_path": "x"}
            with patch("core.password_setup_service.enqueue", side_effect=enqueue) as mocked:
                response = client.post("/api/accounts/password-setup-bulk", json={"account_ids": [1, 1, 2, 3, 99, "bad"]}, headers={"X-Auth-Code": "test-auth"})
            assert response.status_code == 202
            body = response.get_json()
            assert body["started_count"] == 1
            assert body["busy_count"] == 1
            assert body["skipped_count"] == 3
            assert mocked.call_args_list[0].args[0] == 1
            assert mocked.call_args_list[0].kwargs == {"trigger": "manual_bulk", "missing_only": False}


def test_password_setup_all_missing_endpoint_starts_scheduler():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "accounts.json").write_text(json.dumps([
            {"id": 1, "email": "a@example.com", "extra_json": "{}"},
            {"id": 2, "email": "b@example.com", "extra_json": json.dumps({"registration_password": "existing"})},
        ]), encoding="utf-8")
        with patch.multiple(db, **_patches(root)):
            app = create_app(auth_code="test-auth")
            client = app.test_client()
            with patch("core.password_setup_service.start_missing_password_batch", return_value={"accepted": True, "started": True, "status": {"total": 1}}) as starter:
                response = client.post("/api/accounts/password-setup-all-missing", json={}, headers={"X-Auth-Code": "test-auth"})
            assert response.status_code == 202
            assert response.get_json()["status"]["total"] == 1
            starter.assert_called_once_with(include_archived=False)


def test_update_job_persists_registration_stage():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "jobs.json").write_text(json.dumps([{
            "id": 7, "status": "running", "email": "a@example.com"
        }]), encoding="utf-8")
        patches = _patches(root)
        patches["_JOBS_JSON"] = root / "jobs.json"
        with patch.multiple(db, **patches):
            db.update_job(7, registration_stage={"password_set": True, "flow": "protocol"})
            assert db.get_job(7)["registration_stage"]["password_set"] is True


def test_missing_password_snapshot_uses_registration_password_not_mailbox_password():
    from core import password_setup_service
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "accounts.json").write_text(json.dumps([
            {"id": 1, "email": "mailbox@example.com", "password": "mailbox-secret", "extra_json": "{}"},
            {"id": 2, "email": "ready@example.com", "password": "mailbox-secret", "extra_json": json.dumps({"registration_password": "chatgpt-secret", "registration_password_verified": True})},
            {"id": 3, "email": "", "extra_json": "{}"},
        ]), encoding="utf-8")
        with patch.multiple(db, **_patches(root)):
            assert password_setup_service._snapshot_missing_password_ids() == [1]


def test_missing_password_status_and_cancel_endpoints():
    app = create_app(auth_code="test-auth")
    client = app.test_client()
    with patch("core.password_setup_service.get_missing_password_batch_status", return_value={"status": "running", "total": 3, "processed": 1}):
        response = client.get("/api/accounts/password-setup-all-missing/status", headers={"X-Auth-Code": "test-auth"})
    assert response.status_code == 200
    assert response.get_json()["processed"] == 1
    with patch("core.password_setup_service.cancel_missing_password_batch", return_value={"accepted": True, "status": {"status": "stopping"}}):
        response = client.post("/api/accounts/password-setup-all-missing/cancel", headers={"X-Auth-Code": "test-auth"})
    assert response.status_code == 200
    assert response.get_json()["accepted"] is True


def test_unverified_protocol_candidate_is_not_exposed_as_password():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "accounts.json").write_text(json.dumps([{
            "id": 1, "email": "candidate@example.com",
            "registration_password": "wrong-candidate",
            "password_setup_remote_password_present": True,
            "password_setup_ok": True,
            "extra_json": json.dumps({"registration_password": "wrong-candidate"}),
        }]), encoding="utf-8")
        with patch.multiple(db, **_patches(root)):
            assert db.update_account_password_setup(1, {
                "ok": False, "status": "verification_failed",
                "candidate_password": "wrong-candidate",
                "remote_password_present": True,
                "login_verified": False,
                "error": "incorrect email or password",
            })
            account = db.get_account(1)
            assert account["password_setup_status"] == "verification_failed"
            assert account["password_setup_login_verified"] is False
            assert account["password_setup_ok"] is False
            assert db.get_registration_password(account) == ""
            assert account["password_setup_candidate"] == "wrong-candidate"


def test_bulk_password_setup_uses_login_verified_service():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "accounts.json").write_text(json.dumps([
            {"id": 1, "email": "a@example.com"},
            {"id": 2, "email": "b@example.com"},
        ]), encoding="utf-8")
        with patch.multiple(db, **_patches(root)):
            app = create_app(auth_code="test-auth")
            client = app.test_client()
            with patch("core.password_setup_service.enqueue", return_value={"accepted": True, "future": object(), "log_path": "x"}) as enqueue:
                response = client.post(
                    "/api/accounts/password-setup-bulk",
                    json={"account_ids": [1, 2]},
                    headers={"X-Auth-Code": "test-auth"},
                )
            assert response.status_code == 202
            assert response.get_json()["started_count"] == 2
            assert [call.args[0] for call in enqueue.call_args_list] == [1, 2]
            assert all(call.kwargs == {"trigger": "manual_bulk", "missing_only": False} for call in enqueue.call_args_list)


def test_unverified_candidate_is_rejected_by_totp_rotation_and_material_export():
    from core.account_export import _account_material_line
    from core.twofa_rotation_service import _password_from_account

    candidate = "wrong-candidate"
    account = {
        "id": 1,
        "email": "candidate@example.com",
        "original_email_line": "candidate@example.com",
        "totp_secret": "JBSWY3DPEHPK3PXP",
        "registration_password": candidate,
        "password_setup_login_verified": False,
        "extra_json": json.dumps({
            "registration_password": candidate,
            "registration_password_verified": False,
        }),
    }
    assert _password_from_account(account) == ""
    assert candidate not in _account_material_line(account["email"], account)

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "accounts.json").write_text(json.dumps([account]), encoding="utf-8")
        with patch.multiple(db, **_patches(root)):
            app = create_app(auth_code="test-auth")
            client = app.test_client()
            with patch("core.twofa_rotation_service.enqueue_account_totp_rotation") as enqueue:
                response = client.post(
                    "/api/accounts/1/totp-rotate",
                    headers={"X-Auth-Code": "test-auth"},
                )
            assert response.status_code == 400
            assert "缺少登录密码" in response.get_json()["error"]
            enqueue.assert_not_called()




def test_password_setup_switches_from_add_to_reset_when_remote_password_exists():
    from core import password_setup_service

    account = {
        "id": 124,
        "email": "switch@example.com",
        "device_id": "did-124",
        "email_source": "generic_api",
        "password_setup_remote_password_present": False,
        "extra_json": "{}",
    }
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "accounts.json").write_text(json.dumps([account]), encoding="utf-8")
        with patch.multiple(db, **_patches(root)):
            fake_driver_1 = object()
            fake_driver_2 = object()
            open_calls = []

            def fake_open(acc, *, reset, attempts, on_retry=None):
                open_calls.append(reset)
                if not reset:
                    return fake_driver_1, "profile-1", "https://auth.openai.com/add"
                return fake_driver_2, "profile-2", "https://auth.openai.com/reset"

            submit_calls = []

            def fake_submit(drv, pwd, **_kwargs):
                submit_calls.append(drv)
                if drv is fake_driver_1:
                    raise RuntimeError("remote_password_present: 页面要求输入当前密码；该账号应走 password-reset")
                return None

            cleaned_profiles = []
            verified_calls = []

            with patch("core.password_setup_service._open_password_reauth_with_proxy_rotation", side_effect=fake_open), \
                 patch("core.password_setup_service._fill_email_and_otp"), \
                 patch("core.password_setup_service._submit_new_password", side_effect=fake_submit), \
                 patch("core.password_setup_service.cleanup_ant_profile", side_effect=lambda p: cleaned_profiles.append(p)), \
                 patch("core.password_setup_service._verify_password_via_liveness", side_effect=lambda acc, pwd, account_id: (verified_calls.append(pwd), {"ok": True, "password_accepted": True, "access_token": "new-token"})[1]):
                result = password_setup_service._run(124, trigger="manual", missing_only=False)

            assert result["ok"] is True
            assert result["status"] == "success"
            assert open_calls == [False, True]
            assert submit_calls == [fake_driver_1, fake_driver_2]
            assert "profile-1" in cleaned_profiles
            assert len(verified_calls) == 1
            updated = db.get_account(124)
            assert updated["password_setup_remote_password_present"] is True
            assert updated["password_setup_login_verified"] is True
            assert bool(updated.get("registration_password")) is True



def test_batch_candidate_verification_runs_in_background_without_exposing_secrets():
    from core import password_setup_service as service
    ids = [11, 12, 13]
    fake = [
        {"ok": True, "password": "secret-pw", "access_token": "secret-at"},
        {"ok": False, "is_wrong_password": True, "error": "密码错误"},
        {"ok": False, "error": "该账号未找到待验证的候选密码"},
    ]
    with patch.object(service, "verify_account_candidate_password", side_effect=fake) as verify:
        service._run_candidate_verification_batch(ids)
    state = service.candidate_verification_batch_status()
    assert state["status"] == "completed"
    assert (state["success_count"], state["failed_count"], state["skipped_count"]) == (1, 1, 1)
    assert [x["category"] for x in state["results"]] == ["success", "wrong_password", "skipped"]
    assert "secret-pw" not in str(state) and "secret-at" not in str(state)
    assert verify.call_count == 3


def test_bulk_verify_endpoint_queues_and_reports_progress():
    from core import password_setup_service as service
    app = create_app(auth_code="test-auth")
    client = app.test_client()
    with patch.object(service, "enqueue_candidate_verification_batch", return_value={"accepted": True, "total": 2, "status": "queued"}) as enqueue, \
         patch.object(service, "candidate_verification_batch_status", return_value={"status": "running", "total": 2, "processed": 1, "results": []}):
        headers = {"X-Auth-Code": "test-auth"}
        response = client.post("/api/accounts/verify-passwords-bulk", json={"account_ids": [11, 11, 12]}, headers=headers)
        assert response.status_code == 202
        enqueue.assert_called_once_with([11, 12])
        progress = client.get("/api/accounts/verify-passwords-bulk/status", headers=headers)
        assert progress.status_code == 200
        assert progress.get_json()["processed"] == 1


def test_candidate_network_failure_is_flagged_not_promoted():
    from core import password_setup_service as service
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "accounts.json").write_text(json.dumps([{"id": 1, "email": "a@example.com", "password": "candidate", "extra_json": "{}"}]), encoding="utf-8")
        with patch.multiple(db, **_patches(root)), \
             patch.object(service, "_verify_password_via_liveness", side_effect=RuntimeError("HTTP 403")), \
             patch.object(service, "_append_log"):
            result = service.verify_account_candidate_password(1)
            account = db.get_account(1)
        assert result["ok"] is False and result["is_wrong_password"] is False
        assert account["password_setup_status"] == "verification_pending"
        assert account["password_setup_login_verified"] is False
        assert "密码真伪未确定" in account["password_setup_message"]


def test_quick_verify_menu_is_wired_to_modal_login_verification():
    source = (Path(__file__).resolve().parents[1] / "webui" / "templates" / "index.html").read_text(encoding="utf-8")
    assert "data-account-quick-verify-password=" in source
    assert "const quickVerifyPasswordBtn = e.target.closest('[data-account-quick-verify-password]');" in source
    assert "openPasswordManageModal(Number(quickVerifyPasswordBtn.dataset.accountQuickVerifyPassword));\n    await doVerifyPasswordInModal();" in source
    assert "bind('btnDoVerifyPassword', doVerifyPasswordInModal);" in source


def test_single_verify_endpoint_returns_failure_reason_without_promoting():
    from core import password_setup_service as service
    app = create_app(auth_code="test-auth")
    client = app.test_client()
    with patch.object(service, "verify_account_candidate_password", return_value={"ok": False, "error": "HTTP 403"}) as verify:
        response = client.post("/api/accounts/123/verify-password", json={"password": "test-value"}, headers={"X-Auth-Code": "test-auth"})
    assert response.status_code == 400
    assert response.get_json()["error"] == "HTTP 403"
    verify.assert_called_once_with(123, password="test-value")


def test_headless_403_uses_fingerprint_browser_and_requires_matching_session():
    from core import password_setup_service as service
    failure = {"ok": False, "error": "[login_preflight] HTTP 403"}
    browser = {"user": {"email": "user@example.com"}, "accessToken": "fresh-at", "password_accepted": True}
    with patch("core.account_liveness.check_account_liveness", return_value=failure) as headless, \
         patch.object(service, "_password_proxy_for_attempt", return_value="http://proxy.test:8080"), \
         patch.object(service, "_verify_password_login", return_value=browser) as fingerprint, \
         patch.object(service, "_append_log"):
        result = service._verify_password_via_liveness({"email": "user@example.com"}, "candidate", 1)
    assert result["ok"] and result["access_token"] == "fresh-at"
    fingerprint.assert_called_once()
    assert headless.call_count == 1

def test_fingerprint_browser_challenge_without_session_does_not_verify():
    from core import password_setup_service as service
    failure = {"ok": False, "error": "[login_preflight] HTTP 403"}
    browser = {"user": {"email": "user@example.com"}, "password_accepted": True}
    with patch("core.account_liveness.check_account_liveness", return_value=failure), \
         patch.object(service, "_password_proxy_for_attempt", return_value="http://proxy.test:8080"), \
         patch.object(service, "_verify_password_login", return_value=browser), \
         patch.object(service, "_append_log"):
        try:
            service._verify_password_via_liveness({"email": "user@example.com"}, "candidate", 1)
        except RuntimeError as exc:
            assert "待重试" in str(exc)
        else:
            assert False, "challenge-only result was accepted"
