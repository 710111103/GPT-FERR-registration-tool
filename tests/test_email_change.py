# -*- coding: utf-8 -*-
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

from core import db
from core import antbrowser_liveness
from core import email_change_service
from webui.app import create_app


class EmailChangeTests(unittest.TestCase):
    @staticmethod
    def storage(root: Path) -> dict:
        return {
            "_ACCOUNTS_JSON": root / "accounts.json", "_OUTLOOK_JSON": root / "outlook.json",
            "_GENERIC_API_EMAIL_JSON": root / "generic.json", "_DOMAIN_EMAIL_JSON": root / "domain.json",
            "_JOBS_JSON": root / "jobs.json", "_LEGACY_ACCOUNTS_JSON": root / "legacy-accounts.json",
            "_LEGACY_OUTLOOK_JSON": root / "legacy-outlook.json", "_LEGACY_JOBS_JSON": root / "legacy-jobs.json",
            "_LEGACY_SQLITE": root / "legacy.db", "_CODEX_DIR": root / "codex",
            "_CODEX_AGENT_DIR": root / "agent", "_LEGACY_CODEX_EXPORT_STATE": root / "state.json",
            "_SQLITE_READY": False, "_SQLITE_READY_PATH": None,
        }

    def test_finish_keeps_original_and_switches_current_email(self):
        with tempfile.TemporaryDirectory() as td, patch.multiple(db, **self.storage(Path(td))):
            account_id = db.insert_account(email="old@example.com", access_token="old-token", email_source="outlook")
            self.assertTrue(db.claim_account_email_change(account_id, "imap"))
            self.assertTrue(db.mark_account_email_change_running(account_id, "new@example.com"))
            self.assertTrue(db.finish_account_email_change(
                account_id, ok=True, new_email="new@example.com", source="imap",
                material_line="new@example.com----imap-pass",
            ))
            row = db.get_account(account_id)
            self.assertEqual(row["original_email"], "old@example.com")
            self.assertEqual(row["email"], "new@example.com")
            self.assertEqual(row["email_source"], "imap")
            self.assertEqual(row["access_token"], "")
            self.assertEqual(row["email_change_status"], "success")

    def test_account_age_gate_reports_eligible_time(self):
        now = datetime(2026, 9, 17, 21, 35, 0)
        error = email_change_service._account_age_error(
            {"created_at": "2026-09-17T17:37:20"},
            now=now,
        )

        self.assertIn("账号创建未满24小时", error)
        self.assertIn("2026-09-18 17:37:20", error)

    def test_account_age_gate_allows_account_after_24_hours(self):
        now = datetime(2026, 9, 18, 17, 37, 20)
        self.assertIsNone(email_change_service._account_age_error(
            {"created_at": "2026-09-17T17:37:20"},
            now=now,
        ))

    def test_enqueue_rejects_young_account_before_claiming_or_allocating(self):
        account = {
            "id": 29,
            "created_at": datetime.now().isoformat(timespec="seconds"),
        }
        with patch.object(email_change_service.db, "get_account", return_value=account), \
             patch.object(email_change_service.db, "claim_account_email_change") as claim, \
             patch.object(email_change_service._EXECUTOR, "submit") as submit:
            result = email_change_service.enqueue(29, "cloudflare_domain")

        self.assertFalse(result["accepted"])
        self.assertEqual(result["code"], "email_change_account_too_new")
        claim.assert_not_called()
        submit.assert_not_called()

    def test_protocol_uses_captured_begin_and_verify_paths(self):
        session = MagicMock()
        session.device_id = "device"
        session.navigator_language.return_value = "en-US"
        session.get_chatgpt_headers.return_value = {}
        response = MagicMock(status_code=200)
        response.json.return_value = {"success": True}
        session.post.return_value = response
        email_change_service._post(session, "/backend-api/accounts/change_email/begin", "token", {"email": "new@example.com"})
        email_change_service._post(session, "/backend-api/accounts/change_email/verify", "token", {"email": "new@example.com", "code": "123456"})
        self.assertEqual(session.post.call_args_list[0].args[0], "https://chatgpt.com/backend-api/accounts/change_email/begin")
        self.assertEqual(session.post.call_args_list[1].args[0], "https://chatgpt.com/backend-api/accounts/change_email/verify")

    def test_success_triggers_live_check_with_new_email(self):
        queued = {"accepted": True, "status": "queued"}
        with patch.object(email_change_service.db, "get_account", return_value={"proxy_used": "http://proxy.test:8080"}), \
             patch("core.live_check_service.enqueue_account_live_check", return_value=queued) as enqueue:
            result = email_change_service._enqueue_live_check_after_change(12, "new@example.com")
        self.assertTrue(result["accepted"])
        enqueue.assert_called_once_with(
            account_id=12, email="new@example.com", trigger="email_change_auto", proxy="http://proxy.test:8080",
        )

    def test_transport_error_switches_session_and_retries(self):
        first, second = MagicMock(), MagicMock()
        with patch.object(email_change_service, "_post", side_effect=[OSError("curl 35 reset"), {"success": True}]) as post, \
             patch.object(email_change_service, "_new_session", return_value=second) as new_session, \
             patch.object(email_change_service, "_append_log"), \
             patch.object(email_change_service.time, "sleep"):
            result, used_session = email_change_service._post_with_network_retry(
                first, account_id=9, path="/backend-api/accounts/change_email/begin",
                token="token", payload={"email": "new@example.com"},
            )
        self.assertTrue(result["success"])
        self.assertIs(used_session, second)
        self.assertEqual(post.call_count, 2)
        new_session.assert_called_once_with(9, None, email="")

    def test_recent_login_uses_protocol_reauth_and_reuses_session(self):
        session = MagicMock()
        session.proxy = "http://old-proxy"
        session.device_id = "test-device-id"
        with patch("core.account_liveness._warm_authenticated_session") as warm, \
             patch("core.account_liveness._login_via_reauth", return_value={
                 "accessToken": "fresh-token",
             }) as reauth_login, \
             patch.object(email_change_service, "_append_log"):
            used_session, token = email_change_service._refresh_recent_login(
                session,
                account_id=19,
                email="Old@Example.com",
                email_source="imap",
                access_token="stale-token",
            )
        self.assertEqual(token, "fresh-token")
        self.assertIs(used_session, session)
        warm.assert_called_once_with(session, "stale-token")
        reauth_login.assert_called_once()
        self.assertIs(reauth_login.call_args.args[0], session)
        self.assertEqual(reauth_login.call_args.kwargs["email"], "Old@Example.com")
        self.assertEqual(reauth_login.call_args.kwargs["email_source"], "imap")

    def test_recent_login_protocol_retries_on_transient_error(self):
        session = MagicMock()
        session.proxy = "http://old-proxy"
        with patch("core.account_liveness._warm_authenticated_session"), \
             patch("core.account_liveness._clear_optional_bootstrap_circuit") as clear_circuit, \
             patch("core.account_liveness._login_via_reauth", side_effect=[
                 RuntimeError("CF challenge 403"),
                 {"accessToken": "fresh-token-attempt-2"},
             ]) as reauth_login, \
             patch.object(email_change_service.time, "sleep") as mock_sleep, \
             patch.object(email_change_service, "_append_log"):
            used_session, token = email_change_service._refresh_recent_login(
                session,
                account_id=20,
                email="retry@example.com",
                email_source="outlook",
                access_token="stale-token",
            )
        self.assertEqual(token, "fresh-token-attempt-2")
        self.assertIs(used_session, session)
        self.assertEqual(reauth_login.call_count, 2)
        mock_sleep.assert_called_once_with(2)
        self.assertTrue(clear_circuit.called)

    def test_recent_login_protocol_dead_account_does_not_retry(self):
        from core.openai_auth import AccountUnusableError

        session = MagicMock()
        with patch("core.account_liveness._warm_authenticated_session"), \
             patch("core.account_liveness._login_via_reauth", side_effect=AccountUnusableError("account_deactivated")) as reauth_login, \
             patch.object(email_change_service, "_append_log"):
            with self.assertRaises(AccountUnusableError):
                email_change_service._refresh_recent_login(
                    session,
                    account_id=21,
                    email="banned@example.com",
                    email_source="remail",
                    access_token="stale-token",
                )
        self.assertEqual(reauth_login.call_count, 1)

    def test_recent_login_falls_back_to_antbrowser_on_protocol_failure(self):
        session = MagicMock()
        mock_new_session = MagicMock()
        with patch("core.account_liveness._warm_authenticated_session"), \
             patch("core.account_liveness._clear_optional_bootstrap_circuit"), \
             patch("core.account_liveness._login_via_reauth", side_effect=RuntimeError("CF 403")) as reauth_login, \
             patch("core.antbrowser_liveness.refresh_recent_login_browser", return_value={"accessToken": "browser-fresh-token"}) as ant_browser, \
             patch("core.email_change_service._new_session", return_value=mock_new_session), \
             patch.object(email_change_service.time, "sleep"), \
             patch.object(email_change_service, "_append_log"):
            res_session, res_token = email_change_service._refresh_recent_login(
                session,
                account_id=22,
                email="fallback@example.com",
                email_source="imap",
                access_token="stale-token",
            )
        self.assertEqual(reauth_login.call_count, 2)
        ant_browser.assert_called_once_with("fallback@example.com", email_source="imap", proxy=session.proxy, force_headless=True)
        self.assertEqual(res_token, "browser-fresh-token")

    def test_antbrowser_recent_login_returns_token_and_forwards_email_source(self):
        driver = MagicMock()
        opened = MagicMock(profile_id="profile-1", raw={"proxy": "http://effective-proxy"})
        captured = {}

        def fill(_driver, email, otp_provider, auth_url):
            captured["otp"] = otp_provider(email, after_ts=123.0)
            self.assertEqual(auth_url, "https://chatgpt.com/auth/login")

        with patch.object(antbrowser_liveness, "build_ant_driver", return_value=(driver, opened)), \
             patch.object(antbrowser_liveness, "_fill_email_and_otp", side_effect=fill), \
             patch.object(antbrowser_liveness, "wait_for_otp", return_value="654321") as wait_otp, \
             patch.object(antbrowser_liveness, "_fetch_chatgpt_session", return_value={"accessToken": "fresh-token"}), \
             patch.object(antbrowser_liveness, "cleanup_ant_profile") as cleanup:
            result = antbrowser_liveness.refresh_recent_login_browser(
                "old@example.com", email_source="remail", proxy="http://requested-proxy",
            )

        self.assertEqual(result["accessToken"], "fresh-token")
        self.assertEqual(result["_network_proxy"], "http://effective-proxy")
        self.assertEqual(captured["otp"], "654321")
        wait_otp.assert_called_once_with(
            "old@example.com",
            after_ts=123.0,
            max_wait=8,
            poll_interval=2,
            settle_seconds=0,
            email_source="remail",
            exclude_codes=None,
        )
        driver.quit.assert_called_once_with()
        cleanup.assert_called_once_with(opened)

    def test_headed_recent_login_waits_for_mfa_before_session(self):
        driver = MagicMock()
        opened = MagicMock(profile_id="headed-test", raw={"proxy": "http://test-proxy"})
        notices = []
        with patch.object(antbrowser_liveness, "build_ant_driver", return_value=(driver, opened)), \
             patch.object(antbrowser_liveness, "_fill_email_and_otp"), \
             patch.object(antbrowser_liveness, "_is_mfa_challenge_page", side_effect=[True, False]), \
             patch.object(antbrowser_liveness, "_fill_mfa_challenge_if_present", return_value=True) as fill_mfa, \
             patch.object(antbrowser_liveness, "_fetch_chatgpt_session", return_value={"accessToken": "headed-token"}) as fetch, \
             patch.object(antbrowser_liveness, "cleanup_ant_profile"):
            result = antbrowser_liveness.refresh_recent_login_browser(
                "test@example.com", force_headless=False, progress_callback=notices.append,
            )
        self.assertEqual(result["accessToken"], "headed-token")
        self.assertFalse(driver._manual_challenge_wait)
        fill_mfa.assert_called_once()
        fetch.assert_called_once()

    def test_antbrowser_recent_login_cleans_up_after_failure(self):
        driver = MagicMock()
        opened = MagicMock(profile_id="profile-2", raw={})
        with patch.object(antbrowser_liveness, "build_ant_driver", return_value=(driver, opened)), \
             patch.object(antbrowser_liveness, "_fill_email_and_otp", side_effect=RuntimeError("login failed")), \
             patch.object(antbrowser_liveness, "cleanup_ant_profile") as cleanup:
            with self.assertRaisesRegex(RuntimeError, "login failed"):
                antbrowser_liveness.refresh_recent_login_browser("old@example.com")

        driver.quit.assert_called_once_with()
        cleanup.assert_called_once_with(opened)

    def test_antbrowser_recent_login_recreates_instance_after_target_closed(self):
        first_driver, second_driver = MagicMock(), MagicMock()
        first_opened = MagicMock(profile_id="profile-closed", raw={"ephemeral": True})
        second_opened = MagicMock(profile_id="profile-ok", raw={"proxy": "http://proxy"})
        with patch.object(
            antbrowser_liveness, "build_ant_driver",
            side_effect=[(first_driver, first_opened), (second_driver, second_opened)],
        ) as build, patch.object(antbrowser_liveness, "_fill_email_and_otp"), \
             patch.object(
                 antbrowser_liveness, "_fetch_chatgpt_session",
                 side_effect=[RuntimeError("AntBrowser 页面上下文已关闭"), {"accessToken": "fresh-token"}],
             ), patch.object(antbrowser_liveness, "cleanup_ant_profile") as cleanup:
            result = antbrowser_liveness.refresh_recent_login_browser("old@example.com")

        self.assertEqual(result["accessToken"], "fresh-token")
        self.assertEqual(build.call_count, 2)
        first_driver.quit.assert_called_once_with()
        second_driver.quit.assert_called_once_with()
        self.assertEqual(cleanup.call_args_list[0].args, (first_opened,))
        self.assertEqual(cleanup.call_args_list[1].args, (second_opened,))

    def test_oauth_callback_waits_for_access_token_cookie(self):
        session = MagicMock()
        with patch("core.account_liveness.follow_oauth_callback") as follow, \
             patch("core.account_liveness.fetch_session", side_effect=[
                 RuntimeError("未拿到 accessToken，登录态可能未建立"),
                 {"accessToken": "fresh-token"},
             ]) as fetch, patch("core.account_liveness.time.sleep") as sleep:
            from core.account_liveness import _follow_continue_and_fetch

            result = _follow_continue_and_fetch(
                session,
                "https://auth.openai.com/authorize/continue?code=test",
                referer="https://auth.openai.com/email-verification",
            )

        self.assertEqual(result["accessToken"], "fresh-token")
        follow.assert_called_once()
        self.assertEqual(fetch.call_count, 2)
        sleep.assert_called_once_with(1)

    def test_oauth_callback_does_not_hide_non_session_errors(self):
        session = MagicMock()
        with patch("core.account_liveness.follow_oauth_callback"), \
             patch("core.account_liveness.fetch_session", side_effect=ValueError("bad json")), \
             patch("core.account_liveness.time.sleep") as sleep:
            from core.account_liveness import _follow_continue_and_fetch

            with self.assertRaisesRegex(ValueError, "bad json"):
                _follow_continue_and_fetch(
                    session,
                    "https://auth.openai.com/authorize/continue?code=test",
                    referer="https://auth.openai.com/email-verification",
                )

        sleep.assert_not_called()

    def test_post_change_live_check_reuses_current_session(self):
        session = MagicMock()
        session.proxy = "socks5://127.0.0.1:7897"
        session_info = {
            "accessToken": "new-token",
            "user": {"id": "user-1", "email": "new@example.com"},
            "account": {"planType": "free"},
        }
        with patch("core.chatgpt_auth.get_csrf_token", return_value="csrf") as csrf, \
             patch("core.chatgpt_auth.signin_openai", return_value="https://auth/authorize") as signin, \
             patch("core.openai_auth.follow_authorize") as follow, \
             patch("core.account_liveness._login_via_password_or_otp", return_value=session_info) as login, \
             patch("core.account_liveness._safe_fingerprint_for_account", return_value={"geo_country": "JP"}), \
             patch("core.account_liveness._safe_fingerprint_text_for_account", return_value="geo=JP"), \
             patch.object(email_change_service.db, "update_account_liveness", return_value=True) as update, \
             patch.object(email_change_service, "_append_log"):
            result = email_change_service._check_live_in_current_session(
                session,
                account_id=67,
                email="new@example.com",
                email_source="imap",
            )
        self.assertTrue(result["ok"])
        self.assertEqual(result["access_token"], "new-token")
        csrf.assert_called_once_with(session)
        signin.assert_called_once_with(session, "csrf", "new@example.com")
        follow.assert_called_once_with(session, "https://auth/authorize")
        self.assertIs(login.call_args.args[0], session)
        self.assertEqual(login.call_args.kwargs["email_source"], "imap")
        update.assert_called_once_with(67, result)

    def test_post_change_browser_login_persists_new_identity_token(self):
        session = MagicMock()
        session.proxy = "http://old-proxy"
        protocol_info = {
            "ok": True,
            "status": "live",
            "access_token": "new-identity-token",
            "proxy_used": "http://effective-proxy",
            "session": {"accessToken": "new-identity-token"},
        }
        with patch(
            "core.account_liveness.check_account_liveness",
            return_value=protocol_info,
        ) as check_liveness, patch.object(email_change_service.db, "update_account_liveness", return_value=True) as update, \
             patch.object(email_change_service, "_append_log"):
            result = email_change_service._check_live_after_change_browser(
                session,
                account_id=15,
                email="new@example.com",
                email_source="remail",
            )

        self.assertEqual(result["access_token"], "new-identity-token")
        self.assertEqual(result["proxy_used"], "http://effective-proxy")
        check_liveness.assert_called_once_with(
            "new@example.com", proxy="http://old-proxy", clear_log=False, email_source="remail",
        )
        update.assert_called_once_with(15, result)

    def test_post_change_protocol_failure_uses_ant_headless(self):
        session = MagicMock()
        session.proxy = "http://proxy.local:8080"
        with patch("core.account_liveness.check_account_liveness", return_value={"ok": False, "error": "HTTP 403"}), \
             patch("core.antbrowser_liveness.refresh_recent_login_browser", return_value={"accessToken": "new-token"}) as browser, \
             patch.object(email_change_service.db, "update_account_liveness", return_value=True), \
             patch.object(email_change_service, "_append_log"):
            result = email_change_service._check_live_after_change_protocol(
                session, account_id=15, email="new@example.com", email_source="remail",
            )
        self.assertEqual(result["access_token"], "new-token")
        browser.assert_called_once_with(
            "new@example.com", email_source="remail", proxy="http://proxy.local:8080", force_headless=True,
        )

    def test_begin_skips_reauth_when_existing_token_is_recent(self):
        session = MagicMock()
        with patch.object(
            email_change_service,
            "_post_with_network_retry",
            return_value=({"success": True}, session),
        ) as post, patch.object(email_change_service, "_refresh_recent_login") as refresh, \
             patch.object(email_change_service, "_append_log"):
            used_session, token, _, reauthenticated = (
                email_change_service._begin_change_with_optional_reauth(
                    session,
                    account_id=3,
                    current_email="old@example.com",
                    current_source="imap",
                    new_email="new@example.com",
                    access_token="recent-token",
                )
            )
        self.assertIs(used_session, session)
        self.assertEqual(token, "recent-token")
        self.assertFalse(reauthenticated)
        self.assertEqual(post.call_count, 1)
        refresh.assert_not_called()

    def test_begin_reauths_only_after_server_requires_it(self):
        session = MagicMock()
        error = RuntimeError(
            "/backend-api/accounts/change_email/begin 返回 401: "
            "{'code': 'reauth_required', 'message': 'Recent login required'}"
        )
        with patch.object(
            email_change_service,
            "_post_with_network_retry",
            side_effect=[error, ({"success": True}, session)],
        ) as post, patch.object(
            email_change_service, "_refresh_recent_login", return_value=(session, "fresh-token"),
        ) as refresh, patch.object(email_change_service, "_append_log"):
            _, token, _, reauthenticated = (
                email_change_service._begin_change_with_optional_reauth(
                    session,
                    account_id=4,
                    current_email="old@example.com",
                    current_source="imap",
                    new_email="new@example.com",
                    access_token="old-token",
                )
            )
        self.assertEqual(token, "fresh-token")
        self.assertTrue(reauthenticated)
        self.assertEqual(post.call_count, 2)
        refresh.assert_called_once_with(
            session,
            account_id=4,
            email="old@example.com",
            email_source="imap",
            access_token="old-token",
        )

    def test_network_retry_preserves_latest_session_on_reauth_required(self):
        first, retry = MagicMock(), MagicMock()
        reauth_error = RuntimeError(
            "/backend-api/accounts/change_email/begin 返回 401: "
            "{'code': 'reauth_required', 'message': 'Recent login required'}"
        )
        with patch.object(email_change_service, "_post", side_effect=[OSError("curl 35 reset"), reauth_error]), \
             patch.object(email_change_service, "_new_session", return_value=retry), \
             patch.object(email_change_service, "_append_log"), \
             patch.object(email_change_service.time, "sleep"):
            with self.assertRaises(RuntimeError) as raised:
                email_change_service._post_with_network_retry(
                    first, account_id=9, path="/backend-api/accounts/change_email/begin",
                    token="token", payload={"email": "new@example.com"},
                )
        self.assertIs(getattr(raised.exception, "_retry_session", None), retry)

    def test_begin_reauth_uses_session_from_network_retry(self):
        first, retry = MagicMock(), MagicMock()
        reauth_error = RuntimeError(
            "/backend-api/accounts/change_email/begin 返回 401: "
            "{'code': 'reauth_required', 'message': 'Recent login required'}"
        )
        reauth_error._retry_session = retry
        with patch.object(email_change_service, "_post_with_network_retry", side_effect=[reauth_error, ({"success": True}, retry)]), \
             patch.object(email_change_service, "_refresh_recent_login", return_value=(retry, "fresh-token")) as refresh, \
             patch.object(email_change_service, "_append_log"):
            used_session, token, _, reauthenticated = email_change_service._begin_change_with_optional_reauth(
                first,
                account_id=4,
                current_email="old@example.com",
                current_source="imap",
                new_email="new@example.com",
                access_token="old-token",
            )
        self.assertIs(used_session, retry)
        self.assertEqual(token, "fresh-token")
        self.assertTrue(reauthenticated)
        refresh.assert_called_once_with(
            retry,
            account_id=4,
            email="old@example.com",
            email_source="imap",
            access_token="old-token",
        )

    def test_bulk_api_accepts_selected_source(self):
        with tempfile.TemporaryDirectory() as td, patch.multiple(db, **self.storage(Path(td))):
            account_id = db.insert_account(email="old@example.com", access_token="token", email_source="outlook")
            client = create_app(auth_code="test-auth").test_client()
            with patch("core.email_change_service.enqueue", return_value={"accepted": True, "future": MagicMock()}):
                response = client.post("/api/accounts/change-email-bulk", json={"account_ids": [account_id], "source": "imap"}, headers={"X-Auth-Code": "test-auth"})
            self.assertEqual(response.status_code, 202)
            self.assertEqual(response.get_json()["started_count"], 1)

    def test_change_email_log_api(self):
        with tempfile.TemporaryDirectory() as td, patch.multiple(db, **self.storage(Path(td))):
            account_id = db.insert_account(email="old@example.com", access_token="token", email_source="outlook")
            log_file = Path(td) / "change.log"
            log_file.write_text("12:00:00 [INFO] 换绑任务已入队\n", encoding="utf-8")
            client = create_app(auth_code="test-auth").test_client()
            with patch("core.email_change_service.log_path", return_value=log_file), \
                 patch("core.email_change_service.is_running", return_value=False):
                response = client.get(
                    f"/api/accounts/{account_id}/change-email-log",
                    headers={"X-Auth-Code": "test-auth"},
                )
            self.assertEqual(response.status_code, 200)
            self.assertIn("换绑任务已入队", response.get_json()["log"])


if __name__ == "__main__":
    unittest.main()
