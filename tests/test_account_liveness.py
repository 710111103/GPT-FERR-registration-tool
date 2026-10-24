# -*- coding: utf-8 -*-
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import core.account_liveness as liveness
import core.live_check_service as live_service
from core.openai_auth import send_email_otp


class _DummyHttpSession:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class _DummyBrowserSession:
    created = []

    def __init__(self, proxy=None, **kwargs):
        self.proxy = proxy
        self.received_proxy = proxy
        self.device_id = "device-test"
        self.session = _DummyHttpSession()
        self.blocked_until = 0.0
        self.blocked_reason = ""
        self.created.append(self)
        self.kwargs = kwargs

    def fingerprint_summary(self):
        return {
            "proxy": self.proxy or "",
            "user_agent": "test-agent",
            "accept_language": "en-US",
            "timezone_iana": "UTC",
            "timezone_offset_minutes": 0,
            "screen_width": 1440,
            "screen_height": 900,
            "device_pixel_ratio": 2,
            "hardware_concurrency": 8,
            "device_memory": 8,
            "geo_country": "US",
            "geo_city": "Test",
        }

    def fingerprint_summary_text(self):
        return "test-fingerprint"

    def reset_circuit_breaker(self):
        self.blocked_until = 0.0
        self.blocked_reason = ""


class _DummyQueueSlot:
    def __init__(self):
        self.released = False

    def release(self):
        self.released = True


class AccountLivenessTests(unittest.TestCase):
    def setUp(self):
        _DummyBrowserSession.created = []

    def test_mfa_403_diagnostic_page_identifies_deactivated_account(self):
        session = MagicMock()
        session.get.return_value = SimpleNamespace(
            status_code=403,
            text="Auth login details\nerror_code: account_deactivated",
        )
        response = SimpleNamespace(status_code=403, text="Forbidden")
        with self.assertRaises(liveness.AccountUnusableError) as ctx:
            liveness._check_mfa_account_unusable(session, response, "factor")
        self.assertEqual(ctx.exception.error_code, "account_deactivated")
        session.get.assert_called_once()

    def test_mfa_403_without_diagnostic_is_not_assumed_dead(self):
        session = MagicMock()
        session.get.return_value = SimpleNamespace(status_code=403, text="challenge")
        liveness._check_mfa_account_unusable(
            session, SimpleNamespace(status_code=403, text="Forbidden"), "factor"
        )

    def test_dead_code_requires_explicit_remote_signal(self):
        self.assertEqual(liveness._confirmed_dead_code('{"error":{"code":"account_deactivated"}}'), "account_deactivated")
        self.assertEqual(liveness._confirmed_dead_code('Auth login details\nerror_code: account_deactivated'), "account_deactivated")
        self.assertEqual(liveness._confirmed_dead_code('https://auth.openai.com/error?error=account_deactivated', redirect=True), "account_deactivated")
        self.assertEqual(liveness._confirmed_dead_code('https://auth.openai.com/mfa?state=account_deactivated', redirect=True), "")
        self.assertEqual(liveness._confirmed_dead_code('Retry: previous account_deactivated report was stale'), "")
        self.assertEqual(liveness._confirmed_dead_code('HTTP 403 Cloudflare challenge'), "")
        self.assertEqual(liveness._confirmed_dead_code('{"error":{"code":"email_address_changed"}}'), "")

    def test_cloudflare_domain_login_waits_for_delayed_imap_index(self):
        session = _DummyBrowserSession(proxy="")
        with patch.object(liveness, "wait_for_otp", return_value="123456") as wait, \
             patch.object(liveness, "validate_email_otp", return_value={"continue_url": "next"}):
            result = liveness._validate_with_retry(
                session, "target@example.com", 100.0, email_source="cloudflare_domain"
            )

        self.assertEqual(result["continue_url"], "next")
        wait.assert_called_once_with(
            "target@example.com", after_ts=100.0, max_wait=90,
            email_source="cloudflare_domain",
        )

    def test_cloudflare_domain_reauth_waits_for_delayed_imap_index(self):
        session = _DummyBrowserSession(proxy="")
        with patch.object(liveness, "wait_for_otp", return_value="123456") as wait, \
             patch.object(liveness, "_validate_reauth_otp", return_value="next"), \
             patch.object(liveness, "human_delay"):
            result = liveness._validate_reauth_with_retry(
                session, "target@example.com", 100.0, email_source="cloudflare_domain"
            )

        self.assertEqual(result, "next")
        wait.assert_called_once_with(
            "target@example.com", after_ts=100.0, max_wait=90,
            email_source="cloudflare_domain",
        )

    def test_email_verification_landing_uses_otp_before_password(self):
        session = _DummyBrowserSession(proxy="")
        with patch.object(liveness, "_account_registration_password", return_value="saved-password") as password, \
             patch.object(liveness, "_password_verify") as verify_password, \
             patch.object(liveness, "send_email_otp") as send, \
             patch.object(liveness, "_login_via_email_otp", return_value={"accessToken": "fresh"}) as login_otp, \
             patch.object(liveness.time, "time", return_value=123.0):
            result = liveness._login_via_password_or_otp(
                session,
                "user@example.com",
                100.0,
                email_source="remail",
                landing_url="https://auth.openai.com/email-verification",
            )

        self.assertEqual(result["accessToken"], "fresh")
        send.assert_called_once_with(session)
        login_otp.assert_called_once_with(
            session, "user@example.com", 123.0, email_source="remail",
        )
        password.assert_not_called()
        verify_password.assert_not_called()

    def test_missing_verified_password_sends_otp_before_waiting(self):
        session = _DummyBrowserSession(proxy="")
        with patch.object(liveness, "_account_registration_password", return_value=""), \
             patch.object(liveness, "send_email_otp") as send, \
             patch.object(liveness, "_login_via_email_otp", return_value={"accessToken": "fresh"}) as login_otp, \
             patch.object(liveness.time, "time", return_value=456.0):
            result = liveness._login_via_password_or_otp(
                session,
                "user@example.com",
                100.0,
                email_source="generic_api",
                landing_url="https://auth.openai.com/log-in/password",
            )

        self.assertEqual(result["accessToken"], "fresh")
        send.assert_called_once_with(session)
        login_otp.assert_called_once_with(
            session, "user@example.com", 456.0, email_source="generic_api",
        )

    def test_incorrect_saved_password_falls_back_to_fresh_email_otp(self):
        session = _DummyBrowserSession(proxy="")
        with patch.object(liveness, "_account_registration_password", return_value="stale-password"), \
             patch.object(liveness, "_password_verify", side_effect=RuntimeError("密码错误(HTTP 401: Incorrect email address or password)")), \
             patch.object(liveness, "send_email_otp") as send, \
             patch.object(liveness, "_login_via_email_otp", return_value={"accessToken": "fresh"}) as login_otp, \
             patch.object(liveness.time, "time", return_value=789.0):
            result = liveness._login_via_password_or_otp(
                session,
                "user@example.com",
                100.0,
                email_source="generic_api",
                landing_url="https://auth.openai.com/log-in/password",
            )

        self.assertEqual(result["accessToken"], "fresh")
        send.assert_called_once_with(session)
        login_otp.assert_called_once_with(
            session, "user@example.com", 789.0, email_source="generic_api",
        )

    def test_email_otp_about_you_completes_profile_and_fetches_token(self):
        session = _DummyBrowserSession(proxy="")
        validate_result = {
            "continue_url": "https://auth.openai.com/about-you",
            "page": {"type": "about_you"},
        }
        with patch.object(liveness, "_validate_with_retry", return_value=validate_result), \
             patch.object(liveness, "_complete_about_you_and_fetch", return_value={"accessToken": "fresh"}) as complete:
            result = liveness._login_via_email_otp(
                session, "user@example.com", 100.0, email_source="remail"
            )

        self.assertEqual(result["accessToken"], "fresh")
        complete.assert_called_once_with(
            session, "user@example.com", "https://auth.openai.com/about-you"
        )

    def test_password_about_you_completes_profile_and_fetches_token(self):
        session = _DummyBrowserSession(proxy="")
        password_result = {
            "continue_url": "https://auth.openai.com/about-you",
            "page": {"type": "about_you"},
        }
        with patch.object(liveness, "_account_registration_password", return_value="saved-password"), \
             patch.object(liveness, "_password_verify", return_value=password_result), \
             patch.object(liveness, "_complete_about_you_and_fetch", return_value={"accessToken": "fresh"}) as complete, \
             patch("core.db.save_registration_password_checkpoint") as checkpoint:
            result = liveness._login_via_password_or_otp(
                session, "user@example.com", 100.0, email_source="remail"
            )

        self.assertEqual(result["accessToken"], "fresh")
        checkpoint.assert_called_once_with(
            "user@example.com", "saved-password", verified=True,
            stage="liveness_login_verified", create_missing=False,
        )
        complete.assert_called_once_with(
            session, "user@example.com", "https://auth.openai.com/about-you"
        )

    def test_complete_about_you_submits_profile_and_follows_callback(self):
        session = _DummyBrowserSession(proxy="")
        with patch("core.name_samples.random_display_name", return_value="Alex Morgan"), \
             patch("core.profile_utils.generate_random_birthday", return_value="1995-04-18"), \
             patch("core.openai_auth.navigate_about_you") as navigate, \
             patch("core.openai_auth.request_sentinel_token", return_value={"token": "sentinel"}) as request_token, \
             patch("core.openai_auth.build_sentinel_header", return_value=("sentinel-header", "so-header")) as build, \
             patch("core.openai_auth.create_account", return_value={"continue_url": "https://chatgpt.com/api/auth/callback/openai?code=ok"}) as create, \
             patch.object(liveness, "_follow_continue_and_fetch", return_value={"accessToken": "fresh"}) as follow:
            result = liveness._complete_about_you_and_fetch(
                session, "user@example.com", "https://auth.openai.com/about-you"
            )

        self.assertEqual(result["accessToken"], "fresh")
        navigate.assert_called_once_with(session, "https://auth.openai.com/about-you")
        request_token.assert_called_once_with(session, "oauth_create_account")
        build.assert_called_once_with(session, {"token": "sentinel"}, "oauth_create_account")
        create.assert_called_once_with(
            session, "Alex Morgan", "1995-04-18", "sentinel-header", "so-header"
        )
        follow.assert_called_once_with(
            session,
            "https://chatgpt.com/api/auth/callback/openai?code=ok",
            referer="https://auth.openai.com/about-you",
        )

    def test_saved_web_session_refresh_verifies_identity_and_token(self):
        import requests
        browser = MagicMock()
        browser.session.cookies = requests.cookies.RequestsCookieJar()
        stored = "x" * 6200
        with patch.object(liveness.db, "get_account_by_email", return_value={
            "extra_json": {"session_token": stored}, "user_id": "user-1",
        }), patch.object(liveness, "fetch_session", return_value={
            "accessToken": "fresh-at", "user": {"email": "user@example.com", "id": "user-1"},
        }) as fetch, patch.object(liveness, "probe_access_token_liveness", return_value={
            "valid": True, "status_code": 200, "user_id": "user-1",
        }):
            result = liveness._try_saved_web_session_refresh(browser, "user@example.com")
            self.assertEqual(result["accessToken"], "fresh-at")
            # Cookie is available during the session request but removed after it.
            self.assertEqual(list(browser.session.cookies), [])
        fetch.assert_called_once_with(browser)

    def test_saved_web_session_refresh_rejects_mismatch_and_challenge(self):
        import requests
        browser = MagicMock()
        browser.session.cookies = requests.cookies.RequestsCookieJar()
        account = {"extra_json": {"session_token": "secret"}, "user_id": "user-1"}
        with patch.object(liveness.db, "get_account_by_email", return_value=account), patch.object(
            liveness, "fetch_session", return_value={
                "accessToken": "wrong", "user": {"email": "other@example.com"},
            }), patch.object(liveness, "probe_access_token_liveness") as probe:
            self.assertIsNone(liveness._try_saved_web_session_refresh(browser, "user@example.com"))
            probe.assert_not_called()
            self.assertEqual(list(browser.session.cookies), [])
        with patch.object(liveness.db, "get_account_by_email", return_value=account), patch.object(
            liveness, "fetch_session", side_effect=RuntimeError("HTTP 403 challenge")):
            self.assertIsNone(liveness._try_saved_web_session_refresh(browser, "user@example.com"))
            self.assertEqual(list(browser.session.cookies), [])

    def test_missing_access_token_after_callback_is_retryable_session_error(self):
        self.assertTrue(liveness._is_retryable_network_error(
            RuntimeError("未拿到 accessToken，登录态可能未建立")
        ))

    def test_preflight_preserves_explicit_direct_route_and_skips_providers(self):
        with patch.object(liveness, "BrowserSession", _DummyBrowserSession), \
             patch.object(liveness, "_warm_login_fingerprint_context"), \
             patch.object(liveness, "get_csrf_token", return_value="csrf"), \
             patch.object(liveness, "signin_openai", return_value="https://auth.example/authorize"):
            session, authorize_url = liveness._network_preflight_with_retry(
                "user@example.com", "", max_attempts=1
            )

        self.assertEqual(session.proxy, "")
        self.assertEqual(authorize_url, "https://auth.example/authorize")
        self.assertTrue(
            session.kwargs["fingerprint_seed"].startswith("live-check:user@example.com:")
        )

    def test_preflight_403_closes_session_for_outer_identity_rotation(self):
        with patch.object(liveness, "BrowserSession", _DummyBrowserSession), \
             patch.object(liveness, "_warm_login_fingerprint_context"), \
             patch.object(liveness, "get_csrf_token", side_effect=RuntimeError("HTTP Error 403")), \
             patch.object(liveness, "signin_openai", return_value="authorize"), \
             patch.object(liveness.time, "sleep") as sleep:
            with self.assertRaisesRegex(RuntimeError, "403"):
                liveness._network_preflight_with_retry(
                    "user@example.com", None, max_attempts=2
                )

        self.assertEqual(len(_DummyBrowserSession.created), 1)
        self.assertTrue(_DummyBrowserSession.created[0].session.closed)
        self.assertIsNone(_DummyBrowserSession.created[0].received_proxy)
        sleep.assert_not_called()

    def test_preflight_challenge_does_not_enter_backup_login(self):
        blocked = RuntimeError("HTTP Error 403")
        blocked.response = SimpleNamespace(
            status_code=403, headers={"CF-Mitigated": "challenge"}, text="challenge",
        )
        with patch.object(liveness, "BrowserSession", _DummyBrowserSession), \
             patch.object(liveness, "_warm_login_fingerprint_context"), \
             patch.object(liveness, "get_csrf_token", side_effect=blocked), \
             patch.object(liveness, "signin_openai") as signin, \
             patch.object(liveness.time, "sleep") as sleep:
            with self.assertRaises(liveness.AuthChallengeRequiredError):
                liveness._network_preflight_with_retry("user@example.com", None)
        self.assertEqual(len(_DummyBrowserSession.created), 1)
        self.assertTrue(_DummyBrowserSession.created[0].session.closed)
        signin.assert_not_called()
        sleep.assert_not_called()

    def test_fingerprint_identity_is_pinned_when_session_is_recreated_in_one_attempt(self):
        state = {}
        first = MagicMock()
        first.browser_profile = {
            "navigator_language": "ja-JP",
            "timezone_iana": "Asia/Tokyo",
            "screen_width": 1512,
        }
        second = MagicMock()
        second.browser_profile = dict(first.browser_profile)
        with patch.object(liveness, "BrowserSession", side_effect=[first, second]) as factory:
            self.assertIs(
                liveness._new_fingerprint_pinned_session(
                    "user@example.com", "socks5://proxy:1080", state,
                ),
                first,
            )
            self.assertIs(
                liveness._new_fingerprint_pinned_session(
                    "user@example.com", "", state,
                ),
                second,
            )

        first_kwargs = factory.call_args_list[0].kwargs
        second_kwargs = factory.call_args_list[1].kwargs
        self.assertTrue(first_kwargs["detect_exit_geo"])
        self.assertIsNone(first_kwargs["browser_profile"])
        self.assertFalse(second_kwargs["detect_exit_geo"])
        self.assertEqual(second_kwargs["browser_profile"]["navigator_language"], "ja-JP")
        self.assertEqual(second_kwargs["browser_profile"]["timezone_iana"], "Asia/Tokyo")
        self.assertEqual(first_kwargs["fingerprint_seed"], second_kwargs["fingerprint_seed"])
        self.assertTrue(str(first_kwargs["fingerprint_seed"]).startswith("live-check:user@example.com:"))

    def test_reauth_otp_dead_account_error_is_not_retried(self):
        response = SimpleNamespace(
            status_code=403,
            text='{"error":{"code":"account_deactivated"}}',
        )
        error = RuntimeError("HTTP Error 403")
        error.response = response
        session = _DummyBrowserSession(proxy="proxy")

        with patch.object(liveness, "_validate_reauth_otp", side_effect=error), \
             patch.object(liveness, "wait_for_otp", return_value="123456"):
            with self.assertRaises(liveness.AccountUnusableError) as ctx:
                liveness._validate_reauth_with_retry(session, "user@example.com", 1.0)

        self.assertEqual(ctx.exception.error_code, "account_deactivated")

    def test_reauth_explicitly_sends_fresh_otp_before_waiting(self):
        session = _DummyBrowserSession(proxy="")
        with patch.object(liveness, "_trigger_reauth_with_retry", return_value="authorize"), \
             patch.object(liveness, "_follow_reauth_with_retry", return_value="verified"), \
             patch.object(liveness, "send_email_otp") as send, \
             patch.object(liveness, "_validate_reauth_with_retry", return_value="continue") as validate, \
             patch.object(liveness, "_follow_continue_and_fetch", return_value={"accessToken": "fresh"}), \
             patch.object(liveness, "human_delay"), \
             patch.object(liveness.time, "time", return_value=200.0):
            result = liveness._login_via_reauth(
                session,
                "user@example.com",
                100.0,
                email_source="remail",
            )

        self.assertEqual(result["accessToken"], "fresh")
        send.assert_called_once_with(session)
        validate.assert_called_once_with(
            session,
            "user@example.com",
            200.0,
            email_source="remail",
            exclude_codes=set(),
        )

    def test_reauth_uses_totp_when_authorize_enters_mfa_challenge(self):
        session = _DummyBrowserSession(proxy="")
        factor_id = "factor-123"
        with patch.object(liveness, "_trigger_reauth_with_retry", return_value="authorize"), \
             patch.object(liveness, "_follow_reauth_with_retry", return_value=f"https://auth.openai.com/mfa-challenge/{factor_id}"), \
             patch.object(liveness, "_account_totp_secret", return_value="SECRET"), \
             patch.object(liveness, "_account_totp_code", return_value="123456"), \
             patch.object(liveness, "_mfa_issue_challenge") as issue, \
             patch.object(liveness, "_mfa_verify", return_value={"continue_url": "https://chatgpt.com/callback"}) as verify, \
             patch.object(liveness, "_follow_continue_and_fetch", return_value={"accessToken": "fresh"}) as follow, \
             patch.object(liveness, "send_email_otp") as send, \
             patch.object(liveness, "human_delay"):
            result = liveness._login_via_reauth(
                session,
                "user@example.com",
                100.0,
                email_source="remail",
            )

        self.assertEqual(result["accessToken"], "fresh")
        issue.assert_called_once_with(session, factor_id)
        verify.assert_called_once_with(session, factor_id, "123456")
        follow.assert_called_once_with(
            session,
            "https://chatgpt.com/callback",
            referer=f"https://auth.openai.com/mfa-challenge/{factor_id}",
        )
        send.assert_not_called()

    def test_send_email_otp_uses_fetch_headers(self):
        session = MagicMock()
        session.get_auth_headers.return_value = {
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
        }
        response = MagicMock(status_code=200, text="")
        session.get.return_value = response

        send_email_otp(session)

        session.get_auth_headers.assert_called_once_with(
            referer="https://auth.openai.com/email-verification"
        )
        session.get.assert_called_once()
        kwargs = session.get.call_args.kwargs
        self.assertEqual(kwargs["headers"]["sec-fetch-mode"], "cors")
        self.assertEqual(kwargs["headers"]["sec-fetch-dest"], "empty")
        self.assertFalse(kwargs["allow_redirects"])

    def test_send_email_otp_reports_403_stage_and_body(self):
        session = MagicMock()
        session.get_auth_headers.return_value = {}
        session.get.return_value = SimpleNamespace(
            status_code=403,
            text="blocked by edge",
            url="https://auth.openai.com/api/accounts/email-otp/send",
        )

        with self.assertRaisesRegex(RuntimeError, "原邮箱 OTP 发送返回 403: blocked by edge"):
            send_email_otp(session)

    def test_existing_access_token_uses_reauth_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = _DummyBrowserSession(proxy="")
            with patch.object(liveness, "_LOG_DIR", Path(tmp)), \
                 patch.object(liveness, "_stored_access_token", return_value="old-token"), \
                 patch.object(liveness, "BrowserSession", return_value=session), \
                 patch.object(liveness, "_warm_authenticated_session") as warm, \
                 patch.object(liveness, "human_delay"), \
                 patch.object(liveness, "_login_via_reauth", return_value={
                     "accessToken": "new-token",
                     "user": {"id": "user-1"},
                     "account": {"planType": "free"},
                 }) as reauth:
                result = liveness.check_account_liveness("user@example.com", proxy="")

        self.assertTrue(result["ok"])
        self.assertEqual(result["access_token"], "new-token")
        warm.assert_called_once_with(session, "old-token")
        reauth.assert_called_once()
        self.assertTrue(session.session.closed)

    def test_service_403_keeps_proxy_and_never_uses_direct_connection(self):
        slot = _DummyQueueSlot()
        failed = {"ok": False, "status": "failed", "error": "HTTP Error 403: blocked"}
        success = {"ok": True, "status": "live", "access_token": "new-token"}
        with patch.object(live_service, "_QUEUE_SLOTS", slot), \
             patch.object(live_service.db, "mark_account_live_check_running", return_value=True), \
             patch.object(live_service.db, "get_account", return_value={"email_source": "remail"}), \
             patch.object(live_service.db, "update_account_liveness"), \
             patch("core.plan_check_service.enqueue_account_plan_check", return_value={"accepted": True}), \
             patch.object(live_service, "_append_log"), \
             patch.object(live_service, "resolve_plan_check_route", return_value={
                 "proxy": "socks5://proxy.example:1080",
                 "network_route": "proxy",
                 "proxy_mode": "auto",
             }), \
             patch.object(live_service, "check_account_liveness", side_effect=[failed, success]) as check:
            result = live_service._run_live_check(
                account_id=1,
                email="user@example.com",
                proxy=None,
                trigger="manual",
            )

        self.assertFalse(result["ok"])
        self.assertEqual(check.call_count, 1)
        self.assertEqual(check.call_args_list[0].kwargs["proxy"], "socks5://proxy.example:1080")
        self.assertEqual(check.call_args_list[0].kwargs["email_source"], "remail")
        self.assertTrue(slot.released)

    def test_service_token_expired_proxy_failure_never_falls_back_to_direct(self):
        slot = _DummyQueueSlot()
        failed = {
            "ok": False,
            "status": "failed",
            "token_expired": True,
            "error": "AT已过期/失效 (token_expired)；重新登录被验证页拦截 (HTTP 403)",
        }
        success = {"ok": True, "status": "live", "access_token": "fresh-direct-token"}
        with patch.object(live_service, "_QUEUE_SLOTS", slot), \
             patch.object(live_service.db, "mark_account_live_check_running", return_value=True), \
             patch.object(live_service.db, "get_account", return_value={"email_source": "remail"}), \
             patch.object(live_service.db, "update_account_liveness"), \
             patch.object(live_service, "_append_log") as append_log, \
             patch("core.plan_check_service.enqueue_account_plan_check", return_value={"accepted": True}), \
             patch.object(live_service, "resolve_plan_check_route", return_value={
                 "proxy": "socks5://proxy.example:1080",
                 "network_route": "proxy",
                 "proxy_mode": "auto",
             }), \
             patch.object(live_service, "check_account_liveness", side_effect=[failed, success]) as check, \
             patch("core.antbrowser_liveness.refresh_recent_login_browser", return_value={
                 "accessToken": "fresh-browser-token", "user": {"email": "user@example.com"},
             }) as browser, \
             patch.object(live_service, "_verify_browser_token", return_value={"valid": True, "status_code": 200}):
            result = live_service._run_live_check(
                account_id=69, email="user@example.com", proxy=None, trigger="manual",
            )

        self.assertTrue(result["ok"])
        self.assertEqual(check.call_count, 1)
        self.assertEqual(check.call_args_list[0].kwargs["proxy"], "socks5://proxy.example:1080")
        self.assertTrue(browser.call_args.kwargs["force_headless"])
        self.assertFalse(any(
            "直连协议兜底" in str(call.args[1])
            for call in append_log.call_args_list if len(call.args) > 1
        ))
        self.assertTrue(slot.released)

    def test_ant_headless_refresh_persists_new_token_without_protocol_login(self):
        slot = _DummyQueueSlot()
        stored = []
        with patch.object(live_service, "_QUEUE_SLOTS", slot), \
             patch.object(live_service.db, "mark_account_live_check_running", return_value=True), \
             patch.object(live_service.db, "get_account", return_value={"email_source": "remail"}), \
             patch.object(live_service.db, "update_account_liveness", side_effect=lambda aid, result: stored.append(result.copy()) or True), \
             patch.object(live_service, "_append_log"), \
             patch.object(live_service, "resolve_plan_check_route", return_value={"proxy": "socks5://proxy.example:1080", "network_route": "proxy"}), \
             patch.object(live_service, "check_account_liveness") as protocol, \
             patch("core.antbrowser_liveness.refresh_recent_login_browser", return_value={"accessToken": "headed-new-token", "user": {"email": "user@example.com"}}) as browser, \
             patch.object(live_service, "_verify_browser_token", return_value={"valid": True, "status_code": 200}) as verify:
            result = live_service._run_live_check(
                account_id=2, email="user@example.com", proxy=None, trigger="manual_ant_headless_refresh",
            )
        self.assertTrue(result["ok"])
        self.assertEqual(stored[0]["access_token"], "headed-new-token")
        self.assertFalse(stored[0]["token_expired"])
        self.assertTrue(browser.call_args.kwargs["force_headless"])
        verify.assert_called_once()
        protocol.assert_not_called()
        self.assertTrue(slot.released)

    def test_ant_headless_refresh_rejected_token_does_not_write_at(self):
        slot = _DummyQueueSlot()
        stored = []
        with patch.object(live_service, "_QUEUE_SLOTS", slot), \
             patch.object(live_service.db, "mark_account_live_check_running", return_value=True), \
             patch.object(live_service.db, "get_account", return_value={}), \
             patch.object(live_service.db, "update_account_liveness", side_effect=lambda aid, result: stored.append(result.copy()) or True), \
             patch.object(live_service, "_append_log"), \
             patch.object(live_service, "resolve_plan_check_route", return_value={"proxy": "socks5://proxy.example:1080", "network_route": "proxy"}), \
             patch("core.antbrowser_liveness.refresh_recent_login_browser", return_value={"accessToken": "unverified", "user": {"email": "user@example.com"}}), \
             patch.object(live_service, "_verify_browser_token", side_effect=RuntimeError("新 AT 独立鉴权未通过，旧 AT 保持不变：HTTP 403")):
            result = live_service._run_live_check(account_id=2, email="user@example.com", proxy=None, trigger="manual_ant_headless_refresh")
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "blocked")
        self.assertNotIn("access_token", stored[0])
        self.assertTrue(slot.released)

    def test_ant_headless_refresh_failure_preserves_existing_token(self):
        slot = _DummyQueueSlot()
        stored = []
        with patch.object(live_service, "_QUEUE_SLOTS", slot), \
             patch.object(live_service.db, "mark_account_live_check_running", return_value=True), \
             patch.object(live_service.db, "get_account", return_value={}), \
             patch.object(live_service.db, "update_account_liveness", side_effect=lambda aid, result: stored.append(result.copy()) or True), \
             patch.object(live_service, "_append_log"), \
             patch.object(live_service, "resolve_plan_check_route", return_value={"proxy": "socks5://proxy.example:1080", "network_route": "proxy"}), \
             patch("core.antbrowser_liveness.refresh_recent_login_browser", side_effect=RuntimeError("验证页未通过")):
            result = live_service._run_live_check(
                account_id=2, email="user@example.com", proxy=None, trigger="manual_ant_headless_refresh",
            )
        self.assertFalse(result["ok"])
        self.assertNotIn("access_token", stored[0])
        self.assertNotIn("token_expired", stored[0])
        self.assertTrue(slot.released)

    def test_service_missing_proxy_fails_before_network(self):
        slot = _DummyQueueSlot()
        with patch.object(live_service, "_QUEUE_SLOTS", slot), \
             patch.object(live_service.db, "mark_account_live_check_running", return_value=True), \
             patch.object(live_service.db, "get_account", return_value={}), \
             patch.object(live_service.db, "update_account_liveness"), \
             patch.object(live_service, "_append_log"), \
             patch.object(live_service, "resolve_plan_check_route", return_value={
                 "proxy": "", "network_route": "direct_fallback", "proxy_mode": "auto",
             }), \
             patch.object(live_service, "check_account_liveness") as check:
            result = live_service._run_live_check(
                account_id=2, email="user@example.com", proxy=None, trigger="manual",
            )
        self.assertFalse(result["ok"])
        self.assertIn("需要代理", result["error"])
        check.assert_not_called()
        self.assertTrue(slot.released)

    def test_probe_valid_access_token_marks_live_instantly(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = _DummyBrowserSession(proxy="")
            probe_success = {
                "valid": True,
                "token_expired": False,
                "status_code": 200,
                "user_id": "user-valid-1",
                "plan_type": "free",
                "data": {"plan_type": "free"},
                "error": None,
            }
            with patch.object(liveness, "_LOG_DIR", Path(tmp)), \
                 patch.object(liveness, "_stored_access_token", return_value="existing-valid-token"), \
                 patch.object(liveness, "BrowserSession", return_value=session), \
                 patch.object(liveness, "probe_access_token_liveness", return_value=probe_success), \
                 patch.object(liveness, "_login_via_reauth") as reauth:
                result = liveness.check_account_liveness("valid@example.com", proxy="")

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "live")
        self.assertFalse(result["token_expired"])
        self.assertEqual(result["access_token"], "existing-valid-token")
        self.assertEqual(result["session"]["user"]["id"], "user-valid-1")
        # 探测成功时无需重新走漫长的邮箱 OTP 重认证
        reauth.assert_not_called()

    def test_fallback_reports_latest_callback_failure_not_earlier_409(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = _DummyBrowserSession(proxy="")
            with patch.object(liveness, "_LOG_DIR", Path(tmp)), \
                 patch.object(liveness, "_stored_access_token", return_value="expired-token"), \
                 patch.object(liveness, "BrowserSession", return_value=session), \
                 patch.object(liveness, "probe_access_token_liveness", return_value={
                     "valid": False, "token_expired": True, "status_code": 401,
                 }), \
                 patch.object(liveness, "_account_registration_password", return_value="present"), \
                 patch.object(liveness, "_network_preflight_with_retry", return_value=(session, "authorize")), \
                 patch.object(liveness, "follow_authorize", return_value="https://auth.openai.com/log-in/password"), \
                 patch.object(liveness, "_login_via_password_or_otp", side_effect=[
                     RuntimeError("HTTP Error 409"), RuntimeError("HTTP Error 403")
                 ]) as login:
                result = liveness.check_account_liveness("test@example.com", proxy="")
        self.assertEqual(login.call_count, 2)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["token_expired"])
        self.assertIn("HTTP 403", result["error"])
        self.assertNotIn("HTTP 409", result["error"])

    def test_probe_expired_access_token_and_failed_reauth_marks_token_expired(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = _DummyBrowserSession(proxy="")
            probe_expired = {
                "valid": False,
                "token_expired": True,
                "status_code": 401,
                "error": "token_expired: Provided authentication token is expired.",
            }
            with patch.object(liveness, "_LOG_DIR", Path(tmp)), \
                 patch.object(liveness, "_stored_access_token", return_value="old-expired-token"), \
                 patch.object(liveness, "BrowserSession", return_value=session), \
                 patch.object(liveness, "probe_access_token_liveness", return_value=probe_expired), \
                 patch.object(liveness, "_account_registration_password", return_value=None), \
                 patch.object(liveness, "_network_preflight_with_retry", side_effect=RuntimeError("OTP 超时未能取码")):
                result = liveness.check_account_liveness("expired@example.com", proxy="")

        self.assertFalse(result["ok"])
        self.assertTrue(result["token_expired"])
        self.assertIn("token_expired", result["error"])

    def test_expired_at_preserves_login_challenge_cause(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = _DummyBrowserSession(proxy="")
            blocked = RuntimeError("HTTP Error 403")
            blocked.response = SimpleNamespace(status_code=403, headers={"cf-mitigated": "challenge"})
            with patch.object(liveness, "_LOG_DIR", Path(tmp)), \
                 patch.object(liveness, "_stored_access_token", return_value="old-expired-token"), \
                 patch.object(liveness, "BrowserSession", return_value=session), \
                 patch.object(liveness, "probe_access_token_liveness", return_value={"valid": False, "token_expired": True}), \
                 patch.object(liveness, "_account_registration_password", return_value=None), \
                 patch.object(liveness, "_network_preflight_with_retry", side_effect=blocked):
                result = liveness.check_account_liveness("blocked@example.com", proxy="")
        self.assertFalse(result["ok"])
        self.assertTrue(result["token_expired"])
        self.assertIn("HTTP 403", result["error"])
        self.assertIn("验证页", result["error"])

    def test_liveness_failure_identifies_authorize_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = _DummyBrowserSession(proxy="")
            with patch.object(liveness, "_LOG_DIR", Path(tmp)), \
                 patch.object(liveness, "_stored_access_token", return_value=""), \
                 patch.object(liveness, "BrowserSession", return_value=session), \
                 patch.object(liveness, "_network_preflight_with_retry", return_value=(session, "authorize")), \
                 patch.object(liveness, "follow_authorize", side_effect=RuntimeError("HTTP Error 403")):
                result = liveness.check_account_liveness(
                    "user@example.com", proxy="", password_override="candidate",
                    force_password_login=True, skip_existing_token_probe=True,
                )
        self.assertFalse(result["ok"])
        self.assertEqual(result["failure_stage"], "authorize")
        self.assertIn("[authorize]", result["error"])

    def test_challenge_during_password_authorize_skips_backup_login(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = _DummyBrowserSession(proxy="")
            response = SimpleNamespace(status_code=403, headers={"cf-mitigated": "challenge"}, text="challenge")
            challenge = liveness.AuthChallengeRequiredError(response)
            with patch.object(liveness, "_LOG_DIR", Path(tmp)), \
                 patch.object(liveness, "_stored_access_token", return_value="expired-token"), \
                 patch.object(liveness, "_account_registration_password", return_value="stored-password"), \
                 patch.object(liveness, "_new_fingerprint_pinned_session", return_value=session), \
                 patch.object(liveness, "probe_access_token_liveness", return_value={"valid": False, "token_expired": True}), \
                 patch.object(liveness, "_network_preflight_with_retry", return_value=(session, "authorize")) as preflight, \
                 patch.object(liveness, "follow_authorize", side_effect=challenge):
                result = liveness.check_account_liveness("user@example.com", proxy="")
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["token_expired"])
        self.assertIn("验证页", result["error"])
        self.assertEqual(preflight.call_count, 1)

    def test_force_password_liveness_skips_old_token_and_uses_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = _DummyBrowserSession(proxy="")
            login_result = {
                "accessToken": "new-token",
                "user": {"id": "user-1", "email": "user@example.com"},
                "account": {"planType": "free"},
                "password_accepted": True,
                "authentication_method": "password",
            }
            with patch.object(liveness, "_LOG_DIR", Path(tmp)), \
                 patch.object(liveness, "_stored_access_token", return_value="old-token"), \
                 patch.object(liveness, "_account_registration_password", return_value="old-password"), \
                 patch.object(liveness, "_new_fingerprint_pinned_session", return_value=session), \
                 patch.object(liveness, "probe_access_token_liveness") as probe, \
                 patch.object(liveness, "_network_preflight_with_retry", return_value=(session, "authorize")), \
                 patch.object(liveness, "follow_authorize", return_value="https://auth.openai.com/log-in/password"), \
                 patch.object(liveness, "_login_via_password_or_otp", return_value=login_result) as login:
                probe.return_value = {"valid": True, "status_code": 200, "user_id": "user-1"}
                result = liveness.check_account_liveness(
                    "user@example.com", proxy="", password_override="new-password",
                    force_password_login=True, skip_existing_token_probe=True,
                )

        self.assertTrue(result["ok"])
        self.assertTrue(result["password_accepted"])
        self.assertEqual(result["authentication_method"], "password")
        probe.assert_called_once_with(session, "new-token")
        self.assertEqual(login.call_args.kwargs["password_override"], "new-password")
        self.assertTrue(login.call_args.kwargs["force_password_login"])

    def test_force_password_login_does_not_fallback_to_email_otp(self):
        session = _DummyBrowserSession(proxy="")
        with patch.object(liveness, "_password_verify", side_effect=RuntimeError("密码错误(HTTP 401: Incorrect email address or password)")), \
             patch.object(liveness, "send_email_otp") as send_otp:
            with self.assertRaisesRegex(RuntimeError, "密码错误"):
                liveness._login_via_password_or_otp(
                    session, "user@example.com", 0,
                    landing_url="https://auth.openai.com/log-in/password",
                    password_override="wrong-password",
                    force_password_login=True,
                )
        send_otp.assert_not_called()


if __name__ == "__main__":
    unittest.main()
