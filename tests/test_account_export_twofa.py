# -*- coding: utf-8 -*-
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import core.account_export as account_export


class _CircuitSession:
    def __init__(self):
        self.blocked_until = 0.0
        self.blocked_reason = ""
        self.reset_count = 0

    def reset_circuit_breaker(self):
        self.reset_count += 1
        self.blocked_until = 0.0
        self.blocked_reason = ""


class AccountExportTwofaTests(unittest.TestCase):
    def test_reauth_otp_timeout_retriggers_authorize_and_returns_new_code(self):
        session = MagicMock()
        with patch(
            "core.email_provider.wait_for_otp",
            side_effect=[RuntimeError("等待 Remail 验证码超时"), "654321"],
        ) as wait_for_otp, patch.object(
            account_export, "_trigger_reauth_with_retry", return_value="https://auth.example/retry"
        ) as trigger, patch.object(
            account_export, "_follow_reauth_with_retry", return_value="https://auth.openai.com/email-verification"
        ) as follow, patch("core.openai_auth.send_email_otp") as send_otp, patch.object(
            account_export.time, "time", return_value=201.0
        ), patch.object(
            account_export, "human_delay"
        ):
            code, after_ts = account_export._wait_for_reauth_otp_with_retry(
                session, "user@example.com", after_ts=100.0, max_attempts=2
            )

        self.assertEqual(code, "654321")
        self.assertEqual(after_ts, 201.0)
        self.assertEqual(wait_for_otp.call_args_list[0].kwargs["after_ts"], 100.0)
        self.assertEqual(wait_for_otp.call_args_list[1].kwargs["after_ts"], 201.0)
        trigger.assert_called_once_with(session, "user@example.com")
        follow.assert_called_once_with(session, "https://auth.example/retry")
        send_otp.assert_called_once_with(session)

    def test_reauth_otp_non_timeout_error_is_not_retried(self):
        session = MagicMock()
        with patch(
            "core.email_provider.wait_for_otp", side_effect=RuntimeError("Remail service token 缺失")
        ), patch.object(account_export, "_trigger_reauth_with_retry") as trigger:
            with self.assertRaisesRegex(RuntimeError, "service token"):
                account_export._wait_for_reauth_otp_with_retry(
                    session, "user@example.com", after_ts=100.0, max_attempts=2
                )

        trigger.assert_not_called()

    def test_extract_nextauth_session_token_supports_cookie_chunks(self):
        session = SimpleNamespace(session=SimpleNamespace(cookies={
            "__Secure-next-auth.session-token.1": "part-two",
            "__Secure-next-auth.session-token.0": "part-one",
        }))
        self.assertEqual(
            account_export.extract_nextauth_session_token(session),
            "part-onepart-two",
        )

    def test_oauth_callback_403_logs_stage_without_oauth_query_secrets(self):
        session = MagicMock()
        session.session.cookies = {}
        session.get_auth_navigate_headers.return_value = {}
        session.get_chatgpt_navigate_headers.return_value = {}
        callback = "https://chatgpt.com/api/auth/callback/openai?code=secret-code&state=secret-state"
        response = SimpleNamespace(
            status_code=403, url=callback, headers={"cf-mitigated": "challenge"},
            raise_for_status=MagicMock(side_effect=RuntimeError("HTTP Error 403")),
        )
        session.get.return_value = response
        with self.assertLogs("core.account_export", level="INFO") as captured:
            with self.assertRaisesRegex(RuntimeError, "403"):
                account_export.follow_oauth_callback(session, callback)
        emitted = "\n".join(captured.output)
        self.assertIn("cf_mitigated=challenge", emitted)
        self.assertIn("session_cookie_present=False", emitted)
        self.assertNotIn("secret-code", emitted)
        self.assertNotIn("secret-state", emitted)

    def test_oauth_callback_rebuilds_headers_for_auth_to_chatgpt_redirect(self):
        session = MagicMock()
        session.get_auth_navigate_headers.return_value = {"kind": "auth"}
        session.get_chatgpt_navigate_headers.return_value = {"kind": "chatgpt"}
        responses = [
            SimpleNamespace(
                status_code=302,
                url="https://auth.openai.com/authorize/continue?code=one",
                headers={"Location": "https://chatgpt.com/api/auth/callback/openai?code=two"},
                raise_for_status=MagicMock(),
            ),
            SimpleNamespace(
                status_code=302,
                url="https://chatgpt.com/api/auth/callback/openai?code=two",
                headers={"Location": "/"},
                raise_for_status=MagicMock(),
            ),
            SimpleNamespace(
                status_code=200,
                url="https://chatgpt.com/",
                headers={},
                raise_for_status=MagicMock(),
            ),
        ]
        session.get.side_effect = responses

        final_url = account_export.follow_oauth_callback(
            session,
            "https://auth.openai.com/authorize/continue?code=one",
            referer="https://auth.openai.com/mfa-challenge/factor-1",
        )

        self.assertEqual(final_url, "https://chatgpt.com/")
        self.assertEqual(session.get.call_count, 3)
        self.assertEqual(session.get.call_args_list[0].kwargs["headers"], {"kind": "auth"})
        self.assertEqual(session.get.call_args_list[1].kwargs["headers"], {"kind": "chatgpt"})
        self.assertEqual(session.get.call_args_list[2].kwargs["headers"], {"kind": "chatgpt"})
        self.assertTrue(all(not call.kwargs["allow_redirects"] for call in session.get.call_args_list))

    def test_mfa_challenge_document_403_returns_factor_url_and_clears_circuit(self):
        session = _CircuitSession()
        session.get_auth_navigate_headers = MagicMock(return_value={})
        session.get = MagicMock(return_value=SimpleNamespace(
            status_code=403,
            url="https://auth.openai.com/mfa-challenge/factor-123",
        ))
        session.blocked_until = 9999999999.0
        session.blocked_reason = "HTTP 403 from MFA challenge"

        result = account_export._follow_reauth(session, "https://auth.example/authorize")

        self.assertEqual(result, "https://auth.openai.com/mfa-challenge/factor-123")
        self.assertEqual(session.reset_count, 1)
        self.assertEqual(session.blocked_until, 0.0)

    def test_authorize_403_reuses_cf_cookie_and_retries(self):
        session = _CircuitSession()
        calls = []

        def follow(_session, _auth_url):
            calls.append(1)
            if len(calls) == 1:
                session.blocked_until = 9999999999.0
                session.blocked_reason = "HTTP 403 from authorize"
                raise RuntimeError("HTTP 403 from authorize")
            return "https://auth.openai.com/email-verification"

        with patch.object(account_export, "_follow_reauth", side_effect=follow), patch(
            "config.twofa.TWOFA_REAUTH_MAX_ATTEMPTS", 3
        ), patch("config.twofa.TWOFA_REAUTH_RETRY_DELAY", 0), patch.object(
            account_export.time, "sleep"
        ) as sleep:
            result = account_export._follow_reauth_with_retry(
                session, "https://auth.openai.com/api/accounts/authorize?state=test"
            )

        self.assertEqual(result, "https://auth.openai.com/email-verification")
        self.assertEqual(len(calls), 2)
        self.assertEqual(session.reset_count, 1)
        sleep.assert_not_called()

    def test_reauth_403_is_retried_after_circuit_reset(self):
        session = _CircuitSession()
        calls = []

        def trigger(_session, _email):
            calls.append(1)
            if len(calls) < 3:
                session.blocked_until = 9999999999.0
                session.blocked_reason = "HTTP 403 from csrf"
                raise RuntimeError("HTTP 403 from csrf")
            return "https://auth.example/authorize"

        with patch.object(account_export, "_trigger_reauth", side_effect=trigger), patch(
            "config.twofa.TWOFA_REAUTH_MAX_ATTEMPTS", 3
        ), patch("config.twofa.TWOFA_REAUTH_RETRY_DELAY", 0), patch.object(
            account_export.time, "sleep"
        ) as sleep:
            result = account_export._trigger_reauth_with_retry(
                session, "user@example.com"
            )

        self.assertEqual(result, "https://auth.example/authorize")
        self.assertEqual(len(calls), 3)
        self.assertEqual(session.reset_count, 2)
        sleep.assert_not_called()

    def test_reauth_business_400_is_not_retried(self):
        session = _CircuitSession()
        with patch.object(
            account_export, "_trigger_reauth", side_effect=RuntimeError("HTTP 400 invalid request")
        ) as trigger, patch("config.twofa.TWOFA_REAUTH_MAX_ATTEMPTS", 3):
            with self.assertRaisesRegex(RuntimeError, "HTTP 400"):
                account_export._trigger_reauth_with_retry(
                    session, "user@example.com"
                )

        trigger.assert_called_once()
        self.assertEqual(session.reset_count, 0)

    def test_optional_bootstrap_403_does_not_block_reauth(self):
        session = _CircuitSession()

        def bootstrap_with_403(*_args, **_kwargs):
            session.blocked_until = 9999999999.0
            session.blocked_reason = (
                "HTTP 403 from https://chatgpt.com/backend-api/accounts/optimized/check"
            )

        def assert_reauth_can_start(_session, _email):
            self.assertEqual(session.blocked_until, 0.0)
            self.assertEqual(session.blocked_reason, "")
            raise RuntimeError("stop-after-assert")

        with patch(
            "core.chatgpt_bootstrap.authenticated_bootstrap",
            side_effect=bootstrap_with_403,
        ), patch.object(account_export, "human_delay"), patch.object(
            account_export, "_trigger_reauth", side_effect=assert_reauth_can_start
        ):
            with self.assertRaisesRegex(RuntimeError, "stop-after-assert"):
                account_export.setup_2fa(
                    session,
                    "user@example.com",
                    access_token="access-token",
                )

        self.assertEqual(session.reset_count, 1)

    def test_bootstrap_exception_also_clears_circuit(self):
        session = _CircuitSession()

        def bootstrap_failure(*_args, **_kwargs):
            session.blocked_until = 9999999999.0
            session.blocked_reason = "HTTP 403 from optional bootstrap"
            raise RuntimeError("bootstrap failed")

        def assert_reauth_can_start(_session, _email):
            self.assertEqual(session.blocked_until, 0.0)
            raise RuntimeError("stop-after-assert")

        with patch(
            "core.chatgpt_bootstrap.authenticated_bootstrap",
            side_effect=bootstrap_failure,
        ), patch.object(account_export, "human_delay"), patch.object(
            account_export, "_trigger_reauth", side_effect=assert_reauth_can_start
        ):
            with self.assertRaisesRegex(RuntimeError, "stop-after-assert"):
                account_export.setup_2fa(
                    session,
                    "user@example.com",
                    access_token="access-token",
                )

        self.assertEqual(session.reset_count, 1)


    def test_reauth_browser_fallback_rejects_unchanged_authorize_url(self):
        session = _CircuitSession()
        session.get_auth_navigate_headers = MagicMock(return_value={})
        response = SimpleNamespace(
            status_code=403,
            url="https://auth.openai.com/api/accounts/authorize?state=test",
            raise_for_status=MagicMock(side_effect=RuntimeError("HTTP 403")),
        )
        session.get = MagicMock(return_value=response)
        auth_url = response.url

        with patch(
            "core.browser_environment.follow_authorize_with_headless_browser",
            return_value=auth_url,
        ):
            with self.assertRaisesRegex(RuntimeError, "仍停留在 authorize"):
                account_export._follow_reauth(session, auth_url)

    def test_invalid_state_rebuilds_entire_reauth_session(self):
        session = _CircuitSession()
        auth_urls = ["https://auth.example/first", "https://auth.example/second"]
        with patch.object(
            account_export, "_trigger_reauth_with_retry", side_effect=auth_urls
        ) as trigger, patch.object(
            account_export,
            "_follow_reauth_with_retry",
            return_value="https://auth.openai.com/email-verification",
        ) as follow, patch(
            "core.openai_auth.send_email_otp",
            side_effect=[RuntimeError("原邮箱 OTP 发送返回 409: invalid_state"), None],
        ) as send_otp, patch.object(
            account_export.time, "time", return_value=321.0
        ), patch.object(
            account_export.time, "sleep"
        ), patch.object(
            account_export, "human_delay"
        ):
            after_ts = account_export._start_reauth_email_verification(
                session, "user@example.com", max_attempts=2
            )

        self.assertEqual(after_ts, 321.0)
        self.assertEqual(trigger.call_count, 2)
        self.assertEqual(follow.call_count, 2)
        self.assertEqual(send_otp.call_count, 2)
        self.assertEqual(session.reset_count, 1)

    def test_twofa_reauth_uses_saved_password_when_server_lands_on_password_page(self):
        session = _CircuitSession()
        password_result = {
            "continue_url": "https://auth.openai.com/authorize/continue?code=fresh",
            "page": {"type": "external_url"},
        }
        with patch.object(
            account_export, "_trigger_reauth_with_retry", return_value="https://auth.example/authorize"
        ), patch.object(
            account_export, "_follow_reauth_with_retry", return_value="https://auth.openai.com/log-in/password"
        ), patch.object(
            account_export, "_account_registration_password", return_value="Saved-password-123"
        ), patch(
            "core.account_liveness._password_verify", return_value=password_result
        ) as verify, patch(
            "core.account_liveness._extract_continue_url",
            return_value=password_result["continue_url"],
        ), patch.object(
            account_export, "_exchange_new_token", return_value="fresh-access-token"
        ) as exchange, patch.object(account_export, "human_delay"):
            state = account_export._start_twofa_reauth(
                session, "user@example.com", max_attempts=2
            )

        self.assertEqual(state, {"mode": "token", "access_token": "fresh-access-token"})
        verify.assert_called_once_with(session, "Saved-password-123")
        exchange.assert_called_once_with(
            session,
            password_result["continue_url"],
            referer="https://auth.openai.com/log-in/password",
        )

    def test_twofa_reauth_email_page_keeps_otp_flow(self):
        session = _CircuitSession()
        with patch.object(
            account_export, "_trigger_reauth_with_retry", return_value="https://auth.example/authorize"
        ), patch.object(
            account_export, "_follow_reauth_with_retry", return_value="https://auth.openai.com/email-verification"
        ), patch("core.openai_auth.send_email_otp") as send_otp, patch.object(
            account_export.time, "time", return_value=456.0
        ), patch.object(account_export, "human_delay"):
            state = account_export._start_twofa_reauth(
                session, "user@example.com", max_attempts=2
            )

        self.assertEqual(state, {"mode": "email_otp", "after_ts": 456.0})
        send_otp.assert_called_once_with(session)

    def test_twofa_reauth_reports_remote_mfa_when_local_secret_is_missing(self):
        session = _CircuitSession()
        password_result = {
            "continue_url": "https://auth.openai.com/mfa-challenge/factor-123",
            "page": {
                "type": "mfa_challenge",
                "payload": {"factor_id": "factor-123"},
            },
        }
        with patch.object(
            account_export, "_trigger_reauth_with_retry", return_value="https://auth.example/authorize"
        ), patch.object(
            account_export, "_follow_reauth_with_retry", return_value="https://auth.openai.com/log-in/password"
        ), patch.object(
            account_export, "_account_registration_password", return_value="Saved-password-123"
        ), patch(
            "core.account_liveness._password_verify", return_value=password_result
        ), patch(
            "core.account_liveness._extract_continue_url",
            return_value=password_result["continue_url"],
        ), patch.object(account_export, "human_delay"):
            with self.assertRaisesRegex(
                account_export.RemoteMfaAlreadyEnabledError,
                "远端账号已启用 2FA",
            ):
                account_export._start_twofa_reauth(
                    session, "user@example.com", max_attempts=2
                )


if __name__ == "__main__":
    unittest.main()
