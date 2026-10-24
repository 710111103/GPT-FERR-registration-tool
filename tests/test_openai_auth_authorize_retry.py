# -*- coding: utf-8 -*-
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import core.openai_auth as openai_auth
from config import openai_protocol


class _Session:
    def __init__(self):
        self.calls = 0
        self.reset_count = 0
        self.cookie_jar_identity = object()

    def get_auth_navigate_headers(self, **_kwargs):
        return {"sec-fetch-mode": "navigate"}

    def get(self, *_args, **_kwargs):
        self.calls += 1
        if self.calls == 1:
            error = RuntimeError("HTTP Error 403")
            error.response = SimpleNamespace(status_code=403)
            raise error
        return SimpleNamespace(
            status_code=200,
            url="https://auth.openai.com/email-verification",
            raise_for_status=lambda: None,
        )

    def reset_circuit_breaker(self):
        self.reset_count += 1


class AuthorizeRetryTests(unittest.TestCase):
    def test_about_you_403_in_pure_protocol_reports_http_error_not_name_error(self):
        session = _Session()
        session.get = lambda *_args, **_kwargs: SimpleNamespace(status_code=403)

        with patch.object(openai_protocol, "PURE_PROTOCOL_ONLY", True):
            with self.assertRaisesRegex(RuntimeError, "about-you.*HTTP 403"):
                openai_auth.navigate_about_you(session)

    def test_challenge_403_stops_same_session_retries(self):
        session = _Session()
        cookie_jar_identity = session.cookie_jar_identity
        def challenged(*_args, **_kwargs):
            session.calls += 1
            error = RuntimeError("HTTP Error 403")
            error.response = SimpleNamespace(status_code=403, headers={"cf-mitigated": "challenge"}, text="challenge")
            raise error
        session.get = challenged
        with patch.object(openai_auth.time, "sleep") as sleep:
            with self.assertRaises(openai_auth.AuthChallengeRequiredError):
                openai_auth.follow_authorize(
                    session, "https://auth.openai.com/api/accounts/authorize?state=test",
                )
        self.assertEqual(session.calls, 1)
        self.assertEqual(session.reset_count, 0)
        self.assertIs(session.cookie_jar_identity, cookie_jar_identity)
        sleep.assert_not_called()

    def test_plain_403_without_challenge_header_can_retry(self):
        session = _Session()
        with patch.object(openai_auth.time, "sleep") as sleep:
            landing = openai_auth.follow_authorize(session, "https://auth.openai.com/api/accounts/authorize?state=test")
        self.assertEqual(landing, "https://auth.openai.com/email-verification")
        self.assertEqual(session.calls, 2)
        sleep.assert_called_once()

    def test_challenge_page_at_mfa_url_does_not_count_as_landing(self):
        session = _Session()
        session.get = lambda *_args, **_kwargs: SimpleNamespace(
            status_code=403, url="https://auth.openai.com/mfa-challenge/example",
            text="challenge", headers={"cf-mitigated": "challenge"},
        )
        with self.assertRaises(openai_auth.AuthChallengeRequiredError):
            openai_auth.follow_authorize(session, "https://auth.openai.com/api/accounts/authorize?state=test")


    def test_mfa_403_with_deactivated_error_is_not_treated_as_challenge(self):
        session = _Session()
        session.get = lambda *_args, **_kwargs: SimpleNamespace(
            status_code=403,
            url="https://auth.openai.com/mfa-challenge/example",
            text="Auth login details\nerror_code: account_deactivated",
            headers={},
        )
        with self.assertRaises(openai_auth.AccountUnusableError) as ctx:
            openai_auth.follow_authorize(
                session,
                "https://auth.openai.com/api/accounts/authorize?state=test",
            )
        self.assertEqual(ctx.exception.error_code, "account_deactivated")

    def test_mfa_403_without_deactivation_code_remains_challenge(self):
        session = _Session()
        session.get = lambda *_args, **_kwargs: SimpleNamespace(
            status_code=403,
            url="https://auth.openai.com/mfa-challenge/example",
            text="verification required",
            headers={},
        )
        self.assertEqual(
            openai_auth.follow_authorize(
                session,
                "https://auth.openai.com/api/accounts/authorize?state=test",
            ),
            "https://auth.openai.com/mfa-challenge/example",
        )

    def test_headless_about_blank_falls_back_to_protocol(self):
        session = _Session()
        session.get = lambda *_args, **_kwargs: SimpleNamespace(
            status_code=200,
            url="https://auth.openai.com/email-verification",
            raise_for_status=lambda: None,
        )
        with patch(
            "core.browser_environment.follow_authorize_with_headless_browser",
            return_value="about:blank",
        ):
            result = openai_auth.follow_authorize(
                session,
                "https://auth.openai.com/api/accounts/authorize?state=test",
            )
        self.assertEqual(result, "https://auth.openai.com/email-verification")

    def test_unchanged_authorize_url_is_rejected(self):
        authorize_url = "https://auth.openai.com/api/accounts/authorize?state=test"
        with self.assertRaisesRegex(RuntimeError, "未建立有效登录态"):
            openai_auth._require_authorize_landing(authorize_url, authorize_url)


if __name__ == "__main__":
    unittest.main()
