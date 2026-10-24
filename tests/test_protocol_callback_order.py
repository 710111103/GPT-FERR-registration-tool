import unittest
from unittest.mock import MagicMock, patch

import main


class ProtocolCallbackOrderTests(unittest.TestCase):
    def test_protocol_session_succeeds_without_browser(self):
        session = MagicMock()
        with patch.object(main, "follow_oauth_callback") as follow, patch.object(
            main, "fetch_session", return_value={"accessToken": "protocol-token"}
        ), patch.object(main, "human_delay"), patch(
            "core.browser_environment.follow_oauth_callback_with_headless_browser"
        ) as browser:
            result, token = main._finalize_registration_session(
                session, "https://auth.openai.com/authorize/continue", "user@example.com"
            )

        self.assertEqual(token, "protocol-token")
        self.assertEqual(result["accessToken"], token)
        follow.assert_called_once()
        browser.assert_not_called()

    def test_browser_used_after_protocol_error(self):
        session = MagicMock()
        with patch.object(main, "follow_oauth_callback", side_effect=RuntimeError("HTTP 403")), patch.object(
            main, "fetch_session"
        ) as fetch, patch("core.browser_environment.follow_oauth_callback_with_headless_browser", return_value={
            "accessToken": "browser-token"
        }) as browser:
            _, token = main._finalize_registration_session(
                session, "https://auth.openai.com/authorize/continue", "user@example.com"
            )

        self.assertEqual(token, "browser-token")
        fetch.assert_not_called()
        session.reset_circuit_breaker.assert_called_once()
        browser.assert_called_once()

    def test_pure_protocol_mode_never_starts_callback_browser(self):
        session = MagicMock()
        with patch.object(main._protocol_cfg, "PURE_PROTOCOL_ONLY", True), patch.object(
            main, "_FINALIZE_SESSION_MAX_ATTEMPTS", 1
        ), patch.object(main, "follow_oauth_callback", side_effect=RuntimeError("HTTP 403")), patch(
            "core.browser_environment.follow_oauth_callback_with_headless_browser"
        ) as browser:
            with self.assertRaisesRegex(RuntimeError, "HTTP 403"):
                main._finalize_registration_session(
                    session, "https://auth.openai.com/authorize/continue", "user@example.com"
                )
        browser.assert_not_called()


if __name__ == "__main__":
    unittest.main()
