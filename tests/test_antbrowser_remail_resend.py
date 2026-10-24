# -*- coding: utf-8 -*-
import unittest
from unittest.mock import MagicMock, call, patch

from core import antbrowser_registration
from core.email_provider import EmailOtpUnavailableError


class AntBrowserRemailResendTests(unittest.TestCase):
    def test_email_verification_page_helper_is_available(self):
        self.assertTrue(callable(antbrowser_registration._is_email_verification_page))

    @patch.object(antbrowser_registration, "human_delay")
    @patch.object(antbrowser_registration, "_click_resend_email_otp")
    @patch.object(antbrowser_registration, "wait_for_otp")
    @patch.object(antbrowser_registration, "resolve_email_source", return_value="remail")
    def test_waits_90_seconds_then_resends_and_waits_60_seconds(
        self, resolve_source, wait_for_otp, click_resend, human_delay
    ):
        wait_for_otp.side_effect = [RuntimeError("等待 Remail 验证码超时"), "984418"]

        with patch.object(antbrowser_registration.time, "time", return_value=1000.0):
            code = antbrowser_registration._wait_registration_otp(
                MagicMock(), "user@icloud.com", 900.0
            )

        self.assertEqual(code, "984418")
        self.assertEqual(
            wait_for_otp.call_args_list,
            [
                call("user@icloud.com", after_ts=900.0, max_wait=35),
                call("user@icloud.com", after_ts=1000.0, max_wait=30),
            ],
        )
        click_resend.assert_called_once()
        human_delay.assert_called_once_with("api")

    @patch.object(antbrowser_registration, "reject_remail_after_otp_timeout")
    @patch.object(antbrowser_registration, "human_delay")
    @patch.object(antbrowser_registration, "_click_resend_email_otp")
    @patch.object(antbrowser_registration, "wait_for_otp")
    @patch.object(antbrowser_registration, "resolve_email_source", return_value="remail")
    def test_blacklists_only_after_second_wait_times_out(
        self, resolve_source, wait_for_otp, click_resend, human_delay, reject_timeout
    ):
        first = RuntimeError("等待 Remail 验证码超时")
        second = RuntimeError("等待 Remail 验证码超时")
        wait_for_otp.side_effect = [first, second]
        reject_timeout.side_effect = EmailOtpUnavailableError("已跳过拉黑")

        with patch.object(antbrowser_registration.time, "time", return_value=1000.0):
            with self.assertRaises(EmailOtpUnavailableError):
                antbrowser_registration._wait_registration_otp(
                    MagicMock(), "user@icloud.com", 900.0
                )

        reject_timeout.assert_called_once_with("user@icloud.com", second)
        click_resend.assert_called_once()


if __name__ == "__main__":
    unittest.main()
