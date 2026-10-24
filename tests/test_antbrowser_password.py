# -*- coding: utf-8 -*-
import unittest
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

from core import antbrowser_registration, roxy_codex_oauth, roxy_registration
from core.antbrowser_driver import AntBrowserSeleniumDriver


class AntBrowserPasswordTests(unittest.TestCase):
    def test_password_request_capture_records_shape_without_credentials(self):
        context = MagicMock()
        callbacks = {}
        context.on.side_effect = lambda event, callback: callbacks.__setitem__(event, callback)
        state = antbrowser_registration._capture_password_request(context)

        request = MagicMock()
        request.url = "https://auth.openai.com/api/accounts/user/register"
        request.method = "POST"
        request.post_data = '{"username":"user@example.com","password":"Secret-123"}'
        request.headers = {
            "content-type": "application/json",
            "openai-sentinel-token": "secret-sentinel-token",
        }
        response = MagicMock()
        response.request = request
        response.status = 200

        with self.assertLogs(antbrowser_registration.logger, level="INFO") as logs:
            callbacks["request"](request)
            callbacks["response"](response)

        joined = "\n".join(logs.output)
        self.assertIn("/api/accounts/user/register", joined)
        self.assertIn("status=200", joined)
        self.assertIn("'password'", joined)
        self.assertNotIn("Secret-123", joined)
        self.assertNotIn("secret-sentinel-token", joined)
        self.assertNotIn("user@example.com", joined)
        self.assertTrue(state["request_seen"])
        self.assertTrue(state["response_seen"])
        self.assertEqual(state["response_status"], 200)
        self.assertEqual(state["path"], "/api/accounts/user/register")

    def test_ant_registration_rechecks_password_until_late_link_appears(self):
        driver = MagicMock()
        with patch.object(
            antbrowser_registration,
            "_fill_password_page_if_present",
            side_effect=[None, "Test-password-123"],
        ) as fill_password, patch.object(antbrowser_registration.time, "sleep"):
            result = antbrowser_registration._ensure_registration_password(
                driver,
                "user@example.com",
                None,
                timeout=35,
            )

        self.assertEqual(result, "Test-password-123")
        self.assertEqual(fill_password.call_count, 2)

    def test_ant_registration_does_not_invent_password_when_no_page_input(self):
        driver = MagicMock()
        with patch.object(
            antbrowser_registration,
            "_fill_password_page_if_present",
            return_value=None,
        ), patch.object(antbrowser_registration, "_is_email_verification_page", return_value=True):
            result = antbrowser_registration._ensure_registration_password(
                driver,
                "user@example.com",
                None,
                timeout=0,
            )
        self.assertIsNone(result)


    def test_ant_registration_discards_candidate_without_success_response(self):
        driver = MagicMock()
        capture = {"request_seen": True, "response_seen": True, "response_status": 403}
        with patch.object(antbrowser_registration, "_fill_password_page_if_present", return_value="Candidate-123"):
            result = antbrowser_registration._ensure_registration_password(
                driver, "user@example.com", None, timeout=0, capture_state=capture,
            )
        self.assertIsNone(result)

    def test_ant_registration_keeps_candidate_after_success_response(self):
        driver = MagicMock()
        capture = {"request_seen": True, "response_seen": True, "response_status": 200}
        with patch.object(antbrowser_registration, "_fill_password_page_if_present", return_value="Confirmed-123"):
            result = antbrowser_registration._ensure_registration_password(
                driver, "user@example.com", None, timeout=0, capture_state=capture,
            )
        self.assertEqual(result, "Confirmed-123")

    def test_ant_registration_keeps_existing_password_without_page_probe(self):
        driver = MagicMock()
        with patch.object(
            antbrowser_registration,
            "_fill_password_page_if_present",
        ) as fill_password:
            result = antbrowser_registration._ensure_registration_password(
                driver,
                "user@example.com",
                "Existing-password-123",
            )

        self.assertEqual(result, "Existing-password-123")
        fill_password.assert_not_called()

    def test_existing_candidate_is_rejected_when_capture_failed(self):
        driver = MagicMock()
        capture = {"request_seen": True, "response_seen": True, "response_status": 401}
        result = antbrowser_registration._ensure_registration_password(
            driver, "user@example.com", "Candidate-123", timeout=0, capture_state=capture,
        )
        self.assertIsNone(result)

    def test_continue_with_password_uses_native_target_when_available(self):
        driver = MagicMock()
        password_button = MagicMock()
        driver.continue_with_password_target_native.return_value = {
            "ok": True,
            "reason": "playwright_native_continue_with_password",
            "button": password_button,
            "text": "Continue with password",
        }

        with patch.object(roxy_registration, "_human_click") as click:
            result = roxy_registration._click_continue_with_password_if_present(driver)

        self.assertTrue(result["ok"])
        self.assertEqual(result["reason"], "clicked_continue_with_password")
        click.assert_called_once_with(driver, password_button, label="continue_with_password")
        driver.execute_script.assert_not_called()

    def test_password_flow_waits_for_password_page_after_continue_click(self):
        driver = MagicMock()
        password_input = MagicMock()
        submit_button = MagicMock()
        driver.continue_with_password_target_native.return_value = {
            "ok": True, "button": MagicMock(),
        }
        driver.signup_password_targets_native.return_value = {
            "ok": True, "input": password_input, "button": submit_button,
        }

        with patch.object(roxy_registration, "_is_email_verification_page", side_effect=[True, False, True]), \
             patch.object(roxy_registration, "_is_signup_password_page", side_effect=[False, False, True, True]), \
             patch.object(roxy_registration, "_has_access_token", return_value=False), \
             patch.object(roxy_registration, "_password_page_state", return_value={"url": "create-account/password"}), \
             patch.object(roxy_registration, "_is_login_password_page", return_value=False), \
             patch.object(roxy_registration, "_registration_password", return_value="Test-password-123"), \
             patch.object(roxy_registration, "_human_type_text"), \
             patch.object(roxy_registration, "_human_click"), \
             patch.object(roxy_registration, "human_delay"), \
             patch.object(roxy_registration.time, "sleep"):
            result = roxy_registration._fill_password_page_if_present(driver, "user@example.com", timeout=2)

        self.assertEqual(result, "Test-password-123")
        driver.continue_with_password_target_native.assert_called_once_with()

    def test_http_500_rebuilds_email_otp_session(self):
        driver = MagicMock()
        driver.current_url = "chrome-error://chromewebdata/"
        with patch.object(roxy_registration, "_email_otp_page_state", return_value={
            "title": "auth.openai.com", "text": "HTTP ERROR 500", "errors": ["HTTP ERROR 500"],
        }), patch.object(roxy_registration, "_safe_get") as safe_get, patch.object(
            roxy_registration, "_maybe_accept"
        ), patch.object(roxy_registration, "_submit_email_and_wait_next", return_value="otp") as submit, patch.object(
            roxy_registration, "_fill_password_page_if_present"
        ), patch.object(roxy_registration, "_is_email_verification_page", return_value=True):
            recovered = roxy_registration._recover_email_otp_http_500(driver, "failed@example.com")

        self.assertTrue(recovered)
        safe_get.assert_called_once()
        submit.assert_called_once_with(driver, "failed@example.com", attempts=2)

    def test_non_http_error_page_is_not_recovered(self):
        driver = MagicMock()
        driver.current_url = "https://auth.openai.com/email-verification"
        with patch.object(roxy_registration, "_email_otp_page_state", return_value={
            "title": "Verify email", "text": "Enter your code", "errors": [],
        }), patch.object(roxy_registration, "_safe_get") as safe_get:
            recovered = roxy_registration._recover_email_otp_http_500(driver, "user@example.com")

        self.assertFalse(recovered)
        safe_get.assert_not_called()

    def test_resend_navigation_is_treated_as_success(self):
        driver = MagicMock()
        page = driver.page
        locator = page.locator.return_value.first
        locator.count.return_value = 1
        locator.is_visible.return_value = True
        locator.inner_text.return_value = "Resend email"
        locator.click.side_effect = RuntimeError(
            "Execution context was destroyed, most likely because of a navigation"
        )

        with patch.object(roxy_registration, "_check_and_solve_cloudflare", return_value=False):
            result = roxy_registration._click_resend_email_otp(driver, timeout=1)

        self.assertTrue(result["ok"])
        self.assertEqual(result["reason"], "navigation_after_click")
        driver.execute_script.assert_not_called()

    def test_auth_navigation_retries_transient_playwright_error(self):
        driver = MagicMock()
        driver.get.side_effect = [RuntimeError("net::ERR_ABORTED"), None]
        driver.current_url = "about:blank"
        driver.execute_script.return_value = False
        with patch.object(roxy_codex_oauth.time, "sleep"):
            roxy_codex_oauth._open_auth_url(driver, "https://chatgpt.com/auth/login")
        self.assertEqual(driver.get.call_count, 2)

    def test_mfa_uses_native_targets_when_driver_provides_them(self):
        driver = MagicMock()
        code_input = MagicMock()
        submit_button = MagicMock()
        driver.mfa_targets_native.return_value = {
            "ok": True, "input": code_input, "button": submit_button,
        }
        with patch.object(roxy_codex_oauth, "_account_totp_code_for_email", return_value="123456"), \
             patch.object(roxy_codex_oauth, "_is_mfa_challenge_page", side_effect=[True, False]), \
             patch.object(roxy_codex_oauth, "_human_type_text") as type_text, \
             patch.object(roxy_codex_oauth, "_human_click") as click, \
             patch.object(roxy_codex_oauth, "human_delay"):
            result = roxy_codex_oauth._fill_mfa_challenge_if_present(
                driver, "user@example.com", timeout=2,
            )

        self.assertTrue(result)
        type_text.assert_called_once_with(driver, code_input, "123456", clear=True)
        click.assert_called_once_with(driver, submit_button, label="codex_mfa_submit")
        driver.execute_script.assert_not_called()

    def test_login_prefers_mfa_over_email_otp_for_one_time_code_input(self):
        driver = MagicMock()
        with patch.object(roxy_codex_oauth, "_account_password_for_email", return_value="password"), \
             patch.object(roxy_codex_oauth, "_is_mfa_challenge_page", return_value=True), \
             patch.object(roxy_codex_oauth, "_fill_mfa_challenge_if_present", return_value=True) as fill_mfa, \
             patch.object(roxy_codex_oauth, "_is_email_verification_page") as email_otp:
            result = roxy_codex_oauth._fill_login_password_if_present(
                driver, "user@example.com", timeout=2,
            )

        self.assertEqual(result, "next_step")
        fill_mfa.assert_called_once_with(driver, "user@example.com", timeout=15)
        email_otp.assert_not_called()

    def test_password_page_uses_native_targets_when_driver_provides_them(self):
        driver = MagicMock()
        password_input = MagicMock()
        submit_button = MagicMock()
        driver.signup_password_targets_native.side_effect = [
            {"ok": True, "reason": "playwright_native_password_targets", "input": password_input, "button": submit_button},
            {"ok": True, "reason": "playwright_native_password_targets", "input": password_input, "button": submit_button},
        ]

        with patch.object(roxy_registration, "_is_email_verification_page", side_effect=[False, True]), \
             patch.object(roxy_registration, "_has_access_token", return_value=False), \
             patch.object(roxy_registration, "_password_page_state", return_value={"url": "create-account/password"}), \
             patch.object(roxy_registration, "_is_signup_password_page", return_value=True), \
             patch.object(roxy_registration, "_is_login_password_page", return_value=False), \
             patch.object(roxy_registration, "_registration_password", return_value="Test-password-123"), \
             patch.object(roxy_registration, "_human_type_text") as type_text, \
             patch.object(roxy_registration, "_human_click") as click, \
             patch.object(roxy_registration, "human_delay"), \
             patch.object(roxy_registration.time, "sleep"):
            result = roxy_registration._fill_password_page_if_present(
                driver, "user@example.com", timeout=2,
            )

        self.assertEqual(result, "Test-password-123")
        self.assertEqual(driver.signup_password_targets_native.call_count, 2)
        driver.execute_script.assert_not_called()
        type_text.assert_called_once_with(driver, password_input, "Test-password-123", clear=True)
        click.assert_called_once_with(driver, submit_button, label="password_submit")

    def test_password_flow_does_not_treat_transient_blank_dom_as_success(self):
        driver = MagicMock()
        password_input = MagicMock()
        submit_button = MagicMock()
        driver.signup_password_targets_native.side_effect = [
            {"ok": True, "reason": "password_targets", "input": password_input, "button": submit_button},
            {"ok": True, "reason": "password_targets", "input": password_input, "button": submit_button},
        ]
        clock = {"now": 0.0}

        def now():
            clock["now"] += 1.0
            return clock["now"]

        with patch.object(roxy_registration.time, "time", side_effect=now), \
             patch.object(roxy_registration.time, "sleep"), \
             patch.object(roxy_registration, "_is_email_verification_page", return_value=False), \
             patch.object(roxy_registration, "_has_access_token", return_value=False), \
             patch.object(roxy_registration, "_password_page_state", return_value={"url": "about:blank"}), \
             patch.object(roxy_registration, "_is_signup_password_page", side_effect=[True] + [False] * 20), \
             patch.object(roxy_registration, "_is_login_password_page", return_value=False), \
             patch.object(roxy_registration, "_registration_password", return_value="Test-password-123"), \
             patch.object(roxy_registration, "_human_type_text"), \
             patch.object(roxy_registration, "_human_click"), \
             patch.object(roxy_registration, "human_delay"):
            with self.assertRaisesRegex(RuntimeError, "未进入邮箱验证码页或登录态"):
                roxy_registration._fill_password_page_if_present(
                    driver, "user@example.com", timeout=30,
                )

    def test_email_submit_wait_uses_native_state_reader(self):
        driver = MagicMock()
        driver.email_submit_state_native.return_value = {
            "url": "https://auth.openai.com/email-verification",
            "state": "otp",
            "inputs": [],
        }
        with patch.object(roxy_registration, "_has_access_token") as access_token, \
             patch.object(roxy_registration, "_email_input_value_state") as script_state:
            state = roxy_registration._wait_email_submit_next_state(
                driver, "user@example.com", timeout=2,
            )

        self.assertEqual(state, "otp")
        driver.email_submit_state_native.assert_called_once_with("user@example.com")
        access_token.assert_not_called()
        script_state.assert_not_called()

    def test_email_submit_wait_keeps_waiting_on_slow_authorize_page(self):
        driver = MagicMock()
        driver.current_url = "https://auth.openai.com/api/accounts/authorize?state=test"
        driver.email_submit_state_native = None
        clock = {"now": 0.0, "otp_checks": 0}

        def now():
            clock["now"] += 1.0
            return clock["now"]

        def is_otp(_driver):
            clock["otp_checks"] += 1
            return clock["otp_checks"] >= 15

        with patch.object(roxy_registration.time, "time", side_effect=now), patch.object(
            roxy_registration.time, "sleep"
        ), patch.object(
            roxy_registration, "_email_input_value_state", return_value={
                "url": driver.current_url, "state": "unknown", "inputs": [],
            }
        ), patch.object(roxy_registration, "_has_access_token", return_value=False), patch.object(
            roxy_registration, "_is_invalid_authorize_page", return_value=False
        ), patch.object(
            roxy_registration, "_is_email_verification_page", side_effect=is_otp
        ), patch.object(roxy_registration, "_is_signup_password_page", return_value=False), patch.object(
            roxy_registration, "_is_login_password_page", return_value=False
        ):
            state = roxy_registration._wait_email_submit_next_state(
                driver, "user@example.com", timeout=3,
            )

        self.assertEqual(state, "otp")
        self.assertGreaterEqual(clock["otp_checks"], 15)

    def test_safe_get_uses_native_navigation_state_after_timeout(self):
        driver = MagicMock()
        driver.get.side_effect = RuntimeError("Page.goto: Timeout 50000ms exceeded")
        driver.current_url = "https://chatgpt.com/auth/login"
        driver.navigation_state_native.return_value = {
            "url": driver.current_url,
            "has_elements": True,
        }

        roxy_registration._safe_get(
            driver,
            driver.current_url,
            timeout=1,
            attempts=1,
            accept_hosts=("chatgpt.com",),
        )

        driver.navigation_state_native.assert_called_once_with()
        driver.execute_script.assert_not_called()

    def test_phone_failure_does_not_treat_available_whatsapp_copy_as_selected_channel(self):
        state = {
            "radios": [
                {"value": "sms", "checked": True},
                {"value": "whatsapp", "checked": False},
            ],
            "bodyText": "Choose SMS or WhatsApp to receive your code",
        }

        self.assertEqual(roxy_codex_oauth._classify_phone_page_failure(state), "")

    def test_phone_failure_classifies_required_phone_without_whatsapp_mislabel(self):
        state = {
            "radios": [
                {"value": "sms", "checked": True},
                {"value": "whatsapp", "checked": False},
            ],
            "bodyText": "電話號碼為必填項目",
        }

        self.assertEqual(roxy_codex_oauth._classify_phone_page_failure(state), "phone_required")

    def test_phone_channel_rerender_refills_number_before_submit(self):
        driver = MagicMock()
        http = MagicMock()
        cfg = MagicMock(
            SMS_PROVIDER="5sim",
            SMS_MAX_RETRIES=1,
            SMS_CODE_WAIT=30,
            SMS_POLL_INTERVAL=2,
        )
        phone_fill = {
            "e164": "+15551234567",
            "actualVisible": "5551234567",
            "hiddenValue": "+15551234567",
            "dialCode": "1",
            "selectedText": "United States (+1)",
            "selectedChanged": False,
        }
        verified = {"visibleValue": "5551234567", "hiddenValue": "+15551234567"}

        with patch.object(roxy_codex_oauth.sms_provider, "_cfg", cfg), \
             patch.object(roxy_codex_oauth.sms_provider, "_http", return_value=http), \
             patch.object(roxy_codex_oauth.sms_provider, "acquire_number", return_value=("activation-1", "15551234567")), \
             patch.object(roxy_codex_oauth.sms_provider, "set_status"), \
             patch.object(roxy_codex_oauth.sms_provider, "wait_for_sms_code", return_value="123456"), \
             patch.object(roxy_codex_oauth.sms_provider, "complete"), \
             patch.object(roxy_codex_oauth, "_has_strict_add_phone_form", return_value=True), \
             patch.object(roxy_codex_oauth, "_ensure_add_phone_input"), \
             patch.object(roxy_codex_oauth, "_select_phone_country_from_number", return_value={"ok": True, "code": "1", "text": "United States (+1)"}) as select_country, \
             patch.object(roxy_codex_oauth, "_set_phone_value", side_effect=[phone_fill, phone_fill]) as set_phone, \
             patch.object(roxy_codex_oauth, "_verify_add_phone_value_before_submit", side_effect=[verified, RuntimeError("cleared"), verified]) as verify_phone, \
             patch.object(roxy_codex_oauth, "_select_sms_channel_or_raise"), \
             patch.object(roxy_codex_oauth, "_blur_active_input_and_wait"), \
             patch.object(roxy_codex_oauth, "_click_add_phone_continue_button", return_value={"ok": True}), \
             patch.object(roxy_codex_oauth, "_wait_page_settle_after_submit"), \
             patch.object(roxy_codex_oauth, "_wait_after_phone_send", return_value="code_page"), \
             patch.object(roxy_codex_oauth, "_type_otp"), \
             patch.object(roxy_codex_oauth, "_click_if_present", return_value=True), \
             patch.object(roxy_codex_oauth, "_wait_after_phone_otp_submit", return_value="callback"), \
             patch.object(roxy_codex_oauth, "human_delay"):
            roxy_codex_oauth._do_phone_verification_if_present(driver)

        self.assertEqual(select_country.call_count, 2)
        self.assertEqual(set_phone.call_count, 2)
        self.assertEqual(verify_phone.call_count, 3)

    def test_phone_required_reuses_same_order_after_country_rerender(self):
        driver = MagicMock()
        http = MagicMock()
        cfg = MagicMock(SMS_PROVIDER="5sim", SMS_MAX_RETRIES=1, SMS_CODE_WAIT=30, SMS_POLL_INTERVAL=2)
        phone_fill = {
            "e164": "+306997751178", "actualVisible": "6997751178",
            "hiddenValue": "+306997751178", "dialCode": "30",
            "selectedText": "希腊 (+30)", "selectedChanged": True,
        }
        verified = {"visibleValue": "6997751178", "hiddenValue": "+306997751178"}

        with ExitStack() as stack:
            stack.enter_context(patch.object(roxy_codex_oauth.sms_provider, "_cfg", cfg))
            stack.enter_context(patch.object(roxy_codex_oauth.sms_provider, "_http", return_value=http))
            stack.enter_context(patch.object(roxy_codex_oauth.sms_provider, "acquire_number", return_value=("activation-1", "306997751178")))
            stack.enter_context(patch.object(roxy_codex_oauth.sms_provider, "set_status"))
            stack.enter_context(patch.object(roxy_codex_oauth.sms_provider, "wait_for_sms_code", return_value="123456"))
            complete = stack.enter_context(patch.object(roxy_codex_oauth.sms_provider, "complete"))
            cancel = stack.enter_context(patch.object(roxy_codex_oauth.sms_provider, "cancel"))
            stack.enter_context(patch.object(roxy_codex_oauth, "_has_strict_add_phone_form", return_value=True))
            stack.enter_context(patch.object(roxy_codex_oauth, "_ensure_add_phone_input"))
            refresh = stack.enter_context(patch.object(roxy_codex_oauth, "_refresh_add_phone_for_retry"))
            select_country = stack.enter_context(patch.object(
                roxy_codex_oauth, "_select_phone_country_from_number",
                return_value={"ok": True, "code": "30", "text": "希腊 (+30)"},
            ))
            set_phone = stack.enter_context(patch.object(roxy_codex_oauth, "_set_phone_value", return_value=phone_fill))
            stack.enter_context(patch.object(roxy_codex_oauth, "_verify_add_phone_value_before_submit", return_value=verified))
            stack.enter_context(patch.object(roxy_codex_oauth, "_select_sms_channel_or_raise"))
            stack.enter_context(patch.object(roxy_codex_oauth, "_blur_active_input_and_wait"))
            stack.enter_context(patch.object(roxy_codex_oauth, "_click_add_phone_continue_button", return_value={"ok": True}))
            stack.enter_context(patch.object(roxy_codex_oauth, "_wait_page_settle_after_submit"))
            stack.enter_context(patch.object(
                roxy_codex_oauth, "_wait_after_phone_send",
                side_effect=[RuntimeError("phone_required: 電話號碼為必填項目"), "code_page"],
            ))
            stack.enter_context(patch.object(roxy_codex_oauth, "_type_otp"))
            stack.enter_context(patch.object(roxy_codex_oauth, "_click_if_present", return_value=True))
            stack.enter_context(patch.object(roxy_codex_oauth, "_wait_after_phone_otp_submit", return_value="callback"))
            stack.enter_context(patch.object(roxy_codex_oauth, "human_delay"))
            roxy_codex_oauth._do_phone_verification_if_present(driver)

        self.assertEqual(select_country.call_count, 2)
        self.assertEqual(set_phone.call_count, 2)
        refresh.assert_called_once()
        cancel.assert_not_called()
        complete.assert_called_once_with("activation-1", http)

    def test_custom_country_dropdown_selects_longest_matching_dial_code(self):
        driver = MagicMock()
        driver.execute_script.side_effect = [
            {"ok": False, "custom": True, "opened": True, "digits": "48600123456", "currentCode": "1"},
            {"ok": True, "custom": True, "code": "48", "text": "波兰 (+48)"},
        ]

        with patch.object(roxy_codex_oauth.time, "sleep"):
            result = roxy_codex_oauth._select_phone_country_from_number(driver, "+48600123456")

        self.assertEqual(result["code"], "48")
        self.assertEqual(result["text"], "波兰 (+48)")
        self.assertEqual(driver.execute_script.call_count, 2)

    def test_inline_twofa_config_present_and_default_enabled(self):
        from config import twofa as twofa_cfg
        self.assertTrue(hasattr(twofa_cfg, "TWOFA_INLINE_WITH_REGISTRATION"))
        self.assertFalse(bool(getattr(twofa_cfg, "TWOFA_INLINE_WITH_REGISTRATION")))


class AntBrowserEmailSubmitConfirmationTests(unittest.TestCase):
    def _driver(self, url):
        driver = AntBrowserSeleniumDriver.__new__(AntBrowserSeleniumDriver)
        driver.page = MagicMock()
        driver.page.url = url
        return driver

    def test_native_state_reports_chrome_error_as_navigation_error(self):
        driver = self._driver("chrome-error://chromewebdata/")
        state = driver.email_submit_state_native("user@example.com")
        self.assertEqual(state["state"], "navigation_error")
        self.assertEqual(state["error"], "browser_navigation_failed")
        driver.page.locator.assert_not_called()

    def test_native_state_reports_blank_page_as_navigation_error(self):
        driver = self._driver("about:blank")
        state = driver.email_submit_state_native("user@example.com")
        self.assertEqual(state["state"], "navigation_error")

    def test_wait_email_submit_fails_immediately_on_navigation_error(self):
        driver = MagicMock()
        driver.email_submit_state_native.return_value = {
            "url": "chrome-error://chromewebdata/",
            "state": "navigation_error",
            "inputs": [],
            "error": "browser_navigation_failed",
        }
        with patch.object(roxy_registration.time, "sleep") as sleeper:
            with self.assertRaisesRegex(RuntimeError, "navigation_error"):
                roxy_registration._wait_email_submit_next_state(driver, "user@example.com", timeout=20)
        sleeper.assert_not_called()

    def test_wait_email_submit_no_inputs_does_not_raise_unbound_debounce(self):
        driver = MagicMock(spec=["current_url", "execute_script"] )
        driver.current_url = "https://chatgpt.com/auth/login?email=user%40example.com"
        driver.execute_script.return_value = {
            "url": driver.current_url,
            "inputs": [],
        }
        clock = {"value": -1.0}
        def tick():
            clock["value"] += 1.0
            return clock["value"]
        with patch.object(roxy_registration.time, "time", side_effect=tick), \
             patch.object(roxy_registration.time, "sleep"), \
             patch.object(roxy_registration, "_has_access_token", return_value=False), \
             patch.object(roxy_registration, "_is_login_password_page", return_value=False), \
             patch.object(roxy_registration, "_is_email_verification_page", return_value=False), \
             patch.object(roxy_registration, "_is_signup_password_page", return_value=False), \
             patch.object(roxy_registration, "_is_invalid_authorize_page", return_value=False), \
             patch.object(roxy_registration, "_recover_email_submit_if_stuck", return_value={"ok": False}):
            state = roxy_registration._wait_email_submit_next_state(
                driver, "user@example.com", timeout=18
            )
        self.assertEqual(state, "email_cleared")

    def test_type_otp_rejects_chrome_error_before_dom_lookup(self):
        driver = MagicMock()
        driver.current_url = "chrome-error://chromewebdata/"
        with self.assertRaisesRegex(RuntimeError, "navigation_error"):
            roxy_registration._type_otp(driver, "123456")
        driver.page.locator.assert_not_called()

    def test_submit_email_step_rejects_unconfirmed_native_submit(self):
        driver = MagicMock()
        driver.submit_email_native.return_value = {
            "ok": False,
            "reason": "email_submit_not_confirmed",
        }
        with patch.object(roxy_registration, "_maybe_accept"), patch.object(
            roxy_registration, "_stabilize_email_input_before_submit", return_value={"ok": True}
        ), patch.object(roxy_registration.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "邮箱提交未确认页面迁移"):
                roxy_registration._submit_email_step(driver, "user@example.com")


if __name__ == "__main__":
    unittest.main()
