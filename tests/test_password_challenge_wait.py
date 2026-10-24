from unittest.mock import patch

from core import roxy_registration as registration


def test_visible_login_challenge_can_last_longer_than_35_seconds():
    clock = [0.0]
    titles = [0]
    field = object()

    class Page:
        frames = []

        def title(self):
            titles[0] += 1
            return "しばらくお待ちください" if clock[0] < 43 else "Sign in"

    class Driver:
        page = Page()

    def advance(seconds):
        clock[0] += seconds

    with patch.object(registration.time, "time", side_effect=lambda: clock[0]), \
         patch.object(registration.time, "sleep", side_effect=advance), \
         patch.object(registration, "_check_manual_stop"), \
         patch.object(registration, "_find_visible_email_input_js", return_value=field):
        assert registration._wait_for_email_input(Driver(), timeout=90) is field
    assert clock[0] >= 43
    assert titles[0] > 35


def test_headed_challenge_waits_for_manual_completion_and_reports_progress():
    clock = [0.0]
    updates = []
    field = object()

    class Page:
        frames = []

        def title(self):
            return "Just a moment" if clock[0] < 110 else "Sign in"

    class Driver:
        page = Page()
        _manual_challenge_wait = True
        _manual_challenge_timeout = 150
        _challenge_progress = updates.append

    def advance(seconds):
        clock[0] += seconds

    with patch.object(registration.time, "time", side_effect=lambda: clock[0]), \
         patch.object(registration.time, "sleep", side_effect=advance), \
         patch.object(registration, "_check_manual_stop"), \
         patch.object(registration, "_find_visible_email_input_js", return_value=field):
        assert registration._wait_for_email_input(Driver(), timeout=45) is field
    assert clock[0] >= 110
    assert len(updates) >= 3
    assert all("window remains open" in item for item in updates)


def test_password_page_interrupts_stale_challenge_wait():
    class Page:
        frames = []
        def title(self):
            return "Just a moment"

    class Driver:
        page = Page()
        current_url = "https://auth.openai.com/log-in/password"
        _manual_challenge_wait = True
        _manual_challenge_timeout = 300

    with patch.object(registration, "_check_manual_stop"), \
         patch.object(registration, "_find_visible_email_input_js") as find_email:
        try:
            registration._wait_for_email_input(Driver(), timeout=45)
        except registration._LoginPasswordPageReached:
            pass
        else:
            raise AssertionError("password page was not recognized")
        find_email.assert_not_called()


def test_email_transition_to_password_returns_immediately_for_login():
    class Driver:
        current_url = "https://auth.openai.com/auth/login"

    with patch.object(registration, "_is_email_verification_page", return_value=False), \
         patch.object(registration, "_is_signup_password_page", return_value=False), \
         patch.object(registration, "_is_login_password_page", return_value=False), \
         patch.object(registration, "_has_access_token", return_value=False), \
         patch.object(registration, "_type_email_address", side_effect=registration._LoginPasswordPageReached("advanced")):
        assert registration._submit_email_and_wait_next(Driver(), "test@example.com", allow_login_password=True) == "login_password"


def test_password_page_stall_does_not_claim_reauthentication():
    from unittest.mock import MagicMock
    from core import roxy_codex_oauth as flow
    clock = [0.0]
    driver = MagicMock()
    driver.signup_password_targets_native.return_value = {"ok": True, "input": object(), "button": object()}
    driver.page_source = "Password"
    def advance(seconds):
        clock[0] += seconds
    with patch.object(flow.time, "time", side_effect=lambda: clock[0]), \
         patch.object(flow.time, "sleep", side_effect=advance), \
         patch.object(flow, "_account_password_for_email", return_value="test-password"), \
         patch.object(flow, "_is_mfa_challenge_page", return_value=False), \
         patch.object(flow, "_is_email_verification_page", return_value=False), \
         patch.object(flow, "_is_login_password_page", return_value=True), \
         patch.object(flow, "_human_type_text"), \
         patch.object(flow, "_human_click") as click, \
         patch.object(flow, "human_delay"):
        assert flow._fill_login_password_if_present(driver, "test@example.com", timeout=18) == "password_page_stalled"
        click.assert_called_once()

def test_stalled_password_page_does_not_enter_otp_or_report_success():
    from unittest.mock import MagicMock
    from core import roxy_codex_oauth as flow
    driver = MagicMock()
    updates = []
    with patch.object(flow, "_open_auth_url"), \
         patch.object(flow, "human_delay"), \
         patch.object(flow, "_maybe_accept"), \
         patch.object(flow, "_click_reset_password_continue", return_value=False), \
         patch.object(flow, "_submit_email_and_wait_next", return_value="login_password"), \
         patch.object(flow, "_fill_login_password_if_present", return_value="password_page_stalled"), \
         patch.object(flow, "_maybe_click_passwordless_after_email") as passwordless:
        try:
            flow._fill_email_and_otp(driver, "test@example.com", None, "https://auth.openai.com/", progress_callback=lambda *a: updates.append(a[0]))
        except RuntimeError as exc:
            assert "password_page_stalled" in str(exc)
        else:
            raise AssertionError("stalled page must fail as unverified")
        passwordless.assert_not_called()
    assert "password_page_stalled" in updates
    assert "reauthenticated" not in updates
