from unittest.mock import patch
import pytest
from core import headless_routing as routing

@pytest.mark.parametrize("mode,cfg,expected", [
    ("roxy", (True, False), "ant"),
    ("cloak", (False, True), "ant"),
    ("roxy", (False, True), "roxy"),
    ("cloak", (True, False), "cloak"),
    ("protocol", (True, True), "protocol"),
])
def test_task_routing(mode, cfg, expected):
    from config import roxybrowser, cloakbrowser
    with patch.object(roxybrowser, "ROXY_OPEN_HEADLESS", cfg[0]), patch.object(cloakbrowser, "CLOAK_HEADLESS", cfg[1]):
        assert routing.registration_driver(mode) == expected
        assert routing.oauth_driver(mode) == expected

@pytest.mark.parametrize("mode", ["roxy", "cloak"])
def test_direct_registration_headless_calls_ant(mode):
    if mode == "roxy":
        from core import roxy_registration as registration
        from config import roxybrowser as cfg
        flag = "ROXY_OPEN_HEADLESS"
        fn = registration.run_roxy_registration
    else:
        from core import cloakbrowser_registration as registration
        from config import cloakbrowser as cfg
        flag = "CLOAK_HEADLESS"
        fn = registration.run_cloak_registration
    with patch.object(cfg, flag, True), patch("core.antbrowser_registration.run_ant_registration", return_value={"ok": True}) as ant:
        assert fn(email="e@example.test", name="Name", birthday="2000-01-01", proxy="", otp_code=None) == {"ok": True}
        assert ant.call_args.kwargs["force_headless"] is True

@pytest.mark.parametrize("mode", ["roxy", "cloak"])
def test_non_ant_headless_is_rejected_before_launch(mode):
    if mode == "roxy":
        from core.roxybrowser_client import RoxyBrowserClient
        from config import roxybrowser as cfg
        with patch.object(cfg, "ROXY_OPEN_HEADLESS", True):
            with pytest.raises(RuntimeError, match="Ant"):
                RoxyBrowserClient().open_profile()
    else:
        from core.cloakbrowser_driver import build_cloak_driver
        from config import cloakbrowser as cfg
        with patch.object(cfg, "CLOAK_HEADLESS", True):
            with pytest.raises(RuntimeError, match="Ant"):
                build_cloak_driver(proxy="")
