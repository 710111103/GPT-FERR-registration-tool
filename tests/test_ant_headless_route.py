from unittest.mock import patch
from types import SimpleNamespace
import pytest
from core import antbrowser_driver as driver


def test_ant_headless_does_not_select_builtin_chromium_when_api_is_down():
    with patch.object(driver, "_build_standalone_playwright_driver") as builtin, \
         patch.object(driver, "_ant_json", side_effect=RuntimeError("offline")):
        with pytest.raises(RuntimeError, match="Ant local API unavailable"):
            driver.build_ant_driver(proxy="http://127.0.0.1:3128", force_headless=True, ant_headless=True)
        builtin.assert_not_called()


def test_default_headless_also_requires_ant():
    with patch.object(driver, "_build_standalone_playwright_driver") as builtin, \
         patch.object(driver, "_ant_json", side_effect=RuntimeError("offline")):
        with pytest.raises(RuntimeError, match="Ant local API unavailable"):
            driver.build_ant_driver(proxy="http://127.0.0.1:3128", force_headless=True)
        builtin.assert_not_called()


def test_unspecified_headless_never_falls_back_to_builtin():
    with patch.object(driver, "_build_standalone_playwright_driver") as builtin, \
         patch.object(driver, "_ant_json", side_effect=RuntimeError("offline")):
        with pytest.raises(RuntimeError, match="Ant local API unavailable"):
            driver.build_ant_driver(proxy="http://127.0.0.1:3128")
        builtin.assert_not_called()


def test_registration_headless_config_routes_to_ant():
    from core import antbrowser_registration as registration
    with patch.object(registration._cfg, "ANT_HEADLESS", True), \
         patch.object(registration, "build_ant_driver", return_value=(object(), object())) as build:
        registration._open_registration_browser("http://127.0.0.1:3128")
        build.assert_called_once_with(proxy="http://127.0.0.1:3128", force_headless=True)

def test_registration_headed_config_stays_headed():
    from core import antbrowser_registration as registration
    with patch.object(registration._cfg, "ANT_HEADLESS", False), \
         patch.object(registration, "build_ant_driver", return_value=(object(), object())) as build:
        registration._open_registration_browser(None)
        build.assert_called_once_with(proxy=None, force_headless=False)
