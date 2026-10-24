from unittest.mock import Mock, patch
from types import SimpleNamespace
import pytest
from core import browser_environment as env


def test_headless_context_uses_ant_and_cleans_up():
    context = Mock()
    browser = Mock()
    browser.new_context.return_value = context
    opened = SimpleNamespace(raw={"ephemeral": True}, profile_id="test-ant")
    driver = SimpleNamespace(browser=browser, quit=Mock())
    p = Mock()
    session = SimpleNamespace(browser_profile={}, proxy="http://127.0.0.1:3128")
    with patch("core.antbrowser_driver.build_ant_driver", return_value=(driver, opened)) as build, \
         patch("core.antbrowser_driver.cleanup_ant_profile") as cleanup, \
         patch("core.browser_data_saver.BrowserDataSaver") as saver:
        saver.return_value.enabled = False
        managed, result = env._create_stealth_context(p, session)
        assert result is context
        build.assert_called_once_with(proxy=session.proxy, force_headless=True, playwright_instance=p)
        p.chromium.launch.assert_not_called()
        managed.close()
        managed.close()
        driver.quit.assert_called_once()
        cleanup.assert_called_once_with(opened)


def test_headless_context_cleans_ant_on_context_creation_failure():
    browser = Mock()
    browser.new_context.side_effect = RuntimeError("context failed")
    driver = SimpleNamespace(browser=browser, quit=Mock())
    opened = SimpleNamespace(raw={"ephemeral": True})
    with patch("core.antbrowser_driver.build_ant_driver", return_value=(driver, opened)), \
         patch("core.antbrowser_driver.cleanup_ant_profile") as cleanup:
        with pytest.raises(RuntimeError, match="context failed"):
            env._create_stealth_context(Mock(), SimpleNamespace(browser_profile={}, proxy=None))
        driver.quit.assert_called_once()
        cleanup.assert_called_once_with(opened)
