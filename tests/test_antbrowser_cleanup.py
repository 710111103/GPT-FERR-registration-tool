# -*- coding: utf-8 -*-
import unittest
from contextlib import closing
import tempfile
from pathlib import Path
from core import ant_cleanup_journal
from types import SimpleNamespace
from unittest.mock import patch

from core import antbrowser_driver


class AntBrowserCleanupTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        patcher = patch.object(ant_cleanup_journal,"_PATH",Path(temp.name)/"cleanup.sqlite3")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_playwright_ephemeral_profile_is_stopped_and_deleted(self):
        opened = SimpleNamespace(raw={
            "driver": "playwright",
            "ephemeral": True,
            "api_base": "http://127.0.0.1:19876",
            "profile_id": "profile-123",
        })

        with patch.object(antbrowser_driver._cfg, "ANT_DELETE_AFTER_RUN", True), \
             patch.object(antbrowser_driver, "_ant_json") as ant_json:
            ant_json.side_effect = [
                {},
                {"running": False, "debugReady": False, "cdpUrl": "", "directDebugUrl": ""},
                {},
                RuntimeError("API 404: profile not found"),
            ]

            antbrowser_driver.cleanup_ant_profile(opened)

        self.assertEqual(ant_json.call_count, 4)
        self.assertEqual(ant_json.call_args_list[0].args, (
            "POST", "http://127.0.0.1:19876/api/profiles/profile-123/stop"
        ))
        self.assertEqual(ant_json.call_args_list[2].args, (
            "DELETE", "http://127.0.0.1:19876/api/profiles/profile-123"
        ))


    def test_already_removed_profile_is_success_and_cache_proxy_stops(self):
        proxy = unittest.mock.Mock()
        opened = SimpleNamespace(raw={"ephemeral": True, "profile_id": "gone", "static_asset_proxy": proxy})
        with patch.object(antbrowser_driver._cfg, "ANT_DELETE_AFTER_RUN", True), patch.object(antbrowser_driver, "_ant_json", side_effect=RuntimeError('Ant Browser API POST 404: {"error":"profile not found"}')) as api:
            antbrowser_driver.cleanup_ant_profile(opened)
        self.assertEqual(api.call_count, 1)
        proxy.stop.assert_called_once()

    def test_other_errors_are_not_reported_as_deleted(self):
        opened = SimpleNamespace(raw={"ephemeral": True, "profile_id": "retain"})
        with patch.object(antbrowser_driver._cfg, "ANT_DELETE_AFTER_RUN", True), patch.object(antbrowser_driver, "_ant_json", side_effect=RuntimeError("API 403 forbidden")):
            with self.assertRaisesRegex(RuntimeError, "403"):
                antbrowser_driver.cleanup_ant_profile(opened)

    def test_user_owned_profile_is_not_deleted(self):
        opened = SimpleNamespace(raw={"ephemeral": False, "profile_id": "user"})
        with patch.object(antbrowser_driver, "_ant_json") as api:
            antbrowser_driver.cleanup_ant_profile(opened)
        api.assert_not_called()


    def test_failure_is_durable_and_retry_confirms_deletion(self):
        opened=SimpleNamespace(raw={"ephemeral":True,"profile_id":"retry"})
        with patch.object(antbrowser_driver._cfg,"ANT_DELETE_AFTER_RUN",True), patch.object(antbrowser_driver,"_ant_json",side_effect=RuntimeError("API 503")):
            with self.assertRaisesRegex(RuntimeError,"503"):
                antbrowser_driver.cleanup_ant_profile(opened)
        with closing(ant_cleanup_journal.connect()) as c, c:
            row=c.execute("SELECT state,error FROM cleanup").fetchone()
            self.assertEqual(tuple(row),("pending","RuntimeError"))
            c.execute("UPDATE cleanup SET due=0");c.commit()
        with patch.object(antbrowser_driver._cfg,"ANT_DELETE_AFTER_RUN",True), patch.object(antbrowser_driver,"_ant_json",side_effect=[{}, {"running":False}, {},RuntimeError("API 404: profile not found")]) as api:
            ant_cleanup_journal.retry_pending()
            self.assertEqual(api.call_count,4)
        with closing(ant_cleanup_journal.connect()) as c, c:
            self.assertEqual(c.execute("SELECT state FROM cleanup").fetchone()[0],"done")

    def test_delete_acknowledgement_without_absence_stays_pending(self):
        opened=SimpleNamespace(raw={"ephemeral":True,"profile_id":"not-gone"})
        with patch.object(antbrowser_driver._cfg,"ANT_DELETE_AFTER_RUN",True), patch.object(antbrowser_driver,"time") as clock, patch.object(antbrowser_driver,"_ant_json",side_effect=[{}, {"running":False},{},{},{},{}]):
            clock.time.return_value=100
            with self.assertRaisesRegex(RuntimeError,"not confirmed"):
                antbrowser_driver.cleanup_ant_profile(opened)
        with closing(ant_cleanup_journal.connect()) as c, c:
            self.assertEqual(c.execute("SELECT state FROM cleanup").fetchone()[0],"pending")

    def test_quit_cleanup_precedes_cdp_shutdown(self):
        driver=antbrowser_driver.AntBrowserSeleniumDriver.__new__(antbrowser_driver.AntBrowserSeleniumDriver)
        driver._ant_cleanup_opened=SimpleNamespace(raw={"ephemeral":True})
        events=[]
        driver.context=SimpleNamespace(close=lambda:events.append("context"))
        driver.browser=SimpleNamespace(close=lambda:events.append("browser"))
        with patch.object(antbrowser_driver,"cleanup_ant_profile",side_effect=lambda _:events.append("cleanup")):
            driver.quit()
        self.assertEqual(events,["cleanup","context","browser"])

    def test_stop_invalid_argument_is_treated_as_already_inactive(self):
        opened=SimpleNamespace(raw={
            "ephemeral":True,"profile_id":"inactive",
            "api_base":"http://127.0.0.1:19876",
        })
        calls=[]
        deleted = {"done": False}
        def api(method, url, **kwargs):
            calls.append((method,url))
            if method == "POST" and url.endswith("/stop"):
                raise RuntimeError('Ant Browser API POST 500: {"error":"invalid argument","ok":false}')
            if method == "GET" and url.endswith("/status"):
                if deleted["done"]:
                    raise RuntimeError("Ant Browser API GET 404: profile not found")
                return {}
            if method == "DELETE":
                deleted["done"] = True
                return {}
            raise RuntimeError("Ant Browser API GET 404: profile not found")
        with patch.object(antbrowser_driver._cfg,"ANT_DELETE_AFTER_RUN",True), \
             patch.object(antbrowser_driver,"_ant_json",side_effect=api), \
             patch.object(antbrowser_driver.time,"sleep"):
            antbrowser_driver._cleanup_ant_profile_once(opened)
        self.assertIn(("DELETE","http://127.0.0.1:19876/api/profiles/inactive"), calls)

    def test_duplicate_cleanup_does_not_repeat_api_deletion(self):
        opened=SimpleNamespace(raw={"ephemeral":True,"profile_id":"once"})
        with patch.object(antbrowser_driver._cfg,"ANT_DELETE_AFTER_RUN",True), patch.object(antbrowser_driver,"_ant_json",side_effect=RuntimeError("API 404: profile not found")) as api:
            antbrowser_driver.cleanup_ant_profile(opened)
            antbrowser_driver.cleanup_ant_profile(opened)
        self.assertEqual(api.call_count,1)

    def test_browser_scope_closes_on_early_failure(self):
        from core.browser_environment import _browser_cleanup_scope
        browser = unittest.mock.Mock()
        with self.assertRaisesRegex(ValueError, "navigation failed"):
            with _browser_cleanup_scope() as owned:
                owned.append(browser)
                raise ValueError("navigation failed")
        browser.close.assert_called_once_with()

    def test_browser_scope_keeps_original_failure_when_cleanup_fails(self):
        from core.browser_environment import _browser_cleanup_scope
        browser = unittest.mock.Mock()
        browser.close.side_effect = RuntimeError("remote close failed")
        with self.assertRaisesRegex(ValueError, "navigation failed"):
            with _browser_cleanup_scope() as owned:
                owned.append(browser)
                raise ValueError("navigation failed")
        browser.close.assert_called_once_with()

    def test_active_owned_profile_is_never_returned_as_pending_cleanup(self):
        ant_cleanup_journal.record_owned("http://127.0.0.1:19876", "active-login")
        self.assertEqual(ant_cleanup_journal.pending(), [])
        with closing(ant_cleanup_journal.connect()) as c:
            row = c.execute(
                "SELECT state,owner_pid,due FROM cleanup WHERE profile_id=?",
                ("active-login",),
            ).fetchone()
        self.assertEqual(row["state"], "active")
        self.assertGreater(row["owner_pid"], 0)
        self.assertEqual(row["due"], 0)

    def test_live_claim_is_not_retried_until_lease_expires(self):
        self.assertTrue(ant_cleanup_journal.claim("http://127.0.0.1:19876","claim"))
        self.assertFalse(ant_cleanup_journal.claim("http://127.0.0.1:19876","claim"))
        self.assertEqual(ant_cleanup_journal.pending(),[])
        with closing(ant_cleanup_journal.connect()) as c, c:
            c.execute("UPDATE cleanup SET due=0");c.commit()
        self.assertEqual(len(ant_cleanup_journal.pending()),1)


if __name__ == "__main__":
    unittest.main()
