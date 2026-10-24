# -*- coding: utf-8 -*-
import unittest
from unittest.mock import patch

from core.roxybrowser_client import RoxyBrowserClient


class _OpenFailureClient(RoxyBrowserClient):
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.cleaned = []
        self._proxy_pool_target = ""
        self._proxy_pool_relay = None

    def create_profile(self, payload=None):
        return "orphan-123"

    def request(self, method, path, **kwargs):
        if self.error:
            raise self.error
        return self.result or {}

    def cleanup_profile(self, opened):
        self.cleaned.append((opened.profile_id, opened.created_by_run))


class RoxyProfileCleanupTests(unittest.TestCase):
    @patch("core.roxybrowser_client._cfg.ROXY_PROFILE_ID", "")
    @patch("core.roxybrowser_client._cfg.ROXY_ONE_PROFILE_PER_ACCOUNT", True)
    def test_created_profile_is_cleaned_when_open_request_fails(self):
        client = _OpenFailureClient(error=RuntimeError("open failed"))
        with self.assertRaisesRegex(RuntimeError, "open failed"):
            client._open_profile_locked()
        self.assertEqual(client.cleaned, [("orphan-123", True)])

    @patch("core.roxybrowser_client._cfg.ROXY_PROFILE_ID", "")
    @patch("core.roxybrowser_client._cfg.ROXY_ONE_PROFILE_PER_ACCOUNT", True)
    def test_created_profile_is_cleaned_when_open_response_has_no_endpoint(self):
        client = _OpenFailureClient(result={"code": 0, "data": {}})
        with self.assertRaisesRegex(RuntimeError, "未返回 Selenium/调试地址"):
            client._open_profile_locked()
        self.assertEqual(client.cleaned, [("orphan-123", True)])


if __name__ == "__main__":
    unittest.main()
