# -*- coding: utf-8 -*-
import unittest
from unittest.mock import patch

from webui.app import create_app


class _CapturedThread:
    created = []

    def __init__(self, *, target=None, kwargs=None, name=None, daemon=None):
        self.target = target
        self.kwargs = kwargs or {}
        self.name = name
        self.daemon = daemon
        self.__class__.created.append(self)

    def start(self):
        return None


class WebUiCodexRtButtonTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app(auth_code="test-auth")
        self.client = self.app.test_client()
        self.client.post("/login", data={"auth_code": "test-auth", "next": "/"})
        _CapturedThread.created.clear()

    def test_page_contains_visible_get_rt_action(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("获取RT", response.get_data(as_text=True))

    def test_get_rt_button_uses_direct_visible_browser_route(self):
        account = {"id": 148, "email": "owner@example.test", "live_check_status": "live"}
        with (
            patch("webui.app.db.get_account_by_email", return_value=account),
            patch("webui.app.db.update_account_codex_status", return_value=True),
            patch("webui.app.codex_retry_service.reserve", return_value=True),
            patch("webui.app.threading.Thread", _CapturedThread),
        ):
            response = self.client.post(
                "/api/codex/retry",
                json={"email": account["email"], "browser_direct": True},
            )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["ok"])
        self.assertEqual(len(_CapturedThread.created), 1)
        self.assertEqual(_CapturedThread.created[0].kwargs["proxy"], "")


if __name__ == "__main__":
    unittest.main()
