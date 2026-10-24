# -*- coding: utf-8 -*-
import unittest
from unittest.mock import patch

from core import sms_provider
from config import codex as codex_config
from config import env_loader
from webui import config_editor


class _Resp:
    def __init__(self, data=None, status_code=200, text=""):
        self.status_code = status_code
        self._data = data if data is not None else {}
        self.text = text or (str(data) if data is not None else "{}")

    def json(self):
        return self._data


class _Http:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.closed = False

    def get(self, url, headers=None):
        self.calls.append({"method": "GET", "url": url, "headers": headers or {}})
        return self.responses.pop(0)

    def close(self):
        self.closed = True


class FiveSimProviderTests(unittest.TestCase):
    def test_secret_registry_and_webui_fields_include_5sim(self):
        self.assertIn("FIVESIM_API_KEY", env_loader.SECRET_ENV_KEYS)
        fields = {f["key"]: f for f in config_editor.EDITABLE_FIELDS}
        self.assertIn("FIVESIM_API_KEY", fields)
        self.assertIn("FIVESIM_COUNTRY", fields)
        self.assertIn("FIVESIM_OPERATOR", fields)
        self.assertIn("FIVESIM_PRODUCT", fields)
        self.assertTrue(fields["FIVESIM_API_KEY"].get("secret"))

    def test_acquire_number_5sim_success(self):
        resp_data = {
            "id": 98765432,
            "phone": "+447123456789",
            "operator": "any",
            "product": "openai",
            "price": 10.5,
            "status": "PENDING",
            "expires": "2026-09-24T12:00:00Z",
            "country": "england",
        }
        http = _Http([_Resp(data=resp_data, status_code=200, text="ok")])
        with patch.object(codex_config, "SMS_PROVIDER", "5sim"), \
             patch.object(codex_config, "FIVESIM_API_KEY", "test_5sim_token_xyz"), \
             patch.object(codex_config, "FIVESIM_COUNTRY", "england"), \
             patch.object(codex_config, "FIVESIM_OPERATOR", "any"), \
             patch.object(codex_config, "FIVESIM_PRODUCT", "openai"):
            activation_id, phone = sms_provider.acquire_number(http=http)

        self.assertEqual(activation_id, "98765432")
        self.assertEqual(phone, "447123456789")
        self.assertEqual(len(http.calls), 1)
        call = http.calls[0]
        self.assertTrue(call["url"].endswith("/v1/user/buy/activation/england/any/openai"))
        self.assertEqual(call["headers"].get("Authorization"), "Bearer test_5sim_token_xyz")

    def test_acquire_number_5sim_no_free_phones(self):
        http = _Http([_Resp(status_code=400, text="no free phones")])
        with patch.object(codex_config, "SMS_PROVIDER", "5sim"), \
             patch.object(codex_config, "FIVESIM_API_KEY", "test_token"), \
             patch.object(codex_config, "FIVESIM_COUNTRY", "any"), \
             patch.object(codex_config, "FIVESIM_PRODUCT", "openai"):
            with self.assertRaises(sms_provider.SmsNoNumbersError):
                sms_provider.acquire_number(http=http)

    def test_acquire_number_5sim_no_balance(self):
        http = _Http([_Resp(status_code=400, text="not enough user balance")])
        with patch.object(codex_config, "SMS_PROVIDER", "5sim"), \
             patch.object(codex_config, "FIVESIM_API_KEY", "test_token"), \
             patch.object(codex_config, "FIVESIM_COUNTRY", "any"), \
             patch.object(codex_config, "FIVESIM_PRODUCT", "openai"):
            with self.assertRaises(sms_provider.SmsNoBalanceError):
                sms_provider.acquire_number(http=http)

    def test_wait_for_sms_code_5sim_direct_code(self):
        resp_data = {
            "id": 98765432,
            "phone": "+447123456789",
            "status": "RECEIVED",
            "sms": [
                {
                    "created_at": "2026-09-24T12:01:00Z",
                    "date": "2026-09-24T12:01:00Z",
                    "sender": "OpenAI",
                    "text": "Your OpenAI verification code is 123456",
                    "code": "123456",
                }
            ],
        }
        http = _Http([_Resp(data=resp_data, status_code=200)])
        with patch.object(codex_config, "SMS_PROVIDER", "5sim"), \
             patch.object(codex_config, "FIVESIM_API_KEY", "test_token"):
            code = sms_provider.wait_for_sms_code("98765432", http=http, max_wait=2, poll_interval=0)

        self.assertEqual(code, "123456")
        self.assertTrue(http.calls[0]["url"].endswith("/v1/user/check/98765432"))

    def test_wait_for_sms_code_5sim_extract_code_from_text(self):
        resp_data = {
            "id": 98765432,
            "status": "RECEIVED",
            "sms": [
                {
                    "sender": "OpenAI",
                    "text": "Your security code is 654321.",
                    "code": None,
                }
            ],
        }
        http = _Http([_Resp(data=resp_data, status_code=200)])
        with patch.object(codex_config, "SMS_PROVIDER", "5sim"), \
             patch.object(codex_config, "FIVESIM_API_KEY", "test_token"):
            code = sms_provider.wait_for_sms_code("98765432", http=http, max_wait=2, poll_interval=0)

        self.assertEqual(code, "654321")

    def test_complete_5sim_calls_finish(self):
        http = _Http([_Resp(data={"id": 98765432, "status": "FINISHED"}, status_code=200)])
        with patch.object(codex_config, "SMS_PROVIDER", "5sim"), \
             patch.object(codex_config, "FIVESIM_API_KEY", "test_token"):
            sms_provider.complete("98765432", http=http)

        self.assertEqual(len(http.calls), 1)
        self.assertTrue(http.calls[0]["url"].endswith("/v1/user/finish/98765432"))
        self.assertEqual(http.calls[0]["headers"].get("Authorization"), "Bearer test_token")

    def test_cancel_5sim_calls_cancel(self):
        http = _Http([_Resp(data={"id": 98765432, "status": "CANCELED"}, status_code=200)])
        with patch.object(codex_config, "SMS_PROVIDER", "5sim"), \
             patch.object(codex_config, "FIVESIM_API_KEY", "test_token"):
            sms_provider.cancel("98765432", http=http, background=False)

        self.assertEqual(len(http.calls), 1)
        self.assertTrue(http.calls[0]["url"].endswith("/v1/user/cancel/98765432"))
        self.assertEqual(http.calls[0]["headers"].get("Authorization"), "Bearer test_token")


    def test_5sim_reuse_two_accounts_flow(self):
        # 1. 模拟买号
        buy_resp = {
            "id": 11002233,
            "phone": "+18005550199",
            "operator": "any",
            "product": "openai",
            "country": "usa",
        }
        # 第 1 个账号获取验证码返回 123456
        check_resp_1 = {
            "status": "RECEIVED",
            "sms": [{"code": "123456", "text": "Your OpenAI code is 123456"}],
        }
        # 第 2 个账号获取验证码返回两条短信（历史 123456 和 新码 654321）
        check_resp_2 = {
            "status": "RECEIVED",
            "sms": [
                {"code": "123456", "text": "Your OpenAI code is 123456"},
                {"code": "654321", "text": "Your OpenAI code is 654321"},
            ],
        }
        finish_resp = {"status": "FINISHED"}

        http = _Http([
            _Resp(data=buy_resp, status_code=200),
            _Resp(data=check_resp_1, status_code=200),
            _Resp(data=check_resp_2, status_code=200),
            _Resp(data=finish_resp, status_code=200),
        ])

        with patch.object(codex_config, "SMS_PROVIDER", "5sim"), \
             patch.object(codex_config, "FIVESIM_API_KEY", "tok"), \
             patch.object(codex_config, "SMS_REUSE_MAX_ACCOUNTS", 2), \
             patch.object(codex_config, "SMS_REUSE_EXPIRE_SECONDS", 600), \
             patch.object(sms_provider, "_REUSABLE_QUEUE", []), \
             patch.object(sms_provider, "_ACTIVE_SESSIONS", {}):

            # 账号 1 取号
            aid1, phone1 = sms_provider.acquire_number(http=http)
            self.assertEqual(aid1, "11002233")
            self.assertEqual(phone1, "18005550199")

            # 账号 1 等码
            code1 = sms_provider.wait_for_sms_code(aid1, http=http, max_wait=5, poll_interval=1)
            self.assertEqual(code1, "123456")

            # 账号 1 成功完成验证（不应关闭订单，而是放回复用池）
            sms_provider.complete(aid1, http=http)
            self.assertEqual(len(sms_provider._REUSABLE_QUEUE), 1)
            self.assertEqual(sms_provider._REUSABLE_QUEUE[0].activation_id, "11002233")

            # 账号 2 取号（应命中复用池，不发买号请求）
            aid2, phone2 = sms_provider.acquire_number(http=http)
            self.assertEqual(aid2, "11002233")
            self.assertEqual(phone2, "18005550199")

            # 账号 2 等码（应自动跳过历史 123456，精准拿到 654321）
            code2 = sms_provider.wait_for_sms_code(aid2, http=http, max_wait=5, poll_interval=1)
            self.assertEqual(code2, "654321")

            # 账号 2 成功完成验证（达到 2 次上限，正式 finish 订单）
            sms_provider.complete(aid2, http=http)
            self.assertEqual(len(sms_provider._REUSABLE_QUEUE), 0)
            # 确认最后调用了 finish 接口
            self.assertTrue(http.calls[-1]["url"].endswith("/v1/user/finish/11002233"))


if __name__ == "__main__":
    unittest.main()
