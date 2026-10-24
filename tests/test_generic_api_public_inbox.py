# -*- coding: utf-8 -*-
import json
import unittest
from unittest.mock import patch

from core.generic_api_mail_client import (
    GenericApiEmailAccount,
    _extract_embedded_messages_code,
    _extract_html_card_messages_code,
    _extract_structured_api_code,
    _public_inbox_latest_code_url,
    fetch_latest_otp,
)


def test_embedded_mailalias_page_prefers_explicit_message_code():
    html = '''<!doctype html><html><body>
    <div>剩余 00:09:28</div><script>const stale = "890928";</script>
    <pre>{"messages":[{"id":"m1","date":"2026-10-07T15:09:14.000Z",
    "preview":"ChatGPT code 493159","code":"493159"}],"total":1}</pre>
    </body></html>'''
    result = _extract_embedded_messages_code(html)
    assert result is not None
    assert result[0] == "493159"
    assert result[1]["source"] == "embedded_messages_json"



def test_html_mailbox_card_extracts_nested_openai_message_with_after_ts():
    html = """<!doctype html><html><body>
    <div class="card"><div class="dt">Sat, 17 Oct 2026 13:19:31 +0000 (UTC)</div>
    <div class="bd"><html><body>
    <p>この一時検証コードを入力して続行してください:</p><strong>133487</strong>
    </body></html></div></div></body></html>"""
    result = _extract_html_card_messages_code(html, after_ts=1792242900.0)
    assert result is not None
    assert result[0] == "133487"
    assert result[1]["source"] == "html_card_message"

def test_messages_api_uses_newest_code_after_request_time():
    payload = {"messages": [
        {"id": "old", "subject": "Your ChatGPT code", "text": "Code: 111111", "createdAt": "2026-09-19T06:00:00Z"},
        {"id": "new", "subject": "Your ChatGPT code", "text": "Code: 654321", "createdAt": "2026-09-19T07:05:00Z"},
    ]}
    result = _extract_structured_api_code(
        json.dumps(payload), after_ts=1758265200.0,
    )
    assert result is not None
    assert result[0] == "654321"
    assert result[1]["source"] == "messages_api"


class _Response:
    status_code = 200

    def __init__(self, payload):
        self._payload = payload
        self.text = json.dumps(payload, ensure_ascii=False)

    def json(self):
        return self._payload


class _Session:
    def __init__(self):
        self.urls = []
        self.proxies = {}
        self.trust_env = True

    def get(self, url, **_kwargs):
        self.urls.append(url)
        return _Response({
            "mailbox": {"address": "inbox-0141-d678@071898.7bcb28.221wx.com"},
            "messages": [{
                "id": "msg_01",
                "receivedAt": "2026-09-06T12:00:00.000Z",
                "subject": "ChatGPT の一時的な認証コード",
                # 该站点日文邮件 verificationCodes 可能为空，但页面 preview 已有验证码。
                "verificationCodes": [],
                "preview": "この一時検証コードを入力して続行してください: 739201 ChatGPT",
                "fromAddress": "service@example.com",
            }],
        })


class _PlaceholderThenCodeSession(_Session):
    def __init__(self):
        super().__init__()
        self.calls = 0

    def get(self, url, **_kwargs):
        self.urls.append(url)
        self.calls += 1
        code = "000000" if self.calls == 1 else "739201"
        return _Response({
            "mailbox": {"address": "inbox-0141-d678@071898.7bcb28.221wx.com"},
            "messages": [{
                "id": f"msg_{self.calls}",
                "receivedAt": "2026-09-06T12:00:00.000Z",
                "subject": "ChatGPT verification code",
                "preview": f"Your verification code is {code}",
                "verificationCodes": [code],
            }],
        })


class GenericApiPublicInboxTests(unittest.TestCase):
    def test_fetch_latest_otp_ignores_zero_placeholder_until_real_code_arrives(self):
        email = "inbox-0141-d678@071898.7bcb28.221wx.com"
        account = GenericApiEmailAccount(
            email=email,
            code_url="https://mail.knm03.com/i/HTOJyWzFuVXC",
        )
        session = _PlaceholderThenCodeSession()
        with patch("core.generic_api_mail_client.get_account_context", return_value=account), \
             patch("core.generic_api_mail_client.requests.Session", return_value=session):
            code = fetch_latest_otp(
                email,
                max_wait=2,
                poll_interval=0.01,
                settle_seconds=0,
            )

        self.assertEqual(code, "739201")
        self.assertEqual(session.calls, 2)

    def test_public_link_is_converted_to_latest_code_api(self):
        self.assertEqual(
            _public_inbox_latest_code_url("https://mail.knm03.com/i/HTOJyWzFuVXC"),
            "https://mail.knm03.com/api/public/inboxes/HTOJyWzFuVXC/latest-code",
        )

    def test_direct_latest_code_api_is_also_accepted(self):
        url = "https://mail.knm03.com/api/public/inboxes/HTOJyWzFuVXC/latest-code"
        self.assertEqual(_public_inbox_latest_code_url(url), url)

    def test_fetch_latest_otp_uses_public_inbox_api(self):
        email = "inbox-0141-d678@071898.7bcb28.221wx.com"
        account = GenericApiEmailAccount(
            email=email,
            code_url="https://mail.knm03.com/i/HTOJyWzFuVXC",
        )
        session = _Session()
        with patch("core.generic_api_mail_client.get_account_context", return_value=account), \
             patch("core.generic_api_mail_client.requests.Session", return_value=session):
            code = fetch_latest_otp(
                email,
                after_ts=1788690000,
                max_wait=2,
                poll_interval=0.01,
                settle_seconds=0,
            )
        self.assertEqual(code, "739201")
        self.assertEqual(len(session.urls), 1)
        self.assertTrue(session.urls[0].startswith(
            "https://mail.knm03.com/api/public/inboxes/HTOJyWzFuVXC?"
        ))
        self.assertFalse(session.trust_env)

    def test_fetch_latest_otp_applies_proxy_pool_route(self):
        email = "inbox-0141-d678@071898.7bcb28.221wx.com"
        account = GenericApiEmailAccount(email=email, code_url="https://mail.knm03.com/i/token")
        session = _Session()
        proxy = "socks5://user:secret@127.0.0.1:7897"
        with patch("core.generic_api_mail_client.get_account_context", return_value=account), \
             patch("core.generic_api_mail_client._proxy_cfg.pick_proxy", return_value=proxy), \
             patch("core.generic_api_mail_client._email_cfg.GENERIC_API_MAIL_PROXY_MODE", "proxy_first"), \
             patch("core.generic_api_mail_client.requests.Session", return_value=session):
            code = fetch_latest_otp(email, max_wait=2, poll_interval=0.01, settle_seconds=0)
        self.assertEqual(code, "739201")
        self.assertEqual(session.proxies, {"http": proxy, "https": proxy})

    def test_proxy_connection_error_falls_back_to_direct(self):
        email = "inbox-0141-d678@071898.7bcb28.221wx.com"
        account = GenericApiEmailAccount(email=email, code_url="https://mail.knm03.com/i/token")
        proxy_session = _Session()
        direct_session = _Session()

        def proxy_failure(_url, **_kwargs):
            import requests
            raise requests.ConnectionError("proxy reset")

        proxy_session.get = proxy_failure
        with patch("core.generic_api_mail_client.get_account_context", return_value=account), \
             patch("core.generic_api_mail_client._proxy_cfg.pick_proxy", return_value="socks5://127.0.0.1:7897"), \
             patch("core.generic_api_mail_client._email_cfg.GENERIC_API_MAIL_PROXY_MODE", "proxy_first"), \
             patch("core.generic_api_mail_client.requests.Session", side_effect=[proxy_session, direct_session]):
            code = fetch_latest_otp(email, max_wait=2, poll_interval=0.01, settle_seconds=0)
        self.assertEqual(code, "739201")
        self.assertEqual(proxy_session.proxies["https"], "socks5://127.0.0.1:7897")
        self.assertEqual(direct_session.proxies, {})
        self.assertFalse(direct_session.trust_env)

    def test_fetch_latest_otp_defaults_to_direct_route(self):
        email = "inbox-0141-d678@071898.7bcb28.221wx.com"
        account = GenericApiEmailAccount(email=email, code_url="https://mail.knm03.com/i/token")
        direct_session = _Session()
        proxy = "socks5://user:secret@127.0.0.1:7897"
        with patch("core.generic_api_mail_client.get_account_context", return_value=account), \
             patch("core.generic_api_mail_client._proxy_cfg.pick_proxy", return_value=proxy), \
             patch("core.generic_api_mail_client.requests.Session", return_value=direct_session):
            code = fetch_latest_otp(email, max_wait=2, poll_interval=0.01, settle_seconds=0)
        self.assertEqual(code, "739201")
        self.assertEqual(direct_session.proxies, {})
        self.assertFalse(direct_session.trust_env)


if __name__ == "__main__":
    unittest.main()
