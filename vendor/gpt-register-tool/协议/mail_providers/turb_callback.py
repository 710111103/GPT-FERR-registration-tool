"""Isolated OSS task's loopback-only callback to the parent email router."""
import json
import time
from urllib.request import build_opener, ProxyHandler, Request
from .base import MailProvider, register


@register
class TurbCallbackProvider(MailProvider):
    kind = "turb_callback"
    display_name = "本地邮箱接码"
    pooled = False  # parent owns allocation and lifecycle, never touch upstream pool
    ephemeral = False
    accepts_existing_account = True

    def __init__(self, email, callback):
        self.email = email
        self.callback = callback

    @classmethod
    def from_config(cls, settings, account=None):
        account = account or {}
        return cls(account.get("email", ""), account.get("otp_callback") or {})

    def create_mailbox(self):
        return self.email

    def wait_for_otp(self, email_addr, timeout=120, issued_after=None):
        if email_addr.lower() != self.email.lower():
            raise ValueError("OTP 邮箱与任务不一致")
        cb = self.callback
        url = cb.get("url", "")
        if not (url.startswith("http://127.0.0.1:") or url.startswith("http://[::1]:")):
            raise ValueError("OTP 回调必须为本机回环地址")
        body = json.dumps({"email": email_addr, "issued_after": issued_after or time.time(),
                           "timeout": min(max(int(timeout), 1), 900)}).encode("utf-8")
        req = Request(url, data=body, headers={"Authorization": "Bearer " + cb.get("secret", ""),
                                                "Content-Type": "application/json"}, method="POST")
        # Never use an HTTP proxy for the local callback, even when PROXY is set.
        with build_opener(ProxyHandler({})).open(req, timeout=min(int(timeout), 900) + 15) as response:
            result = json.load(response)
        code = str(result.get("code") or "")
        if not code.isascii() or not code.isdigit() or len(code) != 6:
            raise TimeoutError("邮箱接码未取得有效六位验证码")
        return code
