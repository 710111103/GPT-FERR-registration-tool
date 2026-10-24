"""Opt-in adapter for upstream OSS protocol registrar (isolated subprocess)."""
from __future__ import annotations

import os
import random
import json
import secrets
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import Callable
from urllib.parse import urlparse


@contextmanager
def local_otp_callback(email: str, source: str):
    """Expose one job's existing email router only on loopback, for its lifetime."""
    from core.email_provider import wait_for_otp
    secret = secrets.token_urlsafe(32)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            if self.path != "/otp" or self.headers.get("Authorization") != "Bearer " + secret:
                self.send_error(403)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > 1024:
                    raise ValueError("invalid size")
                data = json.loads(self.rfile.read(length))
                if str(data.get("email", "")).lower() != email.lower():
                    raise ValueError("email mismatch")
                timeout = min(max(int(data.get("timeout", 120)), 1), 900)
                after_ts = float(data.get("issued_after") or 0)
                code = wait_for_otp(email, after_ts=after_ts, max_wait=timeout,
                                    email_source=source, force_service=True)
                raw = json.dumps({"code": code}).encode("utf-8")
                self.send_response(200)
            except Exception:
                # No provider credentials or OTP diagnostics returned to child.
                raw = b'{"error":"otp unavailable"}'
                self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {"url": f"http://127.0.0.1:{server.server_port}/otp", "secret": secret}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def run_oss_protocol_registration(*, email: str | None, name: str,
                                  birthday: str | None, proxy: str | None,
                                  batch_dir, on_email_acquired: Callable[[str], None] | None,
                                  relay_url: str | None = None, email_source: str | None = None):
    from config import email as email_cfg, proxy as proxy_cfg
    from config.proxy import normalize_proxy_url
    from core.account_export import save_account_data
    from core.email_provider import acquire_email, acquire_email_from_source, email_material_line, resolve_email_source, release_email
    from core.register_protocol_engine import register

    acquired = not str(email or "").strip()
    if acquired:
        if not email_cfg.USE_EMAIL_SERVICE:
            raise RuntimeError("请提供邮箱或开启邮箱池")
        email = acquire_email_from_source(email_source) if email_source else acquire_email()
        if on_email_acquired:
            on_email_acquired(email)
    source = email_source or resolve_email_source(email)
    material = str(email_material_line(email, source) or "")
    if relay_url is None and "----" in material and source == "icloud_relay":
        relay_url = material.split("----", 1)[1].strip()
    relay_url = str(relay_url or "").strip()
    if relay_url:
        parsed = urlparse(relay_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username:
            return {"success": False, "email": email, "error": "中转取件链接缺失或不是 HTTPS"}
    raw_pool = list(getattr(proxy_cfg, "PROXY_POOL", []) or [])
    # 配置中重复的代理不能重复参与 random.choice，否则同一出口会被人为放大权重。
    # 保留原顺序，供协议子进程在 403/网络失败时轮换不同出口。
    unique_raw_pool = list(dict.fromkeys(
        str(item).strip() for item in raw_pool if str(item or "").strip()
    ))
    pool = [normalize_proxy_url(item) for item in unique_raw_pool]
    selected_proxy = str(proxy or (random.choice(pool) if pool else os.getenv("PROTOCOL_PROXY", "")) or "").strip()
    selected_proxy = normalize_proxy_url(selected_proxy)
    if not selected_proxy:
        return {"success": False, "email": email, "error": "协议引擎缺少代理，未发起注册"}
    # 把去重后的完整代理池传给协议子进程。只传 selected_proxy 会导致首个出口
    # 403 后 bridge 没有候选项可轮换。
    proxy_pool_text = "\n".join(pool)
    try:
        if relay_url:
            data = register(email, relay_url, proxy=selected_proxy,
                            proxy_pool=proxy_pool_text, want_2fa=True)
        else:
            with local_otp_callback(email, source) as callback:
                data = register(email, "", proxy=selected_proxy,
                                proxy_pool=proxy_pool_text, want_2fa=True,
                                otp_callback=callback)
    except Exception as exc:
        return {"success": False, "email": email, "error": f"协议引擎异常: {type(exc).__name__}: {exc}"}
    result = data.get("result") or {}
    token = str(result.get("access_token") or "").strip()
    session_token = str(result.get("session_token") or "").strip()
    cookie_header = str(result.get("cookie_header") or "").strip()
    password = str(result.get("password") or "").strip()
    totp_secret = str(result.get("totp_secret") or "").strip()
    if not data.get("ok") or not token:
        return {"success": False, "email": email, "error": str(data.get("error") or "未取得 AT")}

    # The OSS registrar creates the password before completing OAuth and returns
    # it together with the authenticated session. Persist all artifacts in the
    # turb account row so the account is immediately visible and reusable.
    account_id = save_account_data(
        email=email, access_token=token, totp_secret=totp_secret,
        email_source=source, proxy_used=selected_proxy, batch_dir=batch_dir,
        plan_check_proxy=selected_proxy,
        extra={
            "engine": "oss_protocol",
            "account": {"planType": "free"},
            "registration_password": password,
            "registration_password_verified": bool(password),
            "totp_setup_ok": bool(totp_secret),
            "totp_setup_status": "success" if totp_secret else "missing",
            "session_token": session_token,
            "cookie_header": cookie_header,
            "network_traffic": data.get("network_traffic"),
        },
    )
    if acquired:
        release_email(email, status="used", note=f"已注册，账号ID={account_id}")
    return {"success": True, "email": email, "account_id": account_id,
            "access_token": token, "totp_secret": totp_secret,
            "password_saved": bool(password), "twofa_enabled": bool(totp_secret),
            "flow": {"status": "skipped", "ok": False},
            "codex": {"status": "skipped", "ok": False},
            "network_traffic": data.get("network_traffic"), "error": None}

