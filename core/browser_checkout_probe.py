# -*- coding: utf-8 -*-
"""无头浏览器结账与支付方式探测模块。

当协议请求 /backend-api/payments/checkout 遇到 OpenAI 风控拦截（HTTP 400 unusual activity）时，
拉起 Playwright 内置无头 Chromium 运行在对应国家代理环境下，在真实浏览器执行上下文与
Turnstile/Sentinel 验证下发起结账请求，拦截或提取真实 Stripe checkout session (cs_live_...)，
确证实际可用的支付方式（如 card, upi, paypay, link 等）。
"""
from __future__ import annotations

import json
import logging
import re
import time
import uuid
from typing import Any, Optional
from urllib.parse import quote, urlparse

from core.antbrowser_driver import build_ant_driver, cleanup_ant_profile

logger = logging.getLogger(__name__)

STRIPE_PUBLISHABLE_KEY = "pk_live_51M7EEdCIeA3d5g82g9y9eH9x5VpYnO8F3cK0Z6B7v8X1N2M3L4K5J6H7G8F9D0"
STRIPE_PAYMENT_PAGE_INIT = "https://api.stripe.com/v1/payment_pages/{session_id}/init"


def _collect_methods_from_obj(payload: Any) -> list[str]:
    methods: list[str] = []
    value_keys = {
        "payment_method", "payment_methods", "payment_method_types",
        "supported_payment_methods", "allowed_payment_methods",
    }
    mapping_keys = {"payment_method_specs", "payment_method_options", "payment_method_configurations"}

    def add(v: Any) -> None:
        name = str(v or "").strip().lower()
        from core.chatgpt_plan import _KNOWN_PAYMENT_METHOD_NAMES
        if name and name in _KNOWN_PAYMENT_METHOD_NAMES and name not in methods:
            methods.append(name)

    def walk(val: Any, key: str = "", depth: int = 0) -> None:
        if depth > 8:
            return
        if isinstance(val, dict):
            if key in mapping_keys:
                for k in val:
                    add(k)
            for child_key, child_value in val.items():
                if child_key == "type" and isinstance(child_value, str):
                    add(child_value)
                walk(child_value, str(child_key).lower(), depth + 1)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, dict) and "type" in item:
                    add(item.get("type"))
                elif key in value_keys and isinstance(item, str):
                    add(item)
                else:
                    walk(item, key, depth + 1)
        elif key in value_keys and isinstance(val, str):
            add(val)

    walk(payload)
    return methods


def probe_checkout_headless(
    token: str,
    claims: dict,
    *,
    country: str,
    campaign_id: str = "",
    proxy: Optional[str] = None,
    timeout: float = 30.0,
) -> dict:
    """使用 Playwright 无头浏览器在指定代理下探测 Plus 结账与支付方式。"""
    country = str(country or "US").upper()
    account_id = str((claims or {}).get("account_id") or "").strip()
    user_id = str((claims or {}).get("user_id") or "").strip()

    logger.info(
        "[HeadlessCheckout] 启动无头浏览器探测: country=%s campaign=%s proxy=%s",
        country, campaign_id, proxy or "direct",
    )

    driver = None
    opened = None
    browser = None
    context = None
    page = None
    try:
        driver, opened = build_ant_driver(proxy=proxy, force_headless=True)
        browser = driver.browser
        context = browser.new_context(
            viewport={"width": 1280, "height": 800},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        )
        context.add_init_script("""
        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
        window.chrome = { runtime: {}, loadTimes: function() {}, csi: function() {}, app: {} };
        Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
        """)

        page = context.new_page()
        page.set_default_timeout(int(timeout * 1000))

        # 访问 ChatGPT 首页建立真实的 Cloudflare / Sentinel 上下文
        try:
            page.goto("https://chatgpt.com/", wait_until="domcontentloaded", timeout=int(timeout * 1000))
            time.sleep(2)
        except Exception as e:
            logger.debug("[HeadlessCheckout] 预热页面导航提示: %s", e)

        # 在浏览器上下文中通过 window.fetch 执行结账请求，携带浏览器原生的 cookies 与 context
        eval_script = """
        async ([token, accountId, country, campaignId, currency]) => {
            const payload = {
                entry_point: "all_plans_pricing_modal",
                plan_name: "chatgptplusplan",
                billing_details: { country: country, currency: currency },
                promo_campaign: campaignId ? {
                    promo_campaign_id: campaignId,
                    is_coupon_from_query_param: false
                } : undefined,
                checkout_ui_mode: "custom",
                cancel_url: "https://chatgpt.com/#pricing"
            };
            const headers = {
                "authorization": "Bearer " + token,
                "content-type": "application/json",
                "x-openai-target-path": "/backend-api/payments/checkout",
                "x-openai-target-route": "/backend-api/payments/checkout"
            };
            if (accountId) {
                headers["chatgpt-account-id"] = accountId;
            }
            try {
                const resp = await fetch("https://chatgpt.com/backend-api/payments/checkout", {
                    method: "POST",
                    headers: headers,
                    body: JSON.stringify(payload)
                });
                const status = resp.status;
                let data = null;
                try {
                    data = await resp.json();
                } catch(e) {
                    data = { rawText: await resp.text() };
                }
                return { status: status, data: data };
            } catch(err) {
                return { status: 0, error: err.toString() };
            }
        }
        """

        from core.chatgpt_plan import COUNTRY_CURRENCIES
        currency = COUNTRY_CURRENCIES.get(country, "USD")
        eval_res = page.evaluate(eval_script, [token, account_id, country, campaign_id, currency])
        status = eval_res.get("status", 0)
        data = eval_res.get("data") or {}
        error = eval_res.get("error")

        if 200 <= status < 300 and isinstance(data, dict):
            session_id = str(data.get("checkout_session_id") or data.get("session_id") or data.get("id") or "")
            methods = _collect_methods_from_obj(data)

            # 如果获得了 Stripe session，通过 page context 请求 stripe init
            init_data = {}
            if session_id.startswith("cs_"):
                stripe_eval = """
                async ([sessionId, key]) => {
                    const formData = new URLSearchParams();
                    formData.append("browser_locale", "en-US");
                    formData.append("browser_timezone", "UTC");
                    formData.append("elements_session_client[elements_init_source]", "custom_checkout");
                    formData.append("elements_session_client[referrer_host]", "chatgpt.com");
                    formData.append("elements_session_client[locale]", "en");
                    formData.append("key", key);
                    try {
                        const resp = await fetch("https://api.stripe.com/v1/payment_pages/" + encodeURIComponent(sessionId) + "/init", {
                            method: "POST",
                            headers: { "content-type": "application/x-www-form-urlencoded" },
                            body: formData.toString()
                        });
                        return await resp.json();
                    } catch(e) {
                        return null;
                    }
                }
                """
                init_data = page.evaluate(stripe_eval, [session_id, STRIPE_PUBLISHABLE_KEY]) or {}
                if isinstance(init_data, dict):
                    methods = _collect_methods_from_obj(init_data) or methods

            upi_method_available = "upi" in methods
            upi_trial_eligible = bool(country == "IN" and campaign_id and upi_method_available)

            logger.info(
                "[HeadlessCheckout] 无头探测成功: country=%s session=%s methods=%s upi=%s",
                country, session_id[:16] if session_id else "none", methods, upi_trial_eligible,
            )
            return {
                "payment_probe_ok": True,
                "payment_probe_blocked": False,
                "payment_probe_mode": "headless",
                "trial_payment_methods": methods,
                "checkout_session_kind": "stripe" if session_id.startswith("cs_") else "openai",
                "checkout_session_id": session_id,
                "upi_method_available": upi_method_available,
                "upi_trial_eligible": upi_trial_eligible,
                "upi_trial_status": "verified" if upi_trial_eligible else ("unsupported" if country == "IN" else None),
                "upi_trial_verified": upi_trial_eligible,
            }
        else:
            detail = str(data.get("detail") or data.get("message") or error or f"HTTP {status}").strip()
            blocked = "unusual activity" in detail.lower()
            logger.warning("[HeadlessCheckout] 无头探测返回异常: status=%s detail=%s", status, detail)
            return {
                "payment_probe_ok": False,
                "payment_probe_blocked": blocked,
                "payment_probe_mode": "headless",
                "payment_probe_error": detail,
            }
    except Exception as exc:
        logger.warning("[HeadlessCheckout] 无头探测发生异常: %s", exc)
        return {
            "payment_probe_ok": False,
            "payment_probe_blocked": False,
            "payment_probe_mode": "headless",
            "payment_probe_error": f"无头执行异常: {exc}",
        }
    finally:
        try:
            if context:
                context.close()
        except Exception:
            pass
        try:
            if driver:
                driver.quit()
        finally:
            if opened:
                cleanup_ant_profile(opened)
