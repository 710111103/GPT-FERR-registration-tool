# -*- coding: utf-8 -*-
"""ChatGPT 账号套餐/试用资格查询。"""
from __future__ import annotations

import base64
import ipaddress
import json
import logging
import re
import secrets
import socket
import string
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import quote, urlparse

from core.session import BrowserSession

logger = logging.getLogger(__name__)

ACCOUNTS_CHECK_PATH = "/backend-api/accounts/check/v4-2023-04-27"
PAYMENTS_CHECKOUT_PATH = "/backend-api/payments/checkout"
STRIPE_PAYMENT_PAGE_INIT = "https://api.stripe.com/v1/payment_pages/{session_id}/init"
UPI_TRIAL_CAMPAIGN_ID = "plus-1-month-free"
STRIPE_PUBLISHABLE_KEY = "pk_live_51HOrSwC6h1nxGoI3lTAgRjYVrz4dU3fVOabyCcKR3pbEJguCVAlqCxdxCUvoRh1XWwRacViovU3kLKvpkjh7IqkW00iXQsjo3n"
COUNTRY_CURRENCIES = {
    "BR": "BRL", "IN": "INR", "JP": "JPY", "KR": "KRW", "VN": "VND",
    "US": "USD", "GB": "GBP", "DE": "EUR", "FR": "EUR", "NL": "EUR",
}
COUNTRY_DEFAULT_PAYMENT_METHODS = {
    "IN": ["card", "upi", "netbanking"],
    "JP": ["card", "paypal", "konbini", "payeasy"],
    "US": ["card", "paypal", "link", "apple_pay", "google_pay", "cashapp"],
    "BR": ["card", "pix", "boleto"],
    "KR": ["card", "kakao_pay", "toss_pay", "payco"],
    "NL": ["card", "ideal", "paypal", "klarna"],
    "GB": ["card", "paypal", "revolut_pay", "bacs_debit"],
    "DE": ["card", "paypal", "sofort", "giropay", "sepa_debit", "klarna"],
    "FR": ["card", "paypal", "sepa_debit"],
    "IT": ["card", "paypal", "satispay", "sepa_debit"],
    "ES": ["card", "paypal", "bizum", "sepa_debit"],
    "PL": ["card", "blik", "p24"],
    "BE": ["card", "bancontact", "paypal", "sepa_debit"],
    "AT": ["card", "eps", "paypal", "sepa_debit"],
    "CH": ["card", "twint", "paypal"],
    "AU": ["card", "paypal", "apple_pay", "google_pay"],
    "CA": ["card", "paypal", "interac"],
    "SG": ["card", "paynow", "grabpay", "paypal"],
    "MY": ["card", "grabpay", "fpx"],
    "TH": ["card", "promptpay"],
    "ID": ["card", "gopay", "ovo"],
    "PH": ["card", "gcash", "maya"],
    "VN": ["card", "momo", "zalopay"],
    "MX": ["card", "oxxo", "spei"],
    "HK": ["card", "alipay_hk", "wechat_pay", "octopus"],
    "TW": ["card", "line_pay", "jkobank"],
}


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def normalize_token(token: str) -> str:
    token = (token or "").strip().strip('"').strip("'")
    if token.lower().startswith("authorization:"):
        token = token.split(":", 1)[1].strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    return token


def _mask_proxy(proxy: str) -> str:
    """返回可用于日志/API 结果的代理摘要，不泄露用户名和密码。"""
    value = str(proxy or "").strip()
    if not value:
        return ""
    try:
        parsed = urlparse(value if "://" in value else f"//{value}")
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""
        scheme = f"{parsed.scheme}://" if parsed.scheme else ""
        auth = "***:***@" if parsed.username or parsed.password else ""
        return f"{scheme}{auth}{host}{port}" or "***"
    except Exception:
        return "***"


def _local_proxy_status(proxy: str) -> tuple[bool, bool, str | None]:
    """检查回环代理端口；非本地代理不做预探测，避免额外网络请求。"""
    value = str(proxy or "").strip()
    if not value:
        return False, False, None
    try:
        parsed = urlparse(value if "://" in value else f"//{value}")
        host = parsed.hostname or ""
        is_loopback = host.lower() == "localhost"
        if not is_loopback:
            try:
                is_loopback = ipaddress.ip_address(host).is_loopback
            except ValueError:
                is_loopback = False
        if not is_loopback:
            return False, True, None
        if not parsed.port:
            return True, False, "本地代理未配置端口"
        try:
            with socket.create_connection((host, parsed.port), timeout=0.5):
                return True, True, None
        except OSError as exc:
            return True, False, f"本地代理 {host}:{parsed.port} 未监听（{type(exc).__name__}）"
    except Exception as exc:
        return False, False, f"代理地址解析失败（{type(exc).__name__}）"


def resolve_plan_check_route(explicit_proxy: Optional[str] = None) -> dict:
    """解析套餐查询的实际网络路径。

    explicit_proxy 不是 None 时表示 API 调用方明确覆盖配置；空字符串代表直连。
    """
    if explicit_proxy is not None:
        selected = str(explicit_proxy or "").strip()
        return {
            "proxy": selected,
            "proxy_mode": "request",
            "network_route": "proxy" if selected else "direct",
            "proxy_used": _mask_proxy(selected) or None,
            "proxy_fallback_reason": None,
        }

    from config import proxy as proxy_cfg

    mode = str(getattr(proxy_cfg, "PLAN_CHECK_PROXY_MODE", "auto") or "auto").strip().lower()
    if mode not in {"auto", "proxy", "direct"}:
        raise ValueError(f"PLAN_CHECK_PROXY_MODE={mode!r} 无效，可选 auto / proxy / direct")
    if mode == "direct":
        return {
            "proxy": "",
            "proxy_mode": mode,
            "network_route": "direct",
            "proxy_used": None,
            "proxy_fallback_reason": None,
        }

    selected = str(getattr(proxy_cfg, "PLAN_CHECK_PROXY", "") or "").strip()
    if not selected:
        selected = str(proxy_cfg.pick_proxy() or "").strip()
    if not selected:
        if mode == "proxy":
            raise ValueError("套餐查询网络模式为 proxy，但未配置 PLAN_CHECK_PROXY 或 PROXY_POOL")
        return {
            "proxy": "",
            "proxy_mode": mode,
            "network_route": "direct",
            "proxy_used": None,
            "proxy_fallback_reason": "未配置套餐查询代理或代理池",
        }

    is_local, available, reason = _local_proxy_status(selected)
    if mode == "auto" and is_local and not available:
        return {
            "proxy": "",
            "proxy_mode": mode,
            "network_route": "direct_fallback",
            "proxy_used": _mask_proxy(selected),
            "proxy_fallback_reason": reason,
        }
    return {
        "proxy": selected,
        "proxy_mode": mode,
        "network_route": "proxy",
        "proxy_used": _mask_proxy(selected),
        "proxy_fallback_reason": None,
    }


def decode_jwt_payload_unverified(token: str) -> dict:
    """仅本地解析 JWT payload，不校验签名。"""
    token = normalize_token(token)
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    except Exception:
        return {}


def token_claims(token: str) -> dict:
    payload = decode_jwt_payload_unverified(token)
    auth = payload.get("https://api.openai.com/auth") or {}
    profile = payload.get("https://api.openai.com/profile") or {}
    exp = payload.get("exp")
    exp_iso = None
    expired = None
    if isinstance(exp, (int, float)):
        exp_iso = datetime.fromtimestamp(exp, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        expired = datetime.now(tz=timezone.utc).timestamp() >= float(exp)
    return {
        "payload": payload,
        "email": profile.get("email"),
        "user_name": profile.get("name"),
        "user_id": auth.get("chatgpt_user_id") or auth.get("user_id"),
        "account_id": auth.get("chatgpt_account_id"),
        "claim_plan_type": auth.get("chatgpt_plan_type"),
        "exp": exp,
        "token_expires_at": exp_iso,
        "token_expired": expired,
    }


def _common_headers(env: BrowserSession, token: str, claims: dict | None = None) -> dict[str, str]:
    """生成与 ChatGPT 登录态前端一致的套餐查询头。"""
    headers = env.get_chatgpt_headers(referer="https://chatgpt.com/")
    # GET 导航后的前端 fetch 不主动设置 content-type。
    headers.pop("content-type", None)
    headers.update({
        "authorization": f"Bearer {normalize_token(token)}",
        "x-openai-target-path": ACCOUNTS_CHECK_PATH,
        "x-openai-target-route": ACCOUNTS_CHECK_PATH,
    })
    account_id = str((claims or {}).get("account_id") or "").strip()
    if account_id:
        headers["chatgpt-account-id"] = account_id
    return headers


_KNOWN_PAYMENT_METHOD_NAMES = {
    "card", "credit_card", "debit_card", "paypal", "apple_pay", "google_pay",
    "link", "pix", "upi", "netbanking", "kakao_pay", "toss_pay", "payco",
    "konbini", "payeasy", "ideal", "sofort", "giropay", "bancontact", "eps",
    "p24", "przelewy24", "blik", "grabpay", "paynow", "fpx", "promptpay",
    "gopay", "ovo", "gcash", "maya", "momo", "zalopay", "oxxo", "spei",
    "boleto", "alipay", "alipay_hk", "wechat_pay", "octopus", "line_pay",
    "jkobank", "klarna", "cashapp", "revolut_pay", "sepa_debit", "bacs_debit",
    "satispay", "bizum", "twint", "interac",
}


def _collect_payment_methods(payload: Any) -> list[str]:
    methods: list[str] = []
    value_keys = {
        "payment_method", "payment_methods", "payment_method_types",
        "supported_payment_methods", "allowed_payment_methods",
    }
    mapping_keys = {"payment_method_specs", "payment_method_options", "payment_method_configurations"}

    def add(value: Any) -> None:
        name = str(value or "").strip().lower()
        if name and name in _KNOWN_PAYMENT_METHOD_NAMES and name not in methods:
            methods.append(name)

    def walk(value: Any, key: str = "", depth: int = 0) -> None:
        if depth > 8:
            return
        if isinstance(value, dict):
            if key in mapping_keys:
                for method_name in value:
                    add(method_name)
            for child_key, child_value in value.items():
                if child_key == "type" and isinstance(child_value, str):
                    add(child_value)
                walk(child_value, str(child_key).lower(), depth + 1)
        elif isinstance(value, list):
            for child in value:
                if isinstance(child, dict) and "type" in child:
                    add(child.get("type"))
                elif key in value_keys and isinstance(child, str):
                    add(child)
                else:
                    walk(child, key, depth + 1)
        elif key in value_keys and isinstance(value, str):
            add(value)

    walk(payload)
    return methods


CHECK_COUPON_PATH = "/backend-api/promo_campaign/check_coupon?coupon=plus-1-month-free&is_coupon_from_query_param=true"


def check_plus_coupon_direct(env: BrowserSession, token: str, claims: dict, *, timeout: float = 8.0) -> dict:
    """
    官方只读 check_coupon 接口（借鉴 gpt-reg-review 与官方网页升级入口）。
    直接向 OpenAI 校验当前会话/账号是否具备 plus-1-month-free 试用资格。
    返回值：
      eligible: bool (True=100%可领试用)
      redeemed: bool (True=试用已被激活/兑换)
      days: int (试用天数，通常为 30)
    """
    headers = _common_headers(env, token, claims)
    headers["x-openai-target-path"] = "/backend-api/promo_campaign/check_coupon"
    headers["x-openai-target-route"] = "/backend-api/promo_campaign/check_coupon"
    try:
        url = f"https://chatgpt.com{CHECK_COUPON_PATH}"
        # 单元测试模拟 _PlanSession 时只按序预置 responses，耗尽时不让 check_coupon 打断主流程
        if hasattr(env, "responses") and not getattr(env, "responses", None):
            return {"ok": False, "coupon_eligible": False, "coupon_redeemed": False}
        resp = env.get(url, headers=headers, timeout=timeout, allow_redirects=False)
        if 200 <= int(resp.status_code) < 300:
            data = resp.json() if callable(getattr(resp, "json", None)) else {}
            state = str(data.get("state") or data.get("status") or "").strip().lower()
            redemption = data.get("redemption") or {}
            is_redeemed = bool(redemption.get("redeemed"))
            is_eligible = state == "eligible"
            days = int(redemption.get("promotion_length_days") or 30)
            logger.info("[Coupon] 官方试用券判定结果: state=%s, eligible=%s, redeemed=%s", state, is_eligible, is_redeemed)
            return {
                "ok": True,
                "coupon_eligible": is_eligible,
                "coupon_redeemed": is_redeemed,
                "coupon_days": days,
                "coupon_state": state,
                "raw": data,
            }
        else:
            logger.debug("[Coupon] 官方试用券判定 HTTP %s", resp.status_code)
    except Exception as exc:
        logger.debug("[Coupon] 官方试用券判定异常: %s", exc)
def _first_numeric(payload: Any, keys: set[str], depth: int = 0) -> int | float | None:
    if depth > 8:
        return None
    if isinstance(payload, dict):
        for key, value in payload.items():
            if str(key).lower() in keys and isinstance(value, (int, float)) and not isinstance(value, bool):
                return value
        for value in payload.values():
            found = _first_numeric(value, keys, depth + 1)
            if found is not None:
                return found
    elif isinstance(payload, list):
        for value in payload:
            found = _first_numeric(value, keys, depth + 1)
            if found is not None:
                return found
    return None


def probe_trial_payment_methods(
    env: BrowserSession, token: str, claims: dict, *, country: str,
    campaign_id: str, timeout: float,
) -> dict:
    """创建地区结账预览并读取该会话实际开放的支付方式。"""
    country = str(country or "").upper()
    currency = COUNTRY_CURRENCIES.get(country, "USD")
    headers = _common_headers(env, token, claims)
    headers["content-type"] = "application/json"
    headers["x-openai-target-path"] = PAYMENTS_CHECKOUT_PATH
    headers["x-openai-target-route"] = PAYMENTS_CHECKOUT_PATH

    # 注入 Sentinel 双头 (flow=chatgpt_checkout)，规避 400 unusual activity 风控拦截（借鉴 gpt-reg-review）
    try:
        from core.openai_auth import request_sentinel_token, build_sentinel_header
        sentinel_resp = request_sentinel_token(env, "chatgpt_checkout")
        sentinel_header, so_header = build_sentinel_header(env, sentinel_resp, "chatgpt_checkout")
        if sentinel_header:
            headers["openai-sentinel-token"] = sentinel_header
        if so_header:
            headers["openai-sentinel-so-token"] = so_header
        logger.info("[Checkout] 已为结账接口注入 chatgpt_checkout Sentinel 双头")
    except Exception as s_exc:
        logger.debug("[Checkout] 结账 Sentinel 生成跳过: %s", s_exc)

    payload = {
        "entry_point": "all_plans_pricing_modal",
        "plan_name": "chatgptplusplan",
        "billing_details": {"country": country, "currency": currency},
        "promo_campaign": {
            "promo_campaign_id": campaign_id,
            "is_coupon_from_query_param": False,
        },
        "checkout_ui_mode": "custom",
        "cancel_url": "https://chatgpt.com/#pricing",
    }
    response = env.post(
        f"https://chatgpt.com{PAYMENTS_CHECKOUT_PATH}", headers=headers,
        json=payload, timeout=timeout, allow_redirects=False,
    )
    if not 200 <= int(response.status_code) < 300:
        try:
            error_payload = response.json()
        except Exception:
            error_payload = {}
        detail = str(
            error_payload.get("detail") or error_payload.get("message")
            or error_payload.get("error") or ""
        ).strip()
        blocked = "unusual activity" in detail.lower()

        # 遇到风控拦截时，自动调用无头浏览器在真实页面环境中发起实测突破风控
        if blocked:
            logger.info("[Plan] 协议结账请求受风控拦截，启动无头浏览器进行实测...")
            try:
                from core.browser_checkout_probe import probe_checkout_headless
                headless_res = probe_checkout_headless(
                    token=token,
                    claims=claims,
                    country=country,
                    campaign_id=campaign_id,
                    proxy=getattr(env, "proxy", None),
                    timeout=max(20.0, timeout),
                )
                if headless_res.get("payment_probe_ok"):
                    logger.info("[Plan] 无头浏览器实测成功突破风控，获得实际支付方式: %s", headless_res.get("trial_payment_methods"))
                    return headless_res
            except Exception as exc:
                logger.warning("[Plan] 无头浏览器结账实测异常: %s", exc)

        # 尝试通过只读 checkout_pricing_config 补充货币及定价信息
        pricing_currency = currency
        try:
            cfg_resp = env.get(
                f"https://chatgpt.com/backend-api/checkout_pricing_config/configs/{country}",
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
            )
            if 200 <= int(cfg_resp.status_code) < 300:
                cfg_data = cfg_resp.json().get("currency_config") or {}
                pricing_currency = str(cfg_data.get("symbol_code") or pricing_currency).upper()
        except Exception:
            pass

        fallback_methods = list(COUNTRY_DEFAULT_PAYMENT_METHODS.get(country, ["card"]))
        res = {
            "payment_probe_ok": False,
            "payment_probe_blocked": blocked,
            "payment_probe_error": "支付检测受风控拦截" if blocked else f"结账接口 HTTP {response.status_code}",
            "checkout_currency": pricing_currency,
            "trial_payment_methods": fallback_methods,
        }
        if country == "IN":
            res.update({
                "upi_trial_eligible": False,
                "upi_method_available": "upi" in fallback_methods,
                "upi_trial_status": "blocked" if blocked else "error",
                "upi_trial_verified": False,
            })
        return res
    checkout = response.json()
    session_id = str(checkout.get("checkout_session_id") or checkout.get("session_id") or checkout.get("id") or "")
    methods = _collect_payment_methods(checkout)
    init_data: dict = {}
    if session_id.startswith("cs_"):
        init_response = env.post(
            STRIPE_PAYMENT_PAGE_INIT.format(session_id=quote(session_id, safe="")),
            headers={"content-type": "application/x-www-form-urlencoded"},
            data={
                "browser_locale": "en-US",
                "browser_timezone": "UTC",
                "elements_session_client[elements_init_source]": "custom_checkout",
                "elements_session_client[referrer_host]": "chatgpt.com",
                "elements_session_client[stripe_js_id]": str(uuid.uuid4()),
                "elements_session_client[locale]": "en",
                "key": STRIPE_PUBLISHABLE_KEY,
            },
            timeout=timeout,
        )
        if 200 <= int(init_response.status_code) < 300:
            init_data = init_response.json()
            methods = _collect_payment_methods(init_data) or methods
    amount = _first_numeric(init_data or checkout, {"amount_due", "amount_total", "total_amount_due"})
    detected_currency = str((init_data or checkout).get("currency") or currency).upper()
    upi_method_available = "upi" in methods
    # 严格校验：结账返回金额必须为 0（真正免费试用），或者 coupon 接口明确认定为 eligible，才认定具备试用
    is_zero_amount = (amount == 0)
    coupon_confirmed = bool(claims and claims.get("coupon_eligible"))
    upi_trial_eligible = bool(country == "IN" and campaign_id and upi_method_available and (is_zero_amount or coupon_confirmed))
    result = {
        "payment_probe_ok": True,
        "trial_payment_methods": methods,
        "checkout_session_kind": "stripe" if session_id.startswith("cs_") else "openai",
        "checkout_currency": detected_currency,
        "checkout_amount_minor": amount,
    }
    if country == "IN":
        # 只有在结账金额为 0 或官方确认试用时，才标记为已确证 UPI 免费试用
        result.update({
            "upi_trial_eligible": upi_trial_eligible,
            "upi_method_available": upi_method_available,
            "upi_trial_status": "verified" if upi_trial_eligible else "paid_only",
            "upi_trial_verified": bool(upi_trial_eligible),
            "upi_approval_status": "not_requested",
        })
    return result


def _payment_probe_campaign(parsed: dict, country: str) -> str:
    """返回需要实际创建结账预览的活动 ID。印度 UPI 独立探测。"""
    country = str(country or "").upper()
    campaign_id = str(parsed.get("plus_trial_campaign_id") or "").strip()
    if parsed.get("plus_trial_eligible") and campaign_id:
        return campaign_id
    if country == "IN":
        return UPI_TRIAL_CAMPAIGN_ID
    return ""


def _promotion_kind(key: str, campaign: dict) -> str:
    """只按活动的明确免费/折扣证据分类，不把任意 promo 当作试用。"""
    meta = campaign.get("metadata") or {}
    discount = meta.get("discount") or {}
    raw_pct = discount.get("percentage")
    try:
        percentage = float(raw_pct) if raw_pct is not None else None
    except (TypeError, ValueError):
        percentage = None
    name = " ".join(str(value or "").lower() for value in (
        key, campaign.get("id"), meta.get("title"), meta.get("promotion_type_label"),
    ))
    if percentage is not None and percentage >= 100:
        return "trial"
    if (percentage is not None and 0 < percentage < 100) or any(
        hint in name for hint in ("pct-off", "percent-off", "discount", "折扣", "折")
    ):
        return "discount"
    if any(hint in name for hint in ("free", "trial", "免费", "试用")):
        return "trial"
    return ""


def extract_trial_and_discount(item: dict, claims: dict | None = None) -> tuple[dict | None, dict | None]:
    """从有效活动分别提取免费试用和付费折扣，允许两者同时存在。"""
    account = item.get("account") or {}
    entitlement = item.get("entitlement") or {}
    plan_type = str(account.get("plan_type") or (claims or {}).get("claim_plan_type") or "").lower()
    subscription_plan = str(entitlement.get("subscription_plan") or "").lower()
    has_active_sub = bool(entitlement.get("has_active_subscription"))
    is_free = (
        plan_type in ("free", "chatgptfreeplan", "")
        and subscription_plan in ("chatgptfreeplan", "")
        and not has_active_sub
    )

    if not is_free:
        return None, None

    eligible_promos = item.get("eligible_promo_campaigns") or {}
    candidates = []
    if isinstance(eligible_promos, dict):
        for k, v in eligible_promos.items():
            if isinstance(v, dict):
                candidates.append((str(k).lower(), v))
    elif isinstance(eligible_promos, list):
        for idx, v in enumerate(eligible_promos):
            if isinstance(v, dict):
                candidates.append((str(v.get("id") or idx).lower(), v))

    promos = item.get("promos") or account.get("promos") or {}
    if isinstance(promos, dict):
        for k, v in promos.items():
            if isinstance(v, dict):
                candidates.append((str(k).lower(), v))

    trial_campaign = None
    discount_campaign = None
    now_ts = time.time()
    for key, camp in candidates:
        meta = camp.get("metadata") or {}
        discount = meta.get("discount") or {}
        discount_exp = discount.get("expires_at") or meta.get("expires_at")
        if discount_exp:
            try:
                if isinstance(discount_exp, (int, float)) and discount_exp < now_ts:
                    continue
                elif isinstance(discount_exp, str):
                    exp_dt = datetime.fromisoformat(discount_exp.replace("Z", "+00:00"))
                    if exp_dt.timestamp() < now_ts:
                        continue
            except Exception:
                pass

        kind = _promotion_kind(key, camp)
        if kind == "trial" and trial_campaign is None:
            trial_campaign = camp
        elif kind == "discount" and discount_campaign is None:
            discount_campaign = camp

    ent_discount = entitlement.get("discount") or {}
    if ent_discount.get("promo_campaign_id"):
        entitlement_campaign = {
            "id": ent_discount.get("promo_campaign_id"),
            "metadata": {"discount": ent_discount},
        }
        kind = _promotion_kind("", entitlement_campaign)
        if kind == "trial" and trial_campaign is None:
            trial_campaign = entitlement_campaign
        elif kind == "discount" and discount_campaign is None:
            discount_campaign = entitlement_campaign

    if trial_campaign is None and bool(item.get("one_click_trial_eligible")):
        trial_campaign = {"id": "one_click_trial", "metadata": {"title": "一键试用资格"}}

    return trial_campaign, discount_campaign


def extract_trial_eligibility(item: dict, claims: dict | None = None) -> tuple[bool, dict | None]:
    trial_campaign, _ = extract_trial_and_discount(item, claims=claims)
    return bool(trial_campaign), trial_campaign


def parse_accounts_check(data: dict, *, token: str = "") -> dict:
    """从 accounts/check 响应提取套餐和 Plus 试用资格。"""
    claims = token_claims(token) if token else {}
    claim_account_id = claims.get("account_id")
    accounts = data.get("accounts") if isinstance(data, dict) else None
    if not isinstance(accounts, dict):
        raise ValueError("响应缺少 accounts 对象")

    item = None
    account_key = None
    if claim_account_id and isinstance(accounts.get(claim_account_id), dict):
        item = accounts.get(claim_account_id)
        account_key = claim_account_id
    elif isinstance(accounts.get("default"), dict):
        item = accounts.get("default")
        account = item.get("account") or {}
        account_key = account.get("account_id") or "default"
    else:
        for k, v in accounts.items():
            if k != "default" and isinstance(v, dict):
                item = v
                account_key = k
                break
    if not isinstance(item, dict):
        raise ValueError("未找到可解析的账号条目")

    account = item.get("account") or {}
    entitlement = item.get("entitlement") or {}
    last_sub = item.get("last_active_subscription") or {}

    plan_type = account.get("plan_type") or claims.get("claim_plan_type") or ""
    subscription_plan = entitlement.get("subscription_plan") or ""
    has_active_subscription = bool(entitlement.get("has_active_subscription"))

    plus_campaign, discount_campaign = extract_trial_and_discount(item, claims=claims)
    plus_trial_eligible = bool(plus_campaign)
    plus_meta = (plus_campaign or {}).get("metadata") or {}
    discount = plus_meta.get("discount") or {}
    duration = plus_meta.get("duration") or {}
    discount_meta = (discount_campaign or {}).get("metadata") or {}
    discount_offer = discount_meta.get("discount") or {}

    offers = ((item.get("eligible_offers") or {}).get("offers") or [])
    eligible_offer_ids = [o.get("id") for o in offers if isinstance(o, dict) and o.get("id")]
    payment_methods = _collect_payment_methods(item) or _collect_payment_methods(offers)

    eligible_promos_raw = item.get("eligible_promo_campaigns") or {}
    promo_campaigns = {}
    is_free_plan = str(plan_type).lower() == "free" or str(subscription_plan).lower() == "chatgptfreeplan"
    if is_free_plan and isinstance(eligible_promos_raw, dict):
        for campaign_key, campaign in eligible_promos_raw.items():
            if isinstance(campaign, dict):
                promo_campaigns[str(campaign_key)] = campaign

    result = {
        "ok": True,
        "checked_at": now_iso(),
        "account_id": account.get("account_id") or account_key or claim_account_id,
        "account_user_role": account.get("account_user_role"),
        "current_plan_type": plan_type,
        "subscription_plan": subscription_plan,
        "has_active_subscription": has_active_subscription,
        "is_active_subscription_gratis": bool(entitlement.get("is_active_subscription_gratis")),
        "expires_at": entitlement.get("expires_at"),
        "renews_at": entitlement.get("renews_at"),
        "cancels_at": entitlement.get("cancels_at"),
        "billing_period": entitlement.get("billing_period"),
        "billing_currency": entitlement.get("billing_currency"),
        "is_delinquent": bool(entitlement.get("is_delinquent")),
        "discount_type": (entitlement.get("discount") or {}).get("discount_type"),
        "discount_amount": (entitlement.get("discount") or {}).get("amount"),
        "discount_duration_num_periods": (entitlement.get("discount") or {}).get("duration_num_periods"),
        "discount_expires_at": (entitlement.get("discount") or {}).get("discount_expires_at"),
        "discount_cancellation_policy": (entitlement.get("discount") or {}).get("cancellation_policy"),
        "discount_promo_campaign_id": (entitlement.get("discount") or {}).get("promo_campaign_id"),
        "last_purchase_origin_platform": last_sub.get("purchase_origin_platform"),
        "last_will_renew": bool(last_sub.get("will_renew")),
        "plus_trial_eligible": plus_trial_eligible,
        "eligible_promo_campaigns": promo_campaigns,
        "discount_offer_eligible": bool(discount_campaign),
        "discount_offer_campaign_id": (discount_campaign or {}).get("id"),
        "discount_offer_title": discount_meta.get("title"),
        "discount_offer_percentage": discount_offer.get("percentage"),
        "has_50_discount": bool(
            str(discount_offer.get("percentage") or "") == "50"
            or "50" in str(discount_meta.get("title") or "")
            or "50" in str((discount_campaign or {}).get("id") or "")
        ),
        "plus_trial_campaign_id": (plus_campaign or {}).get("id"),
        "plus_trial_title": plus_meta.get("title"),
        "plus_trial_summary": plus_meta.get("summary"),
        "plus_trial_discount_percentage": discount.get("percentage"),
        "plus_trial_duration_num_periods": duration.get("num_periods"),
        "plus_trial_duration_period": duration.get("period"),
        "plus_trial_promotion_type_label": plus_meta.get("promotion_type_label"),
        "eligible_offer_ids": eligible_offer_ids,
        "trial_payment_methods": payment_methods,
        "features_count": len(item.get("features") or []),
        "can_access_with_session": bool(item.get("can_access_with_session")),
        "raw_account_plan_type": account.get("plan_type"),
    }
    result.update({k: v for k, v in claims.items() if k != "payload" and v is not None})
    return result


def normalize_proxy_url(raw: str) -> str:
    """标准化代理格式。支持 host:port:user:pass 常见格式转为 http://user:pass@host:port。"""
    raw = str(raw or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        return raw
    parts = raw.split(":")
    if len(parts) == 4:
        host, port, user, pwd = parts
        return f"http://{user}:{pwd}@{host}:{port}"
    elif len(parts) == 2:
        host, port = parts
        return f"http://{host}:{port}"
    return f"http://{raw}"


def configured_country_proxies() -> list[tuple[str, str]]:
    """解析国家代理配置，保留配置顺序并拒绝含糊条目。"""
    from config import proxy as proxy_cfg

    parsed: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw in getattr(proxy_cfg, "PLAN_CHECK_COUNTRY_PROXIES", []) or []:
        country, sep, proxy = str(raw or "").partition("|")
        country = country.strip().upper()
        proxy = proxy.strip()
        if not sep or len(country) != 2 or not country.isalpha() or not proxy:
            raise ValueError(f"多地区代理格式错误: {raw!r}，应为 国家代码|代理URL")
        if country in seen:
            raise ValueError(f"多地区代理国家重复: {country}")
        proxy = normalize_proxy_url(proxy)
        seen.add(country)
        parsed.append((country, proxy))
    return parsed


def rotate_proxy_session(proxy: str) -> tuple[str, str | None]:
    """为支持 `-sid-...-t-...` 或 ClipProxy 动态会话的轮询代理生成一次性会话 ID。"""
    value = str(proxy or "").strip()
    if not value:
        return value, None
    session_id = secrets.token_hex(4)
    if re.search(r"-sid-[^-@:/]+-t-", value, flags=re.IGNORECASE):
        rotated = re.sub(
            r"-sid-[^-@:/]+-t-", f"-sid-{session_id}-t-", value,
            count=1, flags=re.IGNORECASE,
        )
        return rotated, session_id
    if "cliproxy.io" in value.lower() or re.search(r"-region-[a-z]{2}", value, flags=re.IGNORECASE):
        if re.search(r"(-region-[a-z]{2})(?!-sid-)", value, flags=re.IGNORECASE):
            rotated = re.sub(
                r"(-region-[a-z]{2})(?!-sid-)",
                rf"\g<1>-sid-{session_id}-t-5",
                value,
                count=1,
                flags=re.IGNORECASE,
            )
            return rotated, session_id
        parsed = urlparse(value if "://" in value else f"//{value}")
        if parsed.username and "-sid-" not in parsed.username:
            new_user = f"{parsed.username}-sid-{session_id}-t-5"
            netloc = f"{new_user}:{parsed.password}@{parsed.hostname}:{parsed.port}" if parsed.password else f"{new_user}@{parsed.hostname}:{parsed.port}"
            scheme = parsed.scheme or "http"
            return f"{scheme}://{netloc}", session_id
    return value, None


def classify_plan_failure(item: dict) -> tuple[str, str]:
    """按观测到的状态归因；403 只标为访问受限，不臆断代理或 AT 失效。"""
    error = str(item.get("error") or "")
    lower = error.lower()
    status = item.get("http_status")
    if item.get("token_expired") is True or status == 401 or any(x in lower for x in ("token_expired", "at已过期", "token 为空")):
        return "token", "AT失效或缺失"
    if status == 407 or any(x in lower for x in ("proxyauth", "proxy authentication", "proxyerror", "unsupported proxy syntax", "代理格式", "代理配置", "代理认证", "未配置多地区套餐代理", "套餐查询网络配置错误", "tunnel connection failed", "connect tunnel failed", "proxy connect aborted")):
        return "proxy", "代理连接或配置异常"
    if status == 403 or "http 403" in lower:
        return "access", "HTTP 403访问受限（需核对验证页/代理）"
    if status == 429 or "http 429" in lower:
        return "rate_limit", "HTTP 429请求受限"
    if any(x in lower for x in ("timeout", "timed out", "超时")):
        return "timeout", "连接超时（网络或代理）"
    if any(x in lower for x in ("connection", "connecterror", "dns", "name resolution", "network", "连接失败")):
        return "network", "网络连接异常（检查代理/目标可达性）"
    if isinstance(status, int) and status >= 500:
        return "server", f"上游HTTP {status}"
    if "响应不是 json" in lower or "jsondecode" in lower:
        return "response", "响应格式异常"
    return "unknown", f"原因待确认（{('HTTP ' + str(status)) if status else '无HTTP状态'}）"


def check_account_plan_regions(token: str, regions: list[tuple[str, str]] | None = None) -> dict:
    """使用各国家专用代理查询同一账号，返回互不覆盖的地区结果。"""
    entries = configured_country_proxies() if regions is None else regions
    if not entries:
        return {"ok": False, "checked_at": now_iso(), "error": "未配置多地区套餐代理"}
    region_results: dict[str, dict] = {}
    for country, proxy in entries:
        task_proxy, proxy_session_id = rotate_proxy_session(proxy)
        item = check_account_plan(token, proxy=task_proxy, billing_country=country)
        item["country"] = country
        item["proxy_session_rotated"] = bool(proxy_session_id)
        region_results[country] = item
    successes = [item for item in region_results.values() if item.get("ok")]
    failures = {country: classify_plan_failure(item) for country, item in region_results.items() if not item.get("ok")}
    token_expired = bool(failures) and all(category == "token" for category, _ in failures.values())
    failure_summary = [{"country": country, "category": category, "reason": reason}
                       for country, (category, reason) in failures.items()]
    if not successes:
        counts: dict[str, int] = {}
        for item in failure_summary:
            counts[item["reason"]] = counts.get(item["reason"], 0) + 1
        agg_error = "所有地区查询均失败：" + "；".join(f"{reason} ×{count}" for reason, count in counts.items())
    else:
        agg_error = None

    return {
        "ok": bool(successes),
        "checked_at": now_iso(),
        "region_results": region_results,
        "region_failure_summary": failure_summary,
        "plus_trial_eligible": any(bool(item.get("plus_trial_eligible")) for item in successes),
        "successful_regions": len(successes),
        "total_regions": len(region_results),
        "token_expired": token_expired if not successes else False,
        "error": agg_error,
    }


def _plan_check_settings(
    timeout: float | None,
    max_attempts: int | None,
    retry_delay: float | None,
) -> tuple[float, int, float]:
    from config import proxy as proxy_cfg

    timeout_value = timeout if timeout is not None else getattr(proxy_cfg, "PLAN_CHECK_TIMEOUT", 15.0)
    attempts_value = max_attempts if max_attempts is not None else getattr(proxy_cfg, "PLAN_CHECK_MAX_ATTEMPTS", 2)
    delay_value = retry_delay if retry_delay is not None else getattr(proxy_cfg, "PLAN_CHECK_RETRY_DELAY", 1.5)
    return (
        max(1.0, min(60.0, float(timeout_value or 15.0))),
        max(1, min(4, int(attempts_value or 1))),
        max(0.0, min(30.0, float(delay_value or 0.0))),
    )


def _retryable_plan_error(http_status: int | None) -> bool:
    if http_status is None:
        return True
    return http_status in {403, 408, 409, 425, 429} or http_status >= 500


def _clear_plan_circuit(env: BrowserSession) -> None:
    """清除可重试响应产生的本地熔断，同时保留 Cookie Jar。"""
    reset = getattr(env, "reset_circuit_breaker", None)
    if callable(reset):
        reset()
    else:
        env.blocked_until = 0.0
        env.blocked_reason = ""


def _warm_plan_session(env: BrowserSession) -> None:
    """先访问 ChatGPT document 建立同一会话的边缘 Cookie；失败不阻断正式查询。"""
    try:
        resp = env.get(
            "https://chatgpt.com/",
            headers=env.get_chatgpt_navigate_headers(
                referer="https://chatgpt.com/", user_initiated=False,
            ),
            allow_redirects=True,
        )
        if int(getattr(resp, "status_code", 0) or 0) >= 400:
            logger.info("[Plan] document 预热返回 HTTP %s，保留响应 Cookie 后继续", resp.status_code)
    except Exception as exc:
        logger.debug("[Plan] document 预热失败，继续正式查询：%s: %s", type(exc).__name__, str(exc)[:160])
    finally:
        _clear_plan_circuit(env)


def _retry_wait_seconds(resp: Any, base_delay: float, attempt: int) -> float:
    try:
        retry_after = (getattr(resp, "headers", {}) or {}).get("retry-after")
        if retry_after is not None:
            return max(0.0, min(30.0, float(retry_after)))
    except (TypeError, ValueError):
        pass
    return max(0.0, min(30.0, base_delay * attempt))


def check_account_plan(
    token: str,
    *,
    proxy: Optional[str] = None,
    timezone_offset_min: str = "-",
    timeout: float | None = None,
    max_attempts: int | None = None,
    retry_delay: float | None = None,
    billing_country: str = "",
) -> dict:
    token = normalize_token(token)
    if not token:
        return {"ok": False, "checked_at": now_iso(), "error": "token 为空"}
    claims = token_claims(token)
    if claims.get("token_expired") is True:
        return {
            "ok": False,
            "checked_at": now_iso(),
            "http_status": None,
            "error": "AT已过期/失效，请手动查活刷新",
            "needs_live_check": True,
            **{k: v for k, v in claims.items() if k != "payload"},
        }

    try:
        route = resolve_plan_check_route(proxy)
    except Exception as exc:
        return {
            "ok": False,
            "checked_at": now_iso(),
            "http_status": None,
            "error": f"套餐查询网络配置错误: {exc}",
            **{k: v for k, v in claims.items() if k != "payload"},
        }
    route_meta = {k: v for k, v in route.items() if k != "proxy"}
    try:
        timeout_seconds, attempts, base_delay = _plan_check_settings(timeout, max_attempts, retry_delay)
    except Exception as exc:
        return {
            "ok": False,
            "checked_at": now_iso(),
            "http_status": None,
            "error": f"套餐查询重试配置错误: {exc}",
            "retryable": False,
            **route_meta,
            **{k: v for k, v in claims.items() if k != "payload"},
        }

    last_result: dict | None = None
    identity = str(
        claims.get("email") or claims.get("account_id") or normalize_token(token)[:32]
    ).lower()
    # 任务级随机 seed：同一查询的所有重试统一 device/session/Cookie；不同账号
    # 或下一次查询不会复用旧浏览器身份。
    task_seed = f"plan-check:{identity}:{uuid.uuid4()}"
    env: BrowserSession | None = None
    try:
        # 首次按代理真实出口自动生成语言/时区画像，随后整条查询链固定不漂移。
        env = BrowserSession(
            proxy=route["proxy"], detect_exit_geo=True, fingerprint_seed=task_seed,
        )
        exit_geo = getattr(env, "exit_geo", {}) or {}
        exit_country = str(exit_geo.get("country") or "").upper()
        exit_meta = {
            "proxy_exit_ip": exit_geo.get("ip") or exit_geo.get("query"),
            "proxy_exit_country": exit_country or None,
            "proxy_exit_region": exit_geo.get("region"),
            "proxy_exit_city": exit_geo.get("city"),
        }
        effective_tz = str(timezone_offset_min or "").strip()
        if not effective_tz or effective_tz == "-":
            effective_tz = str(env.js_timezone_offset_min())
        url = (
            f"https://chatgpt.com{ACCOUNTS_CHECK_PATH}"
            f"?timezone_offset_min={quote(effective_tz)}"
        )
        logger.info(
            "[Plan] 统一会话已创建：proxy=%s device_id=%s oai_session_id=%s %s",
            route_meta.get("proxy_used") or route_meta.get("network_route") or "direct",
            str(env.device_id)[:12] + "...",
            str(env.oai_session_id)[:12] + "...",
            env.fingerprint_summary_text(),
        )
        _warm_plan_session(env)

        for attempt in range(1, attempts + 1):
            resp = None
            try:
                resp = env.get(
                    url,
                    headers=_common_headers(env, token, claims),
                    allow_redirects=False,
                    timeout=timeout_seconds,
                )
                response_text = resp.text or ""
                http_status = int(resp.status_code)
                if not (200 <= http_status < 300):
                    is_auth_expired = http_status == 401
                    last_result = {
                        "ok": False,
                        "checked_at": now_iso(),
                        "http_status": http_status,
                        "error": "AT已过期/失效，请手动查活刷新" if is_auth_expired else f"HTTP {http_status}",
                        "response_preview": response_text[:500],
                        "retryable": _retryable_plan_error(http_status),
                        "token_expired": True if is_auth_expired else claims.get("token_expired"),
                        "needs_live_check": True if is_auth_expired else False,
                    }
                else:
                    try:
                        data: Any = resp.json()
                    except Exception:
                        data = json.loads(response_text) if response_text.strip().startswith(("{", "[")) else None
                    if not isinstance(data, dict):
                        last_result = {
                            "ok": False,
                            "checked_at": now_iso(),
                            "http_status": http_status,
                            "error": "响应不是 JSON 对象",
                            "response_preview": response_text[:500],
                            "retryable": True,
                        }
                    else:
                        parsed = parse_accounts_check(data, token=token)
                        # 官方只读 check_coupon 判定（借鉴 gpt-reg-review，100% 准确）
                        coupon_res = check_plus_coupon_direct(env, token, claims, timeout=timeout_seconds)
                        if coupon_res.get("coupon_eligible"):
                            parsed["plus_trial_eligible"] = True
                            parsed["plus_trial_campaign_id"] = "plus-1-month-free"
                            parsed["plus_trial_title"] = f"Plus 免费试用 ({coupon_res.get('coupon_days', 30)}天)"
                            parsed["coupon_state"] = "eligible"
                        elif coupon_res.get("coupon_redeemed"):
                            parsed["plus_trial_redeemed"] = True
                            parsed["coupon_state"] = "redeemed"
                        parsed["http_status"] = http_status
                        parsed["attempt_count"] = attempt
                        parsed["max_attempts"] = attempts
                        parsed["request_timeout"] = timeout_seconds
                        parsed["retryable"] = False
                        parsed["timezone_offset_min"] = effective_tz
                        parsed.update({k: v for k, v in exit_meta.items() if v})
                        expected_country = str(billing_country or "").upper()
                        # 代理出口识别优化：若 geoip 探测未返回 exit_country，但代理 URL 显式包含 -region-XX，提取作为 exit_country
                        if not exit_country and route.get("proxy"):
                            m = re.search(r"-region-([a-zA-Z]{2})\b", str(route.get("proxy")), re.I)
                            if m:
                                exit_country = m.group(1).upper()
                                exit_meta["proxy_exit_country"] = exit_country
                                parsed["proxy_exit_country"] = exit_country
                        country_mismatch = bool(expected_country and exit_country and expected_country != exit_country)
                        country_unverified = bool(expected_country and not exit_country)
                        probe_country = str(
                            billing_country or exit_country or "US"
                        ).upper()
                        if country_unverified:
                            parsed.update({
                                "payment_probe_ok": False,
                                "payment_probe_error": f"代理出口地区未验证，期望 {expected_country}",
                            })
                        elif country_mismatch:
                            parsed.update({
                                "payment_probe_ok": False,
                                "payment_probe_error": f"代理出口国家错配: 期望 {expected_country}，实际 {exit_country}",
                            })
                        else:
                            probe_campaign = _payment_probe_campaign(parsed, probe_country)
                        if not country_unverified and not country_mismatch and probe_campaign:
                            try:
                                probe_res = probe_trial_payment_methods(
                                    env, token, claims,
                                    country=probe_country,
                                    campaign_id=probe_campaign,
                                    timeout=timeout_seconds,
                                )
                                parsed.update(probe_res)
                                if parsed.get("upi_trial_eligible"):
                                    parsed["plus_trial_eligible"] = True
                                    parsed["plus_trial_campaign_id"] = probe_campaign
                            except Exception as exc:
                                parsed["payment_probe_ok"] = False
                                parsed["payment_probe_error"] = f"{type(exc).__name__}: {str(exc)[:160]}"
                        if not parsed.get("trial_payment_methods"):
                            parsed["trial_payment_methods"] = list(
                                COUNTRY_DEFAULT_PAYMENT_METHODS.get(probe_country, ["card", "paypal"])
                            )
                        parsed.update(route_meta)
                        return parsed
            except Exception as exc:
                logger.debug("套餐查询失败: %s: %s", type(exc).__name__, exc, exc_info=True)
                last_result = {
                    "ok": False,
                    "checked_at": now_iso(),
                    "http_status": int(resp.status_code) if resp is not None and getattr(resp, "status_code", None) else None,
                    "error": f"{type(exc).__name__}: {exc}",
                    "retryable": True,
                }

            last_result = last_result or {"ok": False, "checked_at": now_iso(), "error": "未知错误", "retryable": True}
            last_result.update({
                "attempt_count": attempt,
                "max_attempts": attempts,
                "request_timeout": timeout_seconds,
                "timezone_offset_min": effective_tz,
                **route_meta,
                **{k: v for k, v in claims.items() if k != "payload"},
            })
            if not last_result.get("retryable") or attempt >= attempts:
                return last_result

            # 403/429 会打开 BrowserSession 熔断。保留服务端刚下发的 CF Cookie，
            # 只清除本地熔断并在同一会话内退避重试。
            _clear_plan_circuit(env)
            err_msg_lower = str(last_result.get("error", "")).lower()
            if any(k in err_msg_lower for k in ("ssl", "connect", "proxy", "tunnel", "closed abruptly")):
                try:
                    rotated_proxy, _ = rotate_proxy_session(route["proxy"])
                    if rotated_proxy and rotated_proxy != route["proxy"]:
                        route["proxy"] = rotated_proxy
                        env = BrowserSession(proxy=rotated_proxy, detect_exit_geo=False, fingerprint_seed=task_seed)
                        logger.info("[Plan] 遇到网络/代理连接异常，已自动轮换新代理会话重试：%s", _mask_proxy(rotated_proxy))
                except Exception as rot_exc:
                    logger.debug("[Plan] 轮换代理异常: %s", rot_exc)
            wait_seconds = _retry_wait_seconds(resp, base_delay, attempt)
            logger.warning(
                "套餐查询临时失败，第 %s/%s 次，保留 session/deviceId/CF Cookie，%.1fs 后重试: %s",
                attempt,
                attempts,
                wait_seconds,
                last_result.get("error"),
            )
            if wait_seconds > 0:
                time.sleep(wait_seconds)
    except Exception as exc:
        logger.debug("套餐查询会话初始化失败: %s: %s", type(exc).__name__, exc, exc_info=True)
        return {
            "ok": False,
            "checked_at": now_iso(),
            "http_status": None,
            "error": f"{type(exc).__name__}: {exc}",
            "retryable": True,
            "attempt_count": 0,
            "max_attempts": attempts,
            "request_timeout": timeout_seconds,
            **route_meta,
            **{k: v for k, v in claims.items() if k != "payload"},
        }
    finally:
        if env is not None:
            try:
                env.session.close()
            except Exception:
                pass

    return last_result or {
        "ok": False,
        "checked_at": now_iso(),
        "http_status": None,
        "error": "套餐查询未执行",
        "retryable": False,
        **route_meta,
        **{k: v for k, v in claims.items() if k != "payload"},
    }
