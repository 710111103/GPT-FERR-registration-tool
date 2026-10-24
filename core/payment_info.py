# -*- coding: utf-8 -*-
"""ChatGPT 账号支付方式 / 账单 / 订阅只读查询。

端点均由 tools/capture_payments.py 实际抓包确认（2026-09-18）：

    GET /backend-api/payments/payment_methods?account_id=<uuid>
        200 {"payment_methods": [], "default_payment_method_id": null,
             "backup_payment_method_enabled": null, "one_click_trial_eligible": false}
    GET /backend-api/invoices?account_id=<uuid>
        200 {"data": [], "has_more": false}
    GET /backend-api/subscriptions?account_id=<uuid>
        404 {"detail": "No subscription found for account"}   ← 路由存在，仅无订阅
    GET /backend-api/payments/customer_portal
        200 {"url": "https://pay.openai.com/p/session?secret=live_..."}
        404 {"detail": "No payment methods found"}             ← 路由存在，仅无支付档案

抓包同时确认以下端点**不存在**（404 {"detail": "Not Found"}，不要再调用）：
    /backend-api/payments/transactions、/backend-api/payments/invoices、
    /backend-api/billing/subscription、/backend-api/payments/subscription

注意：抓包时全库 37 个账号均为 free 且未绑卡，payment_methods / invoices / subscriptions
三处返回的一律是空集合，因此**条目内部的字段结构尚未被实测样本验证**，解析函数按容错方式
提取多种候选键名，并把原始条目放回 raw 字段，避免形状未知时丢数据。
"""
from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime
from typing import Any, Optional
from urllib.parse import urlencode

from core import chatgpt_plan as plan
from core.session import BrowserSession

logger = logging.getLogger(__name__)

PAYMENT_METHODS_PATH = "/backend-api/payments/payment_methods"
INVOICES_PATH = "/backend-api/invoices"
SUBSCRIPTIONS_PATH = "/backend-api/subscriptions"
CUSTOMER_PORTAL_PATH = "/backend-api/payments/customer_portal"
BILLING_INFO_PATH = "/backend-api/payments/billing_info"
TRANSACTIONS_PATH = "/backend-api/payments/transaction-history"
CODEX_USAGE_PATH = "/backend-api/wham/usage"

# 抓包确认不存在的端点，仅用于文档与端口探测结果标注
KNOWN_MISSING_PATHS = (
    "/backend-api/payments/transactions",
    "/backend-api/payments/invoices",
    "/backend-api/billing/subscription",
    "/backend-api/payments/subscription",
)

_ROUTE_MISSING_DETAIL = "not found"


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _headers(env: BrowserSession, token: str, claims: dict, path: str) -> dict:
    headers = plan._common_headers(env, token, claims)
    headers["x-openai-target-path"] = path
    headers["x-openai-target-route"] = path
    return headers


def _request(
    env: BrowserSession, token: str, claims: dict, path: str, *, query: dict, timeout: float,
) -> dict:
    """发一条只读 GET，返回 {status, payload, error, path}。"""
    params = {k: v for k, v in (query or {}).items() if v}
    url = f"https://chatgpt.com{path}" + (f"?{urlencode(params)}" if params else "")
    try:
        resp = env.get(url, headers=_headers(env, token, claims, path),
                       allow_redirects=False, timeout=timeout)
    except Exception as exc:
        return {"status": None, "payload": None, "error": f"{type(exc).__name__}: {str(exc)[:160]}", "path": path}
    text = resp.text or ""
    try:
        payload: Any = resp.json()
    except Exception:
        payload = None
    return {"status": int(resp.status_code), "payload": payload, "text": text[:400], "error": None, "path": path}


def _classify(result: dict) -> tuple[str, str]:
    """把一次请求归类为 ok / empty / missing / error。

    抓包确认：路由不存在返回 {"detail": "Not Found"}；业务层空数据返回
    {"detail": "No subscription found for account"} 这类具体说明 —— 两者都可能是 404，
    必须区分，否则会把「该账号没有订阅」误判成「接口没了」。
    """
    status = result.get("status")
    if status is None:
        return "error", result.get("error") or "请求异常"
    payload = result.get("payload")
    detail = ""
    if isinstance(payload, dict):
        detail = str(payload.get("detail") or "").strip()
    if 200 <= int(status) < 300:
        return "ok", ""
    if int(status) == 404:
        if detail.lower() == _ROUTE_MISSING_DETAIL or not detail:
            return "missing", detail or "路由不存在"
        return "empty", detail
    if int(status) == 400 and "must be supplied" in detail:
        return "error", detail
    return "error", detail or f"HTTP {status}"


def _pick(mapping: Any, keys: tuple[str, ...], default: Any = None) -> Any:
    if not isinstance(mapping, dict):
        return default
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return default


def _normalize_payment_method(item: Any, *, default_id: str = "") -> dict:
    """归一化单条支付方式。

    字段结构未经实测样本验证（全库账号均未绑卡），因此同时尝试多组候选键名，
    并保留 raw 原文。
    """
    if not isinstance(item, dict):
        return {"type": "unknown", "raw": item}
    card = _pick(item, ("card", "card_details", "billing_details", "payment_method_details"), {}) or {}
    method_id = str(_pick(item, ("id", "payment_method_id", "pm_id"), "") or "")
    method_type = str(
        _pick(item, ("type", "payment_method_type", "method_type", "wallet_type"), "") or ""
    ).strip().lower()
    brand = str(
        _pick(card, ("brand", "card_brand", "network"), "")
        or _pick(item, ("brand", "card_brand"), "")
        or ""
    ).strip()
    last4 = str(
        _pick(card, ("last4", "last_4", "card_last4"), "")
        or _pick(item, ("last4", "last_4"), "")
        or ""
    ).strip()
    expiry = _pick(card, ("exp", "expiry", "expires"), None)
    is_default = bool(_pick(item, ("is_default", "default", "is_default_payment_method"), False))
    if not is_default and method_id and default_id:
        is_default = method_id == default_id
    return {
        "id": method_id,
        "type": method_type or ("card" if brand or last4 else "unknown"),
        "brand": brand,
        "last4": last4,
        "exp_month": _pick(card, ("exp_month", "expiry_month"), None),
        "exp_year": _pick(card, ("exp_year", "expiry_year"), None),
        "expires_at": expiry,
        "is_default": is_default,
        "raw": item,
    }


def format_payment_methods(methods: list[dict]) -> str:
    """把归一化后的支付方式压成一行短文本，供列表展示。"""
    if not methods:
        return "未绑卡"
    parts: list[str] = []
    for method in methods:
        label = ""
        if method.get("type") == "card" or method.get("brand") or method.get("last4"):
            brand = str(method.get("brand") or "card").upper()
            label = f"{brand} ****{method.get('last4')}" if method.get("last4") else brand
        else:
            label = str(method.get("type") or "unknown").upper()
        if method.get("is_default"):
            label += "(默认)"
        parts.append(label)
    return " / ".join(parts)


def _normalize_subscription(payload: Any) -> dict | None:
    if not isinstance(payload, dict) or not payload:
        return None
    if not (_pick(payload, ("id", "subscription_id"), None) or _pick(payload, ("plan", "plan_type"), None)):
        return None
    plan_info = _pick(payload, ("plan", "plan_type", "price"), {}) or {}
    return {
        "id": _pick(payload, ("id", "subscription_id"), ""),
        "status": _pick(payload, ("status", "state"), ""),
        "plan": plan_info if isinstance(plan_info, str) else _pick(plan_info, ("id", "nickname", "product"), ""),
        "billing_period": _pick(payload, ("billing_period", "interval", "period"), ""),
        "currency": str(_pick(payload, ("currency", "billing_currency"), "") or "").upper(),
        "amount": _pick(payload, ("amount", "amount_minor", "unit_amount"), None),
        "current_period_end": _pick(payload, ("current_period_end", "renews_at", "expires_at"), None),
        "cancel_at": _pick(payload, ("cancel_at", "cancels_at", "canceled_at"), None),
        "raw": payload,
    }


def _normalize_invoices(payload: Any) -> tuple[list[dict], bool]:
    if not isinstance(payload, dict):
        return [], False
    data = payload.get("data")
    if not isinstance(data, list):
        data = payload.get("invoices") if isinstance(payload.get("invoices"), list) else []
    invoices: list[dict] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        invoices.append({
            "id": _pick(item, ("id", "invoice_id"), ""),
            "number": _pick(item, ("number", "invoice_number"), ""),
            "status": _pick(item, ("status", "state"), ""),
            "amount": _pick(item, ("amount_due", "amount_paid", "total", "amount"), None),
            "currency": str(_pick(item, ("currency",), "") or "").upper(),
            "created_at": _pick(item, ("created", "created_at", "date"), None),
            "url": _pick(item, ("hosted_invoice_url", "invoice_pdf", "url"), ""),
        })
    return invoices, bool(payload.get("has_more"))


def _extract_processor(accounts_check: Any, account_id: str) -> dict:
    """从 accounts/check 读取支付处理器状态。

    processor.a001.has_customer_object 是抓包确认的关键位：为 True 时
    /backend-api/payments/customer_portal 才会返回账单门户链接。
    """
    if not isinstance(accounts_check, dict):
        return {}
    accounts = accounts_check.get("accounts")
    if not isinstance(accounts, dict):
        return {}
    item = None
    if account_id and isinstance(accounts.get(account_id), dict):
        item = accounts[account_id]
    elif isinstance(accounts.get("default"), dict):
        item = accounts["default"]
    else:
        item = next((v for k, v in accounts.items() if k != "default" and isinstance(v, dict)), None)
    if not isinstance(item, dict):
        return {}
    account = item.get("account") or {}
    processor = account.get("processor")
    if not isinstance(processor, dict):
        processor = {}
    primary = processor.get("a001") if isinstance(processor.get("a001"), dict) else {}
    history = [
        bool(value.get("has_transaction_history"))
        for key, value in processor.items()
        if isinstance(value, dict) and key != "a001"
    ]
    return {
        "has_customer_object": bool(primary.get("has_customer_object")),
        "processor_entity": primary.get("processor_entity"),
        "has_transaction_history": any(history),
        "has_previously_paid_subscription": account.get("has_previously_paid_subscription"),
    }


def _failure_reason(states: dict, endpoint_status: dict, endpoint_notes: dict) -> str:
    """把失败端点压成一行可读原因。

    没有这一步时 ok=False 的返回体里没有任何 error，前端和日志只能看到「未知错误」，
    排查时无法区分「代理挂了 / TLS 指纹不被支持 / 被风控」。
    """
    parts: list[str] = []
    for name, state in states.items():
        if state in {"ok", "empty"}:
            continue
        status = endpoint_status.get(name)
        status_text = str(status) if isinstance(status, int) else "请求异常"
        detail = str(endpoint_notes.get(name) or "").strip()
        parts.append(f"{name} HTTP {status_text}" + (f": {detail}" if detail else ""))
    return "；".join(parts[:3]) or "支付方式查询失败，未返回具体原因"


def fetch_payment_profile(
    env: BrowserSession,
    token: str,
    claims: dict,
    *,
    timeout: float = 15.0,
) -> dict:
    """读取账号的支付方式 / 账单 / 订阅 / 账单门户（全部只读）。"""
    account_id = str((claims or {}).get("account_id") or "").strip()
    token = plan.normalize_token(token)
    if not account_id:
        return {"ok": False, "checked_at": now_iso(), "error": "token 中缺少 chatgpt_account_id"}

    endpoint_status: dict[str, Any] = {}
    endpoint_notes: dict[str, str] = {}
    endpoint_states: dict[str, str] = {}
    unavailable: list[str] = []

    def call(path: str, *, with_account: bool = True, key: str = "", extra_query: dict | None = None) -> dict:
        q = {"account_id": account_id} if with_account else {}
        if extra_query:
            q.update(extra_query)
        result = _request(
            env, token, claims, path,
            query=q, timeout=timeout,
        )
        state, detail = _classify(result)
        endpoint_states[key or path] = state
        endpoint_status[key or path] = result.get("status")
        if detail:
            endpoint_notes[key or path] = detail
        if state == "missing" and (key in {"payment_methods", "invoices", "subscriptions", "customer_portal", "accounts_check"}):
            unavailable.append(key or path)
        return {"state": state, "detail": detail, **result}

    methods_result = call(PAYMENT_METHODS_PATH, key="payment_methods")
    billing_result = call(BILLING_INFO_PATH, key="billing_info")
    transactions_result = call(TRANSACTIONS_PATH, extra_query={"limit": 20}, key="transactions")
    invoices_result = call(INVOICES_PATH, key="invoices")
    subscriptions_result = call(SUBSCRIPTIONS_PATH, key="subscriptions")
    usage_result = call(CODEX_USAGE_PATH, with_account=False, key="codex_usage")
    portal_result = call(CUSTOMER_PORTAL_PATH, with_account=False, key="customer_portal")
    check_result = call(plan.ACCOUNTS_CHECK_PATH, with_account=False, key="accounts_check")

    is_token_expired = any(
        endpoint_status.get(k) == 401 or "token_expired" in str(endpoint_notes.get(k) or "").lower()
        for k in ("payment_methods", "accounts_check", "codex_usage", "subscriptions", "billing_info", "transactions")
    )

    methods_payload = methods_result.get("payload") if methods_result["state"] == "ok" else None
    raw_methods = methods_payload.get("payment_methods") if isinstance(methods_payload, dict) else None
    default_id = str(
        (methods_payload or {}).get("default_payment_method_id") or ""
    ) if isinstance(methods_payload, dict) else ""
    methods = [
        _normalize_payment_method(item, default_id=default_id)
        for item in (raw_methods if isinstance(raw_methods, list) else [])
    ]

    billing_payload = billing_result.get("payload") if billing_result["state"] == "ok" else None
    billing_info = billing_payload if isinstance(billing_payload, dict) else {}

    transactions_payload = transactions_result.get("payload") if transactions_result["state"] == "ok" else None
    transactions_list = transactions_payload.get("transactions") if isinstance(transactions_payload, dict) and isinstance(transactions_payload.get("transactions"), list) else []

    usage_payload = usage_result.get("payload") if usage_result["state"] == "ok" else None
    usage_info = usage_payload if isinstance(usage_payload, dict) else {}

    invoices, has_more = _normalize_invoices(
        invoices_result.get("payload") if invoices_result["state"] == "ok" else None
    )
    subscription = _normalize_subscription(
        subscriptions_result.get("payload") if subscriptions_result["state"] == "ok" else None
    )
    portal_payload = portal_result.get("payload") if portal_result["state"] == "ok" else None
    portal_url = str((portal_payload or {}).get("url") or "") if isinstance(portal_payload, dict) else ""

    processor = _extract_processor(
        check_result.get("payload") if check_result["state"] == "ok" else None, account_id
    )

    reachable = [k for k, v in endpoint_status.items() if isinstance(v, int) and 200 <= v < 300]
    hard_errors = [
        k for k, v in endpoint_status.items()
        if not isinstance(v, int) or v >= 500
    ]
    ok = bool(
        not is_token_expired
        and endpoint_states.get("payment_methods") in {"ok", "empty"}
        and endpoint_states.get("accounts_check") in {"ok", "empty"}
    )
    error_msg = "AT已过期/失效 (token_expired)" if is_token_expired else ("" if ok else _failure_reason(endpoint_states, endpoint_status, endpoint_notes))
    return {
        "ok": ok,
        "error": error_msg,
        "token_expired": is_token_expired,
        "checked_at": now_iso(),
        "account_id": account_id,
        "payment_methods": methods,
        "payment_methods_text": format_payment_methods(methods),
        "has_payment_method": bool(methods),
        "default_payment_method_id": default_id or None,
        "backup_payment_method_enabled": (
            (methods_payload or {}).get("backup_payment_method_enabled")
            if isinstance(methods_payload, dict) else None
        ),
        "one_click_trial_eligible": bool(
            (methods_payload or {}).get("one_click_trial_eligible")
            if isinstance(methods_payload, dict) else False
        ),
        "billing_info": billing_info,
        "transactions": transactions_list,
        "codex_usage": usage_info,
        "invoices": invoices,
        "invoices_has_more": has_more,
        "invoice_count": len(invoices),
        "subscription": subscription,
        "portal_url": portal_url,
        "endpoint_status": endpoint_status,
        "endpoint_notes": endpoint_notes,
        "endpoint_unavailable": unavailable,
        "reachable_endpoints": reachable,
        "hard_error_endpoints": hard_errors,
        **processor,
        # 抓包时无绑卡样本，支付方式条目内部结构未经实测验证
        "shape_verified": False,
    }


def check_account_payment_profile(
    token: str,
    *,
    proxy: Optional[str] = None,
    timeout: float | None = None,
    max_attempts: int | None = None,
) -> dict:
    """带指纹会话、代理路由与重试的支付信息查询入口（与套餐查询同策略）。"""
    token = plan.normalize_token(token)
    if not token:
        return {"ok": False, "checked_at": now_iso(), "error": "token 为空"}
    claims = plan.token_claims(token)
    if claims.get("token_expired") is True:
        return {
            "ok": False,
            "checked_at": now_iso(),
            "error": "AT已过期/失效，请手动查活刷新",
            "needs_live_check": True,
            **{k: v for k, v in claims.items() if k != "payload"},
        }

    try:
        route = plan.resolve_plan_check_route(proxy)
    except Exception as exc:
        return {
            "ok": False, "checked_at": now_iso(),
            "error": f"支付查询网络配置错误: {exc}",
            **{k: v for k, v in claims.items() if k != "payload"},
        }
    route_meta = {k: v for k, v in route.items() if k != "proxy"}

    try:
        timeout_seconds, attempts, base_delay = plan._plan_check_settings(timeout, max_attempts, None)
    except Exception as exc:
        return {
            "ok": False, "checked_at": now_iso(),
            "error": f"支付查询重试配置错误: {exc}",
            "retryable": False,
            **route_meta,
            **{k: v for k, v in claims.items() if k != "payload"},
        }

    identity = str(claims.get("email") or claims.get("account_id") or token[:32]).lower()
    env: BrowserSession | None = None
    last_result: dict | None = None
    try:
        env = BrowserSession(
            proxy=route["proxy"], detect_exit_geo=True,
            fingerprint_seed=f"payment-check:{identity}:{uuid.uuid4()}",
        )
        plan._warm_plan_session(env)
        for attempt in range(1, attempts + 1):
            try:
                result = fetch_payment_profile(env, token, claims, timeout=timeout_seconds)
                result.update({
                    "attempt_count": attempt,
                    "max_attempts": attempts,
                    "request_timeout": timeout_seconds,
                    **route_meta,
                    **{k: v for k, v in claims.items() if k != "payload"},
                })
                if result.get("ok"):
                    return result
                last_result = result
            except Exception as exc:
                last_result = {
                    "ok": False, "checked_at": now_iso(),
                    "error": f"{type(exc).__name__}: {str(exc)[:180]}",
                }
                logger.debug("支付信息查询失败: %s: %s", type(exc).__name__, exc, exc_info=True)

            last_result = last_result or {"ok": False, "checked_at": now_iso(), "error": "未知错误"}
            last_result.update({
                "attempt_count": attempt,
                "max_attempts": attempts,
                "request_timeout": timeout_seconds,
                **route_meta,
                **{k: v for k, v in claims.items() if k != "payload"},
            })
            if attempt >= attempts:
                break
            plan._clear_plan_circuit(env)
            wait_seconds = max(0.0, min(30.0, base_delay * attempt))
            if wait_seconds > 0:
                time.sleep(wait_seconds)
        return last_result or {"ok": False, "checked_at": now_iso(), "error": "未知错误"}
    except Exception as exc:
        logger.debug("支付信息会话初始化失败: %s: %s", type(exc).__name__, exc, exc_info=True)
        return {
            "ok": False, "checked_at": now_iso(),
            "error": f"{type(exc).__name__}: {str(exc)[:180]}",
            **route_meta,
            **{k: v for k, v in claims.items() if k != "payload"},
        }
