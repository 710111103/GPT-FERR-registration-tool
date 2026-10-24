#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ChatGPT 支付方式 / 订阅 / 账单接口抓包。

用途：
    用库里账号的 access_token + 项目统一 BrowserSession 指纹环境（curl_cffi TLS 指纹 +
    UA/语言/时区画像 + oai-did Cookie），对「支付方式 / 订阅 / 交易 / 账单」候选端点矩阵
    逐个发只读请求，把 method / URL / 请求头 / 状态码 / 响应体完整落成 JSONL 抓包文件，
    再按结账会话级联到 Stripe 客户级接口。

    抓包结论用于确定哪些端点真实存在（404/405 同样落盘）、支付方式字段落在哪个 JSON 路径。

用法：
    # 用库内账号 id 抓包（最常用）
    python tools/capture_payments.py --account-id 1

    # 指定邮箱 / 直接给 token
    python tools/capture_payments.py --email foo@outlook.com
    python tools/capture_payments.py --token '<JWT>'

    # 只跑某一组：baseline / subscription / billing_config / payments / checkout / stripe
    python tools/capture_payments.py --account-id 1 --probe-only payments
    python tools/capture_payments.py --account-id 1 --probe-only baseline,subscription

    # 指定结账国家与代理；--proxy '' 表示直连
    python tools/capture_payments.py --account-id 1 --country IN --proxy ''

    # 打印关键响应体
    python tools/capture_payments.py --account-id 1 --pretty

说明：
    - 只发只读请求；结账接口只创建预览会话，不确认支付、不修改支付方式、不取消订阅。
    - 输出目录默认 注册日志/payment_capture/，JSONL 内 authorization/cookie 已脱敏。
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote, urlencode

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from core import db  # noqa: E402
from core import chatgpt_plan as plan  # noqa: E402
from core.session import BrowserSession  # noqa: E402

logger = logging.getLogger("capture_payments")

CHATGPT_BASE = "https://chatgpt.com"
STRIPE_API = "https://api.stripe.com/v1"
_OUT_DIR = _PROJECT_ROOT / "注册日志" / "payment_capture"
_MAX_BODY_CHARS = 20000
_STRIPE_ID_PREFIXES = ("cus_", "cs_", "sub_", "pm_", "in_", "pi_", "ch_", "price_", "prod_")
_PRETTY_PATHS = (
    "/backend-api/accounts/check",
    "/backend-api/subscriptions",
    "/backend-api/payments/checkout",
    "/backend-api/payments/payment_methods",
    "/backend-api/invoices",
    "/payment_pages/",
    "/v1/payment_methods",
)
# 抓包已确认真实存在的三个数据源端点（详见 --scan-accounts 输出结论）
CORE_ENDPOINTS = (
    ("payment_methods", "/backend-api/payments/payment_methods", True),
    ("invoices", "/backend-api/invoices", True),
    ("subscriptions", "/backend-api/subscriptions", True),
    ("customer_portal", "/backend-api/payments/customer_portal", False),
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _mask_secret(value: Any, left: int = 12, right: int = 6) -> str:
    text = str(value or "")
    if len(text) <= left + right:
        return "***" if text else ""
    return f"{text[:left]}...{text[-right:]}"


def _safe_headers(headers: Any) -> dict:
    """请求/响应头脱敏：authorization / cookie / 各类 key 只留前后片段。"""
    safe: dict[str, str] = {}
    for key, value in dict(headers or {}).items():
        name = str(key)
        lowered = name.lower()
        if lowered in {"authorization", "cookie", "set-cookie", "x-api-key", "api-key"}:
            safe[name] = _mask_secret(value)
        else:
            safe[name] = str(value)
    return safe


def _truncate(text: str, limit: int = _MAX_BODY_CHARS) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    return text[:limit], True


def _try_json(text: str) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return None


def _harvest_ids(payload: Any, found: dict[str, list[str]], depth: int = 0) -> None:
    """递归收集 Stripe 对象 id（cus_/cs_/sub_/... ），供结账级联使用。"""
    if depth > 12:
        return
    if isinstance(payload, dict):
        for key, value in payload.items():
            if isinstance(value, str) and any(value.startswith(p) for p in _STRIPE_ID_PREFIXES):
                bucket = found.setdefault(value[: value.index("_") + 1], [])
                if value not in bucket:
                    bucket.append(value)
            else:
                _harvest_ids(value, found, depth + 1)
    elif isinstance(payload, list):
        for item in payload:
            _harvest_ids(item, found, depth + 1)


def _json_keys(payload: Any, depth: int = 2) -> list[str]:
    """列出响应体的顶层（及一层嵌套）字段名，用于摘要表判断数据落点。"""
    keys: list[str] = []

    def walk(value: Any, prefix: str, level: int) -> None:
        if level > depth or not isinstance(value, dict):
            return
        for key, child in value.items():
            label = f"{prefix}{key}"
            keys.append(label)
            if isinstance(child, dict):
                walk(child, f"{label}.", level + 1)

    walk(payload, "", 1)
    return keys[:60]


class Capture:
    """JSONL 抓包落盘器：一条请求一行，写盘即刷新。"""

    def __init__(self, path: Path):
        self.path = path
        self.records: list[dict] = []
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.path.open("w", encoding="utf-8")

    def add(self, record: dict) -> dict:
        record["seq"] = len(self.records) + 1
        record.setdefault("ts", _now_iso())
        self.records.append(record)
        self._handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._handle.flush()
        return record

    def close(self) -> None:
        try:
            self._handle.close()
        except Exception:
            pass


def _chatgpt_headers(
    env: BrowserSession, token: str, claims: dict, path: str, *, json_body: bool = False,
) -> dict:
    headers = plan._common_headers(env, token, claims)
    headers["x-openai-target-path"] = path
    headers["x-openai-target-route"] = path
    if json_body:
        headers["content-type"] = "application/json"
    return headers


def _send(
    env: BrowserSession,
    capture: Capture,
    *,
    group: str,
    method: str,
    url: str,
    target_path: str,
    headers: dict,
    json_body: Any = None,
    data: Any = None,
    timeout: float,
    note: str = "",
) -> tuple[Any, Any]:
    """发一条请求并记录完整抓包；异常也落盘，返回 (response, parsed_json)。"""
    started = time.time()
    record: dict = {
        "group": group,
        "method": method.upper(),
        "url": url,
        "target_path": target_path,
        "request_headers": _safe_headers(headers),
        "request_body": json_body if json_body is not None else (data if data is not None else None),
        "note": note,
    }
    resp = None
    try:
        kwargs: dict = {"headers": headers, "allow_redirects": False, "timeout": timeout}
        if json_body is not None:
            kwargs["json"] = json_body
        if data is not None:
            kwargs["data"] = data
        resp = env.get(url, **kwargs) if method.upper() == "GET" else env.post(url, **kwargs)
        text = resp.text or ""
        body, truncated = _truncate(text)
        record.update({
            "status": int(resp.status_code),
            "reason": str(getattr(resp, "reason", "") or ""),
            "elapsed_ms": int((time.time() - started) * 1000),
            "response_headers": _safe_headers(resp.headers),
            "response_body": body,
            "response_truncated": truncated,
            "response_bytes": len(text.encode("utf-8", "ignore")),
        })
        parsed = _try_json(text)
        record["response_json"] = isinstance(parsed, (dict, list))
        if isinstance(parsed, (dict, list)):
            record["response_keys"] = _json_keys(parsed)
        capture.add(record)
        return resp, parsed
    except Exception as exc:
        record.update({
            "status": None,
            "elapsed_ms": int((time.time() - started) * 1000),
            "error": f"{type(exc).__name__}: {str(exc)[:300]}",
        })
        capture.add(record)
        logger.warning("[抓包] %s %s 请求异常: %s: %s", method.upper(), url, type(exc).__name__, str(exc)[:160])
        return None, None


def _build_chatgpt_matrix(country: str, account_id: str, timezone_offset_min: str) -> list[dict]:
    """ChatGPT backend-api 候选端点矩阵。account_id_variant 表示额外补一次带账号参数的请求。"""
    items: list[dict] = [
        {"group": "baseline", "method": "GET", "path": plan.ACCOUNTS_CHECK_PATH,
         "query": {"timezone_offset_min": timezone_offset_min}},
        {"group": "subscription", "method": "GET", "path": "/backend-api/subscriptions",
         "query": {"account_id": account_id} if account_id else {}},
        {"group": "billing_config", "method": "GET", "path": "/backend-api/pageConfigs/billing"},
        {"group": "billing_config", "method": "GET",
         "path": f"/backend-api/checkout_pricing_config/configs/{quote(country, safe='')}"},
        {"group": "payments", "method": "GET", "path": "/backend-api/payments/payment_methods",
         "account_id_variant": True},
        {"group": "payments", "method": "GET", "path": "/backend-api/payments/customer_portal",
         "account_id_variant": True},
        {"group": "payments", "method": "GET", "path": "/backend-api/invoices",
         "account_id_variant": True},
        {"group": "payments", "method": "GET", "path": "/backend-api/payments/transactions",
         "account_id_variant": True},
        {"group": "payments", "method": "GET", "path": "/backend-api/payments/invoices",
         "account_id_variant": True},
        {"group": "payments", "method": "GET", "path": "/backend-api/billing/subscription"},
        {"group": "payments", "method": "GET", "path": "/backend-api/payments/subscription"},
    ]

    expanded: list[dict] = []
    for item in items:
        expanded.append(item)
        if item.get("account_id_variant") and account_id:
            expanded.append({
                **item,
                "query": {**(item.get("query") or {}), "account_id": account_id},
                "note": "带 account_id 变体",
            })
    return expanded


def _run_chatgpt_matrix(
    env: BrowserSession, capture: Capture, token: str, claims: dict,
    *, country: str, account_id: str, timezone_offset_min: str, timeout: float, groups: set[str],
) -> tuple[dict[str, list[str]], dict[str, Any]]:
    ids: dict[str, list[str]] = {}
    responses: dict[str, Any] = {}
    for item in _build_chatgpt_matrix(country, account_id, timezone_offset_min):
        if groups and item["group"] not in groups:
            continue
        path = item["path"]
        query = {k: v for k, v in (item.get("query") or {}).items() if v}
        url = f"{CHATGPT_BASE}{path}" + (f"?{urlencode(query)}" if query else "")
        headers = _chatgpt_headers(env, token, claims, path)
        resp, parsed = _send(
            env, capture, group=item["group"], method=item["method"], url=url,
            target_path=path, headers=headers, timeout=timeout,
            note=item.get("note", ""),
        )
        responses[url] = parsed
        _harvest_ids(parsed, ids)
        status = int(getattr(resp, "status_code", 0) or 0)
        logger.info("[抓包] %-14s %s %s -> %s", item["group"], item["method"], path, status or "ERR")
    return ids, responses


def _run_checkout_cascade(
    env: BrowserSession, capture: Capture, token: str, claims: dict,
    *, country: str, campaign_id: str, timeout: float,
) -> tuple[dict[str, list[str]], dict[str, Any]]:
    """创建结账预览（只读）→ Stripe payment_pages init，读该会话开放的支付方式。"""
    ids: dict[str, list[str]] = {}
    responses: dict[str, Any] = {}
    if not campaign_id:
        logger.info("[抓包] checkout  跳过：该账号无可用于预览结账的活动 ID")
        return ids, responses

    currency = plan.COUNTRY_CURRENCIES.get(country, "USD")
    payload = {
        "entry_point": "all_plans_pricing_modal",
        "plan_name": "chatgptplusplan",
        "billing_details": {"country": country, "currency": currency},
        "promo_campaign": {"promo_campaign_id": campaign_id, "is_coupon_from_query_param": False},
        "checkout_ui_mode": "custom",
        "cancel_url": "https://chatgpt.com/#pricing",
    }
    headers = _chatgpt_headers(env, token, claims, plan.PAYMENTS_CHECKOUT_PATH, json_body=True)
    resp, checkout = _send(
        env, capture, group="checkout", method="POST",
        url=f"{CHATGPT_BASE}{plan.PAYMENTS_CHECKOUT_PATH}", target_path=plan.PAYMENTS_CHECKOUT_PATH,
        headers=headers, json_body=payload, timeout=timeout,
        note=f"结账预览（campaign={campaign_id}, country={country}）",
    )
    responses["checkout"] = checkout
    _harvest_ids(checkout, ids)
    logger.info(
        "[抓包] checkout       POST %s -> %s", plan.PAYMENTS_CHECKOUT_PATH,
        int(getattr(resp, "status_code", 0) or 0) or "ERR",
    )

    session_ids = ids.get("cs_") or []
    if not session_ids:
        logger.info("[抓包] stripe-init   跳过：结账响应未返回 cs_ 会话 ID")
        return ids, responses

    session_id = session_ids[0]
    url = plan.STRIPE_PAYMENT_PAGE_INIT.format(session_id=quote(session_id, safe=""))
    stripe_headers = {"content-type": "application/x-www-form-urlencoded"}
    data = {
        "browser_locale": "en-US",
        "browser_timezone": "UTC",
        "elements_session_client[elements_init_source]": "custom_checkout",
        "elements_session_client[referrer_host]": "chatgpt.com",
        "elements_session_client[stripe_js_id]": str(uuid.uuid4()),
        "elements_session_client[locale]": "en",
        "key": plan.STRIPE_PUBLISHABLE_KEY,
    }
    resp, init_data = _send(
        env, capture, group="checkout", method="POST", url=url,
        target_path=f"/payment_pages/{session_id}/init", headers=stripe_headers,
        data=data, timeout=timeout, note=f"Stripe 结账页初始化（{session_id}）",
    )
    responses["stripe_init"] = init_data
    _harvest_ids(init_data, ids)
    logger.info("[抓包] stripe-init    POST %s -> %s", f"/payment_pages/{session_id}/init",
                int(getattr(resp, "status_code", 0) or 0) or "ERR")
    return ids, responses


def _run_stripe_customer_cascade(
    env: BrowserSession, capture: Capture, ids: dict[str, list[str]], *, timeout: float,
) -> dict[str, Any]:
    """按结账响应里拿到的 Stripe 客户 id 读取客户级支付方式 / 订阅 / 账单。"""
    responses: dict[str, Any] = {}
    customers = ids.get("cus_") or []
    if not customers:
        logger.info("[抓包] stripe-customer 跳过：未提取到 cus_ 客户 ID")
        return responses

    customer = customers[0]
    public_key = plan.STRIPE_PUBLISHABLE_KEY
    endpoints = [
        ("payment_methods", f"{STRIPE_API}/payment_methods", {"customer": customer, "type": "card", "limit": "10"}),
        ("customer", f"{STRIPE_API}/customers/{quote(customer, safe='')}", {}),
        ("subscriptions", f"{STRIPE_API}/subscriptions", {"customer": customer, "limit": "10"}),
        ("invoices", f"{STRIPE_API}/invoices", {"customer": customer, "limit": "10"}),
        ("charges", f"{STRIPE_API}/charges", {"customer": customer, "limit": "10"}),
    ]
    for name, base_url, query in endpoints:
        params = {**query, "key": public_key}
        url = f"{base_url}?{urlencode(params)}"
        _, parsed = _send(
            env, capture, group="stripe_customer", method="GET", url=url,
            target_path=f"stripe:{name}", headers={}, timeout=timeout,
            note=f"Stripe 客户级查询（{name}, customer={customer}）",
        )
        responses[name] = parsed
        logger.info("[抓包] stripe:%-10s GET %s -> %s", name, name, "OK" if parsed is not None else "ERR")
    return responses


def _run_core_scan(
    env: BrowserSession, capture: Capture, *, timeout: float, scan_accounts: int,
) -> list[dict]:
    """跨账号扫描三个已确认端点，用于发现带真实支付方式/订阅/账单的样本，拿到完整字段结构。"""
    rows: list[dict] = []
    scanned = 0
    for account in db.list_accounts(limit=int(scan_accounts) or 1):
        token = plan.normalize_token(account.get("access_token") or "")
        account_uuid = str(account.get("account_id") or "").strip()
        if not token:
            continue
        if not account_uuid:
            claims = plan.token_claims(token)
            account_uuid = str(claims.get("account_id") or "").strip()
        if not account_uuid:
            continue
        scanned += 1
        claims = plan.token_claims(token)
        row: dict = {"id": account.get("id"), "email": account.get("email")}
        for name, path, needs_account in CORE_ENDPOINTS:
            query = {"account_id": account_uuid} if needs_account else {}
            url = f"{CHATGPT_BASE}{path}" + (f"?{urlencode(query)}" if query else "")
            headers = _chatgpt_headers(env, token, claims, path)
            resp, parsed = _send(
                env, capture, group="scan", method="GET", url=url, target_path=f"{name}|{path}",
                headers=headers, timeout=timeout, note=f"跨账号扫描 id={account.get('id')}",
            )
            status = int(getattr(resp, "status_code", 0) or 0)
            row[name] = {
                "status": status,
                "count": _data_count(name, parsed),
                "has_data": bool(_data_count(name, parsed)),
                "detail": (parsed or {}).get("detail") if isinstance(parsed, dict) else None,
            }
        rows.append(row)
        logger.info(
            "[扫描] id=%-4s %s -> 支付方式=%s 账单=%s 订阅=%s",
            row.get("id"), row.get("email"),
            row["payment_methods"]["status"], row["invoices"]["status"], row["subscriptions"]["status"],
        )
        time.sleep(0.5)
    logger.info("[扫描] 共扫描 %s 个账号", scanned)
    return rows


def _data_count(name: str, payload: Any) -> int:
    """按端点语义统计有效数据条数（区别于路由不存在）。"""
    if not isinstance(payload, dict):
        return 0
    if name == "payment_methods":
        methods = payload.get("payment_methods")
        return len(methods) if isinstance(methods, list) else 0
    if name == "invoices":
        data = payload.get("data")
        return len(data) if isinstance(data, list) else 0
    if name == "subscriptions":
        return 1 if payload.get("id") or payload.get("subscription_id") else 0
    if name == "customer_portal":
        return 1 if payload.get("url") else 0
    return 0


def _print_scan_table(rows: list[dict]) -> None:
    if not rows:
        return
    print("\n" + "=" * 108)
    print(f"{'库内id':<8}{'email':<38}{'支付方式':<14}{'账单':<14}{'订阅':<14}客户门户")
    print("-" * 108)
    for row in rows:
        def cell(name: str) -> str:
            item = row.get(name) or {}
            status = item.get("status")
            count = item.get("count") or 0
            return f"{status}/{count}条" if status else "ERR"
        print(
            f"{str(row.get('id')):<8}{str(row.get('email'))[:36]:<38}"
            f"{cell('payment_methods'):<14}{cell('invoices'):<14}{cell('subscriptions'):<14}"
            f"{cell('customer_portal')}"
        )
    print("-" * 108)
    samples = [r for r in rows if (r.get("payment_methods") or {}).get("has_data")
               or (r.get("subscriptions") or {}).get("has_data")]
    if samples:
        print("含真实数据的账号（可用于提取完整字段结构）：")
        for row in samples:
            print(f"  id={row.get('id')} {row.get('email')}")
    else:
        print("本次扫描没有任何账号返回支付方式/订阅数据 —— 全库均为未绑卡 free 账号。")
    print("=" * 108 + "\n")


def _print_summary(capture: Capture) -> None:
    print("\n" + "=" * 108)
    print(f"{'组':<16}{'方法':<6}{'状态':<7}{'耗时ms':<9}端点")
    print("-" * 108)
    for record in capture.records:
        status = record.get("status")
        status_text = str(status) if status is not None else "ERR"
        path = record.get("target_path") or record.get("url", "")
        print(
            f"{record.get('group', ''):<16}{record.get('method', ''):<6}"
            f"{status_text:<7}{record.get('elapsed_ms', 0):<9}{path}"
        )
    print("-" * 108)
    ok = sum(1 for r in capture.records if isinstance(r.get("status"), int) and 200 <= r["status"] < 300)
    print(f"共 {len(capture.records)} 条请求，2xx {ok} 条，抓包文件：{capture.path}")
    print("=" * 108 + "\n")


def _print_pretty(capture: Capture, responses: dict[str, Any]) -> None:
    for label, payload in responses.items():
        if payload is None:
            continue
        if not any(token in str(label) for token in _PRETTY_PATHS):
            continue
        print(f"\n----- {label} -----")
        print(json.dumps(payload, ensure_ascii=False, indent=2)[:4000])


def _write_summary(capture: Capture, out_dir: Path, stamp: str, ids: dict[str, list[str]]) -> Path:
    summary = {
        "created_at": _now_iso(),
        "capture_file": str(capture.path),
        "request_count": len(capture.records),
        "stripe_ids": ids,
        "endpoints": [
            {
                "group": r.get("group"),
                "method": r.get("method"),
                "target_path": r.get("target_path"),
                "status": r.get("status"),
                "elapsed_ms": r.get("elapsed_ms"),
                "response_keys": r.get("response_keys"),
                "error": r.get("error"),
                "note": r.get("note"),
            }
            for r in capture.records
        ],
    }
    path = out_dir / f"summary-{stamp}.json"
    path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _load_account(args) -> tuple[str, str, str]:
    """返回 (token, chatgpt_account_id, email)。

    注意区分两个 id：`--account-id` 是库内账号主键（用于取 token），
    而请求里要用的 `account_id` 是 ChatGPT 账号 UUID（来自账号 payload 或 JWT claims）。
    """
    token = plan.normalize_token(args.token or "")
    email = str(args.email or "").strip()
    db_pk = str(args.account_id or "").strip()

    if not token:
        account = None
        if db_pk:
            account = db.get_account(int(db_pk))
        elif email:
            account = db.get_account_by_email(email)
        else:
            for candidate in db.list_accounts(limit=int(getattr(args, "limits", 200) or 200)):
                if str(candidate.get("access_token") or "").strip():
                    account = candidate
                    break
        if not account:
            raise SystemExit("未找到可用账号：请传 --account-id / --email / --token，或确认库内有带 access_token 的账号")
        token = plan.normalize_token(account.get("access_token") or "")
        email = email or str(account.get("email") or "")
        logger.info(
            "[账号] 从数据库取用: 库内 id=%s email=%s chatgpt_account_id=%s",
            account.get("id"), email, account.get("account_id") or "-",
        )

    if not token:
        raise SystemExit("账号缺少 access_token，请换一个账号或直接传 --token")

    claims = plan.token_claims(token)
    account_id = str(getattr(args, "chatgpt_account_id", None) or claims.get("account_id") or "").strip()
    email = email or str(claims.get("email") or "")
    if claims.get("token_expired") is True:
        logger.warning("[账号] 该 access_token 已过期，抓包可能全部返回 401，建议先查活刷新")
    if not account_id:
        logger.warning("[账号] 未能解析出 ChatGPT account_id，带账号参数的端点会返回校验错误")
    logger.info(
        "[账号] email=%s chatgpt_account_id=%s plan=%s token=%s",
        email or "-", account_id or "-", claims.get("claim_plan_type") or "-", _mask_secret(token),
    )
    return token, account_id, email


def main() -> int:
    parser = argparse.ArgumentParser(
        description="ChatGPT 支付方式/订阅/账单接口抓包",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--account-id", default=None, help="库内账号主键 id（用于取 access_token）")
    parser.add_argument("--chatgpt-account-id", default=None, help="直接指定 ChatGPT 账号 UUID，默认从 token 解析")
    parser.add_argument("--email", default=None, help="库内账号邮箱")
    parser.add_argument("--token", default=None, help="直接指定 access_token（优先于账号查询）")
    parser.add_argument("--country", default=None, help="结账国家代码，默认取代理出口国家，兜底 US")
    parser.add_argument("--timezone-offset-min", default="-", help="accounts/check 的时区偏移，默认 '-' 自动")
    parser.add_argument(
        "--probe-only", default="",
        help="只跑指定组，逗号分隔：baseline,subscription,billing_config,payments,checkout,stripe_customer",
    )
    parser.add_argument("--proxy", default=None, help="代理；不传按 PLAN_CHECK_PROXY_MODE 解析；传空字符串强制直连")
    parser.add_argument("--timeout", type=float, default=None, help="单请求超时秒数，默认沿用 PLAN_CHECK_TIMEOUT")
    parser.add_argument("--out-dir", default=str(_OUT_DIR), help="抓包输出目录")
    parser.add_argument("--limits", type=int, default=200, help="从库内挑选账号时的扫描上限")
    parser.add_argument("--pretty", action="store_true", help="额外打印关键响应体")
    parser.add_argument(
        "--scan-accounts", type=int, default=0,
        help="跨账号扫描三个已确认端点（支付方式/账单/订阅），找出带真实数据的样本",
    )
    parser.add_argument("--verbose", action="store_true", help="显示 DEBUG 日志")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    groups = {g.strip() for g in str(args.probe_only or "").split(",") if g.strip()}
    unknown = groups - {"baseline", "subscription", "billing_config", "payments", "checkout", "stripe_customer"}
    if unknown:
        raise SystemExit(f"--probe-only 含未知组: {', '.join(sorted(unknown))}")

    token, account_id, email = _load_account(args)
    claims = plan.token_claims(token)

    route = plan.resolve_plan_check_route(args.proxy)
    timeout = (args.timeout if args.timeout is not None
               else plan._plan_check_settings(None, None, None)[0])
    logger.info(
        "[网络] route=%s proxy=%s timeout=%.0fs",
        route.get("network_route"), route.get("proxy_used") or "direct", timeout,
    )

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = Path(args.out_dir)
    capture = Capture(out_dir / f"capture-{stamp}.jsonl")

    env: Optional[BrowserSession] = None
    try:
        env = BrowserSession(
            proxy=route["proxy"], detect_exit_geo=True,
            fingerprint_seed=f"payment-capture:{email or account_id}:{uuid.uuid4()}",
        )
        exit_geo = getattr(env, "exit_geo", {}) or {}
        exit_country = str(exit_geo.get("country") or "").upper()
        country = str(args.country or exit_country or "US").upper()
        logger.info(
            "[网络] 出口=%s/%s 结账国家=%s device_id=%s",
            exit_geo.get("ip") or "-", exit_country or "-", country, str(env.device_id)[:12] + "...",
        )
        if args.country and exit_country and country != exit_country:
            logger.warning("[网络] 指定国家 %s 与代理出口 %s 不一致，结账预览可能被风控拦截", country, exit_country)

        plan._warm_plan_session(env)

        timezone_offset_min = str(args.timezone_offset_min or "-").strip()
        if not timezone_offset_min or timezone_offset_min == "-":
            timezone_offset_min = str(env.js_timezone_offset_min())

        scan_rows: list[dict] = []
        responses: dict[str, Any] = {}
        ids: dict[str, list[str]] = {}
        if args.scan_accounts:
            scan_rows = _run_core_scan(
                env, capture, timeout=timeout, scan_accounts=int(args.scan_accounts),
            )
        else:
            ids, responses = _run_chatgpt_matrix(
                env, capture, token, claims,
                country=country, account_id=account_id, timezone_offset_min=timezone_offset_min,
                timeout=timeout, groups=groups,
            )
            if not groups or "checkout" in groups:
                probe_campaign = plan.UPI_TRIAL_CAMPAIGN_ID if country == "IN" else ""
                checkout_ids, checkout_responses = _run_checkout_cascade(
                    env, capture, token, claims, country=country,
                    campaign_id=probe_campaign, timeout=timeout,
                )
                for prefix, values in checkout_ids.items():
                    ids.setdefault(prefix, [])
                    ids[prefix].extend(v for v in values if v not in ids[prefix])
                responses.update({f"checkout.{k}": v for k, v in checkout_responses.items()})

            if not groups or "stripe_customer" in groups:
                stripe_responses = _run_stripe_customer_cascade(env, capture, ids, timeout=timeout)
                responses.update({f"stripe.{k}": v for k, v in stripe_responses.items()})
    finally:
        capture.close()
        if env is not None:
            closer = getattr(env, "close", None)
            if callable(closer):
                try:
                    closer()
                except Exception:
                    pass

    _print_summary(capture)
    if scan_rows:
        _print_scan_table(scan_rows)
    if ids:
        print("[结账级联] 提取到的对象 ID：")
        for prefix, values in sorted(ids.items()):
            print(f"  {prefix:<8}{', '.join(values[:5])}")
    summary_path = _write_summary(capture, out_dir, stamp, ids)
    print(f"[摘要] {summary_path}")
    if args.pretty:
        _print_pretty(capture, responses)
    return 0


if __name__ == "__main__":
    sys.exit(main())
