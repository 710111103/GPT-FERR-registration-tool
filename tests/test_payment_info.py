# -*- coding: utf-8 -*-
"""core/payment_info.py 解析层测试。

fixture 取自 2026-09-18 的真实抓包（注册日志/payment_capture/capture-*.jsonl），
token / account_id / portal secret 已脱敏，其余字段与状态码保持原样。

抓包结论（决定了下面哪些分支必须覆盖）：
    - payment_methods / invoices 恒为 200；free 未绑卡账号返回空集合。
    - subscriptions / customer_portal 在「无订阅 / 无支付档案」时返回 404，
      但 detail 是业务说明而不是 "Not Found" —— 必须落 empty 而不是 missing。
    - payments/transactions、payments/invoices、billing/subscription、
      payments/subscription 四个端点返回 404 {"detail": "Not Found"}，属真正不存在。
"""
from unittest.mock import patch

from core import chatgpt_plan as plan
from core import payment_info


ACCOUNT_ID = "00000000-1111-2222-3333-444444444444"
TOKEN = "eyJhbGciOiJIUzI1NiJ9.redacted.redacted"


class _Response:
    def __init__(self, payload, status_code=200, text=""):
        self._payload = payload
        self.status_code = status_code
        self.text = text or ""

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class _Env:
    """假 BrowserSession：按 (path, 是否有 account_id) 路由到预置响应。"""

    def __init__(self, routes, *, record=None):
        self._routes = routes
        self._record = record if record is not None else []
        self.exit_geo = {}

    def get_chatgpt_headers(self, **kwargs):
        return {"content-type": "application/json", "user-agent": "pytest"}

    def get(self, url, **kwargs):
        path = url.split("chatgpt.com", 1)[-1].split("?", 1)[0]
        self._record.append(kwargs.get("headers", {}).get("x-openai-target-path") or path)
        item = self._routes.get(path)
        if item is None:
            return _Response({"detail": "Not Found"}, 404)
        if callable(item):
            return item(url, kwargs)
        return item


# ---- 抓包实测的 5 个端点响应 ------------------------------------------------

ACCOUNTS_CHECK_NO_PROFILE = {
    "accounts": {
        ACCOUNT_ID: {
            "account": {
                "plan_type": "free",
                "is_paid_subscription_active": False,
                "processor": {"a001": {"has_customer_object": False}},
            }
        }
    }
}

ACCOUNTS_CHECK_WITH_PROFILE = {
    "accounts": {
        ACCOUNT_ID: {
            "account": {
                "plan_type": "free",
                "has_previously_paid_subscription": False,
                "processor": {
                    "a001": {
                        "has_customer_object": True,
                        "processor_entity": "openai_ie",
                    }
                },
            }
        }
    }
}


def _free_unbound_routes(accounts_check=ACCOUNTS_CHECK_NO_PROFILE):
    """未绑卡 free 账号：payment_methods/invoices 空集合，订阅与门户走业务 404。"""
    return {
        payment_info.PAYMENT_METHODS_PATH: _Response({
            "payment_methods": [],
            "default_payment_method_id": None,
            "backup_payment_method_enabled": None,
            "one_click_trial_eligible": False,
        }),
        payment_info.INVOICES_PATH: _Response({"data": [], "has_more": False}),
        payment_info.SUBSCRIPTIONS_PATH: _Response(
            {"detail": "No subscription found for account"}, 404
        ),
        payment_info.CUSTOMER_PORTAL_PATH: _Response(
            {"detail": "No payment methods found"}, 404
        ),
        plan.ACCOUNTS_CHECK_PATH: _Response(accounts_check),
    }


# ---- 未绑卡账号 -------------------------------------------------------------


def test_fetch_payment_profile_free_unbound_account():
    record: list[str] = []
    env = _Env(_free_unbound_routes(), record=record)
    result = payment_info.fetch_payment_profile(env, TOKEN, {"account_id": ACCOUNT_ID})

    assert result["ok"] is True
    assert result["account_id"] == ACCOUNT_ID
    assert result["payment_methods"] == []
    assert result["payment_methods_text"] == "未绑卡"
    assert result["has_payment_method"] is False
    assert result["one_click_trial_eligible"] is False
    assert result["invoice_count"] == 0
    assert result["subscription"] is None
    assert result["portal_url"] == ""
    assert result["has_customer_object"] is False
    assert result["shape_verified"] is False

    # 业务层 404（有具体 detail）不能算「接口不存在」
    assert result["endpoint_unavailable"] == []
    assert result["endpoint_notes"]["subscriptions"] == "No subscription found for account"
    assert result["endpoint_notes"]["customer_portal"] == "No payment methods found"
    assert result["endpoint_status"]["payment_methods"] == 200
    assert result["endpoint_status"]["subscriptions"] == 404
    assert result["hard_error_endpoints"] == []

    # 只请求抓包确认存在的 5 个端点，绝不请求已确认缺失的路径
    for missing in payment_info.KNOWN_MISSING_PATHS:
        assert missing not in record


def test_fetch_payment_profile_reports_has_customer_object_and_portal():
    routes = _free_unbound_routes(ACCOUNTS_CHECK_WITH_PROFILE)
    routes[payment_info.CUSTOMER_PORTAL_PATH] = _Response({
        "url": "https://pay.openai.com/p/session?secret=live_redacted",
    })
    env = _Env(routes)
    result = payment_info.fetch_payment_profile(env, TOKEN, {"account_id": ACCOUNT_ID})

    assert result["ok"] is True
    assert result["has_customer_object"] is True
    assert result["processor_entity"] == "openai_ie"
    assert result["portal_url"] == "https://pay.openai.com/p/session?secret=live_redacted"


def test_fetch_payment_profile_flags_truly_missing_route():
    routes = _free_unbound_routes()
    routes[payment_info.PAYMENT_METHODS_PATH] = _Response({"detail": "Not Found"}, 404)
    env = _Env(routes)
    result = payment_info.fetch_payment_profile(env, TOKEN, {"account_id": ACCOUNT_ID})

    assert "payment_methods" in result["endpoint_unavailable"]
    assert result["ok"] is False
    assert "payment_methods HTTP 404" in result["error"]


def test_fetch_payment_profile_requires_account_id():
    env = _Env({})
    result = payment_info.fetch_payment_profile(env, TOKEN, {})
    assert result["ok"] is False
    assert "chatgpt_account_id" in result["error"]


def test_fetch_payment_profile_marks_hard_error_endpoint():
    routes = _free_unbound_routes()
    routes[payment_info.INVOICES_PATH] = _Response({"detail": "boom"}, 500)
    env = _Env(routes)
    result = payment_info.fetch_payment_profile(env, TOKEN, {"account_id": ACCOUNT_ID})

    assert "invoices" in result["hard_error_endpoints"]
    assert result["endpoint_status"]["invoices"] == 500
    # 5xx 不能污染已成功的 payment_methods
    assert result["payment_methods_text"] == "未绑卡"
    # 单个非阻塞端点失败不影响整体 ok
    assert result["ok"] is True
    assert result["error"] == ""


def test_fetch_payment_profile_surfaces_exception_reason():
    """会话级异常（如 TLS 指纹不被支持）必须落到 error，不能只剩 ok=False。"""
    def _boom(url, kwargs):
        raise RuntimeError("ImpersonateError: Impersonating chrome146 is not supported")

    routes = {path: _boom for path in (
        payment_info.PAYMENT_METHODS_PATH,
        payment_info.INVOICES_PATH,
        payment_info.SUBSCRIPTIONS_PATH,
        payment_info.CUSTOMER_PORTAL_PATH,
        plan.ACCOUNTS_CHECK_PATH,
    )}
    env = _Env(routes)
    result = payment_info.fetch_payment_profile(env, TOKEN, {"account_id": ACCOUNT_ID})

    assert result["ok"] is False
    assert result["error"]
    assert "ImpersonateError" in result["error"]
    assert "payment_methods HTTP 请求异常" in result["error"]
    assert result["endpoint_status"]["payment_methods"] is None
    assert set(result["hard_error_endpoints"]) == {
        "payment_methods", "invoices", "subscriptions", "customer_portal", "accounts_check",
    }


# ---- 支付方式归一化（结构未经实测，只验证容错与多候选键名） -----------------


def test_normalize_payment_method_card_shape():
    method = payment_info._normalize_payment_method(
        {
            "id": "pm_1",
            "type": "card",
            "card": {"brand": "visa", "last4": "4242", "exp_month": 12, "exp_year": 2027},
        },
        default_id="pm_1",
    )
    assert method["type"] == "card"
    assert method["brand"] == "visa"
    assert method["last4"] == "4242"
    assert method["exp_month"] == 12
    assert method["is_default"] is True
    assert method["raw"]["id"] == "pm_1"


def test_format_payment_methods_shapes():
    assert payment_info.format_payment_methods([]) == "未绑卡"
    assert payment_info.format_payment_methods([
        {"type": "card", "brand": "visa", "last4": "4242", "is_default": True},
        {"type": "card", "brand": "mastercard", "last4": "4444", "is_default": False},
    ]) == "VISA ****4242(默认) / MASTERCARD ****4444"
    assert payment_info.format_payment_methods([
        {"type": "paypal", "brand": "", "last4": "", "is_default": False},
    ]) == "PAYPAL"


def test_normalize_payment_method_keeps_unknown_shape():
    method = payment_info._normalize_payment_method({"weird_field": 1})
    assert method["type"] == "unknown"
    assert method["raw"] == {"weird_field": 1}


def test_fetch_payment_profile_reads_payment_method_shape():
    routes = _free_unbound_routes()
    routes[payment_info.PAYMENT_METHODS_PATH] = _Response({
        "payment_methods": [{
            "id": "pm_card_1",
            "type": "card",
            "card": {"brand": "visa", "last4": "4242", "exp_month": 8, "exp_year": 2029},
        }],
        "default_payment_method_id": "pm_card_1",
        "backup_payment_method_enabled": True,
        "one_click_trial_eligible": True,
    })
    env = _Env(routes)
    result = payment_info.fetch_payment_profile(env, TOKEN, {"account_id": ACCOUNT_ID})

    assert result["has_payment_method"] is True
    assert result["payment_methods_text"] == "VISA ****4242(默认)"
    assert result["default_payment_method_id"] == "pm_card_1"
    assert result["backup_payment_method_enabled"] is True
    assert result["one_click_trial_eligible"] is True


# ---- 订阅 / 账单 归一化 -----------------------------------------------------


def test_fetch_payment_profile_reads_subscription_and_invoices():
    routes = _free_unbound_routes()
    routes[payment_info.SUBSCRIPTIONS_PATH] = _Response({
        "id": "sub_1",
        "status": "active",
        "plan": {"id": "plus", "nickname": "ChatGPT Plus"},
        "billing_period": "monthly",
        "currency": "usd",
        "amount": 2000,
        "current_period_end": "2026-10-18T00:00:00Z",
    })
    routes[payment_info.INVOICES_PATH] = _Response({
        "data": [{
            "id": "in_1",
            "number": "INV-0001",
            "status": "paid",
            "amount_paid": 2000,
            "currency": "usd",
            "created": "2026-09-18T00:00:00Z",
            "hosted_invoice_url": "https://pay.openai.com/invoice/redacted",
        }],
        "has_more": False,
    })
    env = _Env(routes)
    result = payment_info.fetch_payment_profile(env, TOKEN, {"account_id": ACCOUNT_ID})

    assert result["subscription"]["id"] == "sub_1"
    assert result["subscription"]["status"] == "active"
    assert result["subscription"]["currency"] == "USD"
    assert result["subscription"]["current_period_end"] == "2026-10-18T00:00:00Z"
    assert result["invoice_count"] == 1
    assert result["invoices"][0]["number"] == "INV-0001"
    assert result["invoices"][0]["url"] == "https://pay.openai.com/invoice/redacted"
    assert result["invoices_has_more"] is False


def test_normalize_subscription_ignores_empty_payload():
    assert payment_info._normalize_subscription(None) is None
    assert payment_info._normalize_subscription({}) is None
    assert payment_info._normalize_subscription({"unrelated": 1}) is None


# ---- check_account_payment_profile 入口 ------------------------------------


def test_check_account_payment_profile_rejects_empty_token():
    result = payment_info.check_account_payment_profile("   ")
    assert result["ok"] is False
    assert result["error"] == "token 为空"


def test_check_account_payment_profile_reports_expired_token():
    claims = {
        "email": "user@example.com",
        "account_id": ACCOUNT_ID,
        "token_expired": True,
        "token_expires_at": "2020-01-01T00:00:00Z",
        "payload": {"secret": "must-not-leak"},
    }
    with patch.object(payment_info.plan, "token_claims", return_value=claims):
        result = payment_info.check_account_payment_profile(TOKEN)
    assert result["ok"] is False
    assert result["needs_live_check"] is True
    assert "payload" not in result


def test_check_account_payment_profile_runs_with_fake_session():
    claims = {"email": "user@example.com", "account_id": ACCOUNT_ID, "token_expired": False}
    captured = {}

    class _Session:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def get_chatgpt_headers(self, **kwargs):
            return {"content-type": "application/json"}

        def get(self, url, **kwargs):
            path = url.split("chatgpt.com", 1)[-1].split("?", 1)[0]
            return _free_unbound_routes().get(path, _Response({"detail": "Not Found"}, 404))

    with patch.object(payment_info.plan, "token_claims", return_value=claims), \
         patch.object(payment_info, "BrowserSession", _Session), \
         patch.object(payment_info.plan, "resolve_plan_check_route",
                      return_value={"proxy": None, "network_route": "direct", "proxy_mode": "direct"}) as route_mock, \
         patch.object(payment_info.plan, "_warm_plan_session", return_value=None):
        result = payment_info.check_account_payment_profile(TOKEN, timeout=5, max_attempts=1)

    assert route_mock.called
    assert captured["proxy"] is None
    assert captured["detect_exit_geo"] is True
    assert captured["fingerprint_seed"].startswith("payment-check:user@example.com:")
    assert result["ok"] is True
    assert result["network_route"] == "direct"
    assert result["attempt_count"] == 1
    assert result["payment_methods_text"] == "未绑卡"
