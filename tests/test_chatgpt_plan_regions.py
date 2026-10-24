from unittest.mock import patch

from core import chatgpt_plan


class _Response:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload

    @property
    def text(self):
        import json
        return json.dumps(self._payload)


def test_probe_trial_payment_methods_reads_stripe_session_methods():
    class Env:
        def get_chatgpt_headers(self, **kwargs):
            return {"content-type": "application/json"}

        def post(self, url, **kwargs):
            if "payments/checkout" in url:
                return _Response({"checkout_session_id": "cs_test_123"})
            return _Response({
                "currency": "jpy", "amount_due": 0,
                "payment_method_types": ["card", "paypal"],
                "payment_method_specs": {"konbini": {}},
            })

    result = chatgpt_plan.probe_trial_payment_methods(
        Env(), "token", {}, country="JP", campaign_id="plus-trial", timeout=10,
    )
    assert result["payment_probe_ok"] is True
    assert result["trial_payment_methods"] == ["card", "paypal", "konbini"]
    assert result["checkout_currency"] == "JPY"
    assert result["checkout_amount_minor"] == 0


def test_probe_trial_payment_methods_reports_risk_block():
    class Env:
        def get_chatgpt_headers(self, **kwargs):
            return {}

        def post(self, url, **kwargs):
            return _Response({"detail": "Our systems have detected unusual activity. Please try again later."}, 400)

    result = chatgpt_plan.probe_trial_payment_methods(
        Env(), "token", {}, country="JP", campaign_id="trial", timeout=10,
    )
    assert result["payment_probe_ok"] is False
    assert result["payment_probe_blocked"] is True
    assert result["payment_probe_error"] == "支付检测受风控拦截"


def test_probe_trial_payment_methods_detects_upi_trial_without_using_renewal_amount():
    class Env:
        def get_chatgpt_headers(self, **kwargs):
            return {}

        def post(self, url, **kwargs):
            if "payments/checkout" in url:
                return _Response({"checkout_session_id": "cs_test_upi"})
            return _Response({
                "currency": "inr",
                "amount_due": 0,
                "payment_method_types": ["card", "upi"],
            })

    result = chatgpt_plan.probe_trial_payment_methods(
        Env(), "token", {}, country="IN", campaign_id="plus-1-month-free", timeout=10,
    )
    assert result["upi_trial_eligible"] is True
    assert result["upi_method_available"] is True
    assert result["upi_trial_status"] == "verified"
    assert result["upi_trial_verified"] is True
    assert result["upi_approval_status"] == "not_requested"
    assert result["checkout_amount_minor"] == 0


def test_probe_trial_payment_methods_reports_missing_upi_for_india():
    class Env:
        def get_chatgpt_headers(self, **kwargs):
            return {}

        def post(self, url, **kwargs):
            if "payments/checkout" in url:
                return _Response({"checkout_session_id": "cs_test_card"})
            return _Response({"currency": "inr", "payment_method_types": ["card"]})

    result = chatgpt_plan.probe_trial_payment_methods(
        Env(), "token", {}, country="IN", campaign_id="plus-1-month-free", timeout=10,
    )
    assert result["upi_trial_eligible"] is False
    assert result["upi_method_available"] is False
    assert result["upi_trial_status"] in ("upi_unavailable", "paid_only")


def test_india_upi_probe_uses_known_campaign_when_accounts_check_has_no_campaign():
    parsed = {"plus_trial_eligible": False, "plus_trial_campaign_id": None}
    assert chatgpt_plan._payment_probe_campaign(parsed, "IN") == "plus-1-month-free"


def test_non_india_probe_still_requires_accounts_check_eligibility():
    parsed = {"plus_trial_eligible": False, "plus_trial_campaign_id": None}
    assert chatgpt_plan._payment_probe_campaign(parsed, "JP") == ""


def test_parse_accounts_check_extracts_declared_payment_methods():
    result = chatgpt_plan.parse_accounts_check({"accounts": {"default": {
        "account": {"plan_type": "free"},
        "eligible_promo_campaigns": {"plus": {"id": "trial", "metadata": {}}},
        "eligible_offers": {"offers": [{"id": "plus", "supported_payment_methods": ["card", "apple_pay"]}]},
    }}})
    assert result["plus_trial_eligible"] is True
    assert result["trial_payment_methods"] == ["card", "apple_pay"]


def test_discount_offer_is_not_free_trial():
    result = chatgpt_plan.parse_accounts_check({"accounts": {"default": {
        "account": {"plan_type": "free"},
        "eligible_promo_campaigns": {"go": {
            "id": "go-2-months-50-pct-off",
            "metadata": {"title": "Get a 50% discount on Go for 2 months", "discount": {"percentage": 50}},
        }},
    }}})
    assert result["plus_trial_eligible"] is False
    assert result["discount_offer_eligible"] is True
    assert result["discount_offer_campaign_id"] == "go-2-months-50-pct-off"
    assert result["discount_offer_percentage"] == 50


def test_free_trial_and_discount_offer_can_be_reported_separately():
    result = chatgpt_plan.parse_accounts_check({"accounts": {"default": {
        "account": {"plan_type": "free"},
        "eligible_promo_campaigns": {
            "plus": {"id": "plus-1-month-free", "metadata": {"discount": {"percentage": 100}}},
            "go": {"id": "go-2-months-50-pct-off", "metadata": {"discount": {"percentage": 50}}},
        },
    }}})
    assert result["plus_trial_eligible"] is True
    assert result["plus_trial_campaign_id"] == "plus-1-month-free"
    assert result["discount_offer_eligible"] is True
    assert result["discount_offer_campaign_id"] == "go-2-months-50-pct-off"


def test_check_account_plan_regions_keeps_partial_success():
    responses = [
        {"ok": True, "plus_trial_eligible": True, "trial_payment_methods": ["card"]},
        {"ok": False, "error": "HTTP 403"},
    ]
    with patch.object(chatgpt_plan, "check_account_plan", side_effect=responses) as check:
        result = chatgpt_plan.check_account_plan_regions("token", [("US", "http://u:p@us:1"), ("JP", "http://u:p@jp:2")])
    assert result["ok"] is True
    assert result["plus_trial_eligible"] is True
    assert result["region_results"]["JP"]["error"] == "HTTP 403"
    assert check.call_count == 2


def test_configured_country_proxies_rejects_duplicate_country(monkeypatch):
    from config import proxy
    monkeypatch.setattr(proxy, "PLAN_CHECK_COUNTRY_PROXIES", ["US|http://one", "US|http://two"])
    try:
        chatgpt_plan.configured_country_proxies()
    except ValueError as exc:
        assert "国家重复" in str(exc)
    else:
        raise AssertionError("duplicate country should fail")


def test_inferred_upi_on_payment_probe_blocked():
    accounts_check_resp = _Response({
        "accounts": {
            "default": {
                "account": {"plan_type": "free"},
                "eligible_promo_campaigns": {"plus": {"id": "plus-1-month-free", "metadata": {}}},
            }
        }
    })
    checkout_blocked_resp = _Response(
        {"detail": "Our systems have detected unusual activity. Please try again later."},
        400,
    )

    class FakeSession:
        def __init__(self, **kwargs):
            self.device_id = "test-device"
            self.oai_session_id = "test-session"
            self.exit_geo = {"country": "IN", "city": "Mumbai", "ip": "1.2.3.4"}
            self.cookies = {}

        def js_timezone_offset_min(self):
            return -330

        def fingerprint_summary_text(self):
            return "fake"

        def get_chatgpt_navigate_headers(self, **kwargs):
            return {}

        def get_chatgpt_headers(self, **kwargs):
            return {"content-type": "application/json"}

        def get(self, url, **kwargs):
            return accounts_check_resp

        def post(self, url, **kwargs):
            return checkout_blocked_resp

    with patch.object(chatgpt_plan, "BrowserSession", FakeSession), \
         patch.object(chatgpt_plan, "_warm_plan_session"):
        result = chatgpt_plan.check_account_plan(
            "dummy_token", proxy="http://127.0.0.1:8080", billing_country="IN"
        )
    assert result["ok"] is True
    assert result["payment_probe_ok"] is False
    assert result["payment_probe_blocked"] is True
    assert result["upi_trial_eligible"] is False
    assert result["upi_trial_status"] == "blocked"
    assert result["payment_probe_error"] == "支付检测受风控拦截"


def test_proxy_url_region_fallback_when_exit_geo_empty():
    accounts_check_resp = _Response({
        "accounts": {
            "default": {
                "account": {"plan_type": "free"},
                "eligible_promo_campaigns": {"plus": {"id": "plus-1-month-free", "metadata": {}}},
            }
        }
    })
    checkout_blocked_resp = _Response(
        {"detail": "Our systems have detected unusual activity. Please try again later."},
        400,
    )

    class FakeSession:
        def __init__(self, **kwargs):
            self.device_id = "test-device"
            self.oai_session_id = "test-session"
            # exit_geo is empty, e.g. geoip timed out
            self.exit_geo = {}
            self.cookies = {}

        def js_timezone_offset_min(self):
            return -330

        def fingerprint_summary_text(self):
            return "fake"

        def get_chatgpt_navigate_headers(self, **kwargs):
            return {}

        def get_chatgpt_headers(self, **kwargs):
            return {"content-type": "application/json"}

        def get(self, url, **kwargs):
            return accounts_check_resp

        def post(self, url, **kwargs):
            return checkout_blocked_resp

    with patch.object(chatgpt_plan, "BrowserSession", FakeSession), \
         patch.object(chatgpt_plan, "_warm_plan_session"):
        result = chatgpt_plan.check_account_plan(
            "dummy_token",
            proxy="http://user-region-IN:pass@cliproxy.io:3010",
            billing_country="IN",
        )
    assert result["ok"] is True
    assert result["proxy_exit_country"] == "IN"
    assert result["payment_probe_ok"] is False
    assert result["payment_probe_blocked"] is True
    assert result["upi_trial_eligible"] is False
    assert result["upi_trial_status"] == "blocked"



def test_rotate_proxy_session_replaces_clipproxy_sid():
    source = "http://user-region-JP-sid-fixed-t-5:pass@proxy.test:3010"
    rotated, session_id = chatgpt_plan.rotate_proxy_session(source)
    assert session_id
    assert "-sid-fixed-t-" not in rotated
    assert f"-sid-{session_id}-t-" in rotated
    assert rotated.endswith("@proxy.test:3010")


def test_rotate_proxy_session_leaves_plain_proxy_unchanged():
    source = "http://user:pass@proxy.test:3010"
    assert chatgpt_plan.rotate_proxy_session(source) == (source, None)
