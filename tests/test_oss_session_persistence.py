from core import account_export, register_protocol_engine
from core.oss_protocol_registration import run_oss_protocol_registration


def test_oss_registration_persists_session_artifacts(monkeypatch):
    captured = {}

    register_call = {}

    def fake_register(*args, **kwargs):
        register_call.update(kwargs)
        return {
            "ok": True,
            "result": {
                "access_token": "at-value",
                "password": "registered-password",
                "totp_secret": "TOTPSECRET",
                "session_token": "st-value",
                "cookie_header": "__Secure-next-auth.session-token=st-value; oai-did=did",
            },
            "network_traffic": {"available": True, "total_bytes": 123},
        }

    monkeypatch.setattr(register_protocol_engine, "register", fake_register)

    def fake_save_account_data(**kwargs):
        captured.update(kwargs)
        return 4321

    monkeypatch.setattr(account_export, "save_account_data", fake_save_account_data)

    result = run_oss_protocol_registration(
        email="fixture@example.test",
        name="",
        birthday=None,
        proxy="http://127.0.0.1:8080",
        relay_url="https://mail.example.test/inbox",
        email_source="icloud_relay",
        batch_dir=None,
        on_email_acquired=None,
    )

    assert result["success"] is True
    assert result["account_id"] == 4321
    assert register_call["want_2fa"] is True
    assert captured["access_token"] == "at-value"
    assert captured["totp_secret"] == "TOTPSECRET"
    assert captured["extra"]["registration_password"] == "registered-password"
    assert captured["extra"]["registration_password_verified"] is True
    assert captured["extra"]["totp_setup_ok"] is True
    assert result["password_saved"] is True
    assert result["twofa_enabled"] is True
    assert captured["extra"]["session_token"] == "st-value"
    assert captured["extra"]["cookie_header"].startswith("__Secure-next-auth.session-token=")
    assert captured["extra"]["network_traffic"]["total_bytes"] == 123
    assert captured["plan_check_proxy"] == "http://127.0.0.1:8080"


def test_oss_registration_deduplicates_proxy_pool(monkeypatch):
    from config import proxy as proxy_cfg

    register_call = {}

    def fake_register(*args, **kwargs):
        register_call.update(kwargs)
        return {
            "ok": True,
            "result": {"access_token": "at", "password": "pw"},
        }

    monkeypatch.setattr(register_protocol_engine, "register", fake_register)
    monkeypatch.setattr(account_export, "save_account_data", lambda **kwargs: 1)
    duplicate = "http://user:pass@proxy.example:8080"
    other = "http://user:pass@other.example:8080"
    monkeypatch.setattr(proxy_cfg, "PROXY_POOL", [duplicate, duplicate, other])

    result = run_oss_protocol_registration(
        email="fixture@example.test",
        name="",
        birthday=None,
        proxy=None,
        relay_url="https://mail.example.test/inbox",
        email_source="icloud_relay",
        batch_dir=None,
        on_email_acquired=None,
    )

    assert result["success"] is True
    assert register_call["proxy_pool"].splitlines() == [duplicate, other]
