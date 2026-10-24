import json
import threading
from types import SimpleNamespace

from core import task_observability as obs
from core.session import BrowserSession


def test_probe_records_first_failure_and_context_traffic(tmp_path, monkeypatch):
    monkeypatch.setattr(obs, "_ROOT", tmp_path)
    probe = obs.ProbeSession("plan_check", 42, email="one@example.com")
    with probe.activate():
        probe.mark("plan_query", "started")
        obs.record_http_traffic("https://chatgpt.com/backend-api/accounts/check", 120, 880, 403)
        probe.mark("plan_query", "failed", error="HTTP 403 cf-mitigated challenge")
    summary = probe.finish("failed", error="HTTP 403")

    assert summary["first_failure_stage"] == "plan_query"
    assert summary["first_failure_category"] == "http_403_challenge"
    assert summary["traffic"]["request_count"] == 1
    assert summary["traffic"]["total_bytes"] == 1000
    assert summary["traffic"]["by_host"]["chatgpt.com"]["statuses"]["403"] == 1
    events = obs.read_events("plan_check", 42)
    assert [event["stage"] for event in events] == ["plan_query", "plan_query", "task"]


def test_probe_redacts_tokens_and_proxy_credentials(tmp_path, monkeypatch):
    monkeypatch.setattr(obs, "_ROOT", tmp_path)
    probe = obs.ProbeSession("live_check", "mail@example.com")
    probe.mark(
        "login", "failed",
        error="Bearer abc.def password=hello proxy=https://user:pass@host:443",
        access_token="secret-token",
    )
    raw = probe.path.read_text(encoding="utf-8")
    assert "abc.def" not in raw
    assert "password=hello" not in raw
    assert "user:pass@" not in raw
    assert "secret-token" not in raw


def test_browser_session_reports_per_host_traffic_to_active_probe(tmp_path, monkeypatch):
    monkeypatch.setattr(obs, "_ROOT", tmp_path)
    session = object.__new__(BrowserSession)
    session.upload_bytes = 0
    session.download_bytes = 0
    session.request_count = 0
    session.traffic_by_host = {}
    session._trace_path = None
    session._trace_lock = threading.Lock()
    response = SimpleNamespace(
        status_code=200,
        content=b"response-body",
        headers={"content-type": "application/json"},
    )
    probe = obs.ProbeSession("registration", 7)
    with probe.activate():
        session._record_traffic(
            "https://auth.openai.com/api/accounts/password",
            {"x-test": "1"},
            {"password": "hidden"},
            response,
        )

    traffic = session.get_network_traffic()
    assert traffic["request_count"] == 1
    assert traffic["by_host"]["auth.openai.com"]["request_count"] == 1
    assert probe.traffic()["by_host"]["auth.openai.com"]["request_count"] == 1


def _environment_summary(**updates):
    result = {
        "device_id": "device-a",
        "proxy": "http://user:password@proxy.example:3000",
        "proxy_mode": "proxy",
        "geo_ip": "203.0.113.7",
        "geo_country": "JP",
        "geo_region": "13",
        "browser_family": "chrome",
        "browser_os": "macOS",
        "user_agent": "Mozilla/5.0 Chrome/140",
        "accept_language": "ja-JP,ja;q=0.9",
        "navigator_language": "ja-JP",
        "navigator_languages": ["ja-JP", "ja"],
        "timezone_iana": "Asia/Tokyo",
        "timezone_offset_minutes": 540,
        "screen_width": 1512,
        "screen_height": 982,
        "device_pixel_ratio": 2,
        "hardware_concurrency": 8,
        "device_memory": 8,
        "sec_ch_ua": '"Chromium";v="140"',
        "sec_ch_ua_platform": '"macOS"',
        "sec_ch_ua_platform_version": '"15.0.0"',
    }
    result.update(updates)
    return result


def test_environment_freeze_reports_only_real_drift(tmp_path, monkeypatch):
    monkeypatch.setattr(obs, "_ROOT", tmp_path)
    probe = obs.ProbeSession("registration", 88)
    first = probe.observe_environment(_environment_summary())
    same = probe.observe_environment(_environment_summary())
    changed = probe.observe_environment(_environment_summary(
        device_id="device-b", geo_ip="203.0.113.9", timezone_iana="Asia/Seoul",
    ))

    assert first == {"frozen": True, "changed": False, "differences": {}}
    assert same["changed"] is False
    assert changed["changed"] is True
    assert set(changed["differences"]) >= {"device_id", "geo_ip", "timezone_iana"}
    raw = probe.path.read_text(encoding="utf-8")
    assert "user:password@" not in raw


def test_runtime_environment_check_detects_profile_mismatch(tmp_path, monkeypatch):
    monkeypatch.setattr(obs, "_ROOT", tmp_path)
    probe = obs.ProbeSession("registration", 89)
    profile = _environment_summary()
    report = probe.observe_runtime(profile, {
        "language": "en-US",
        "timezone": "UTC",
        "screen": [1920, 1080, 1],
        "webdriver": True,
    })
    assert report["all_passed"] is False
    assert not any(report["checks"].values())
