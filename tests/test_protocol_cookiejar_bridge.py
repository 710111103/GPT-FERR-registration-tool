from pathlib import Path

BRIDGE = Path(__file__).resolve().parents[1] / "vendor" / "gpt-register-tool" / "协议" / "_turb_bridge.py"


def test_browser_cookie_transfer_uses_underlying_cookiejar():
    source = BRIDGE.read_text(encoding="utf-8")
    assert source.count('getattr(flow.session.cookies, "jar", None)') >= 2
    assert "for cookie in list(flow.session.cookies):" not in source
    assert "for c in list(flow.session.cookies):" not in source

def test_empty_protocol_session_triggers_browser_recovery():
    source = BRIDGE.read_text(encoding="utf-8")
    assert 'recovery_reason = "协议返回空 Session"' in source
    assert 'if session_token or access_token:\n                return result' in source
    assert '_browser_finish_callback(self, "", consume_callback=False)' in source



def test_authflow_initializes_sentinel_token():
    auth_flow = BRIDGE.parent / "auth_flow.py"
    source = auth_flow.read_text(encoding="utf-8")
    assert 'self._last_sentinel_token = ""' in source


def test_protocol_registration_default_start_gap_is_fifteen_seconds():
    source = BRIDGE.read_text(encoding="utf-8")
    assert 'os.environ.get("TURB_START_GAP", "15")' in source
    assert "gap = 15.0" in source
    assert "默认 15 秒" in source

