from pathlib import Path

BRIDGE = Path(__file__).resolve().parents[1] / "vendor" / "gpt-register-tool" / "协议" / "_turb_bridge.py"
AUTH = Path(__file__).resolve().parents[1] / "vendor" / "gpt-register-tool" / "协议" / "auth_flow.py"


def test_warmup_browser_fallback_requires_real_oai_did_cookie():
    source = BRIDGE.read_text(encoding="utf-8")
    assert "_orig_warmup = AuthFlow.warmup" in source
    assert 'required_cookie="oai-did"' in source
    assert 'if ok and cookies.get("oai-did"):' in source
    assert "return _orig_warmup(self)" in source
    assert "AuthFlow.warmup = _patched_warmup" in source


def test_browser_fallback_uses_the_proxy_of_the_latest_protocol_session():
    bridge = BRIDGE.read_text(encoding="utf-8")
    auth = AUTH.read_text(encoding="utf-8")
    assert 'getattr(flow, "_active_proxy", "")' in bridge
    assert "self._active_proxy = config.proxy" in auth
    assert "self._active_proxy = self._next_proxy()" in auth
    assert "proxy=self._active_proxy" in auth


def test_authenticated_proxy_is_split_for_playwright():
    source = BRIDGE.read_text(encoding="utf-8")
    assert 'out = {"server": f"{scheme}://{host}{port}"}' in source
    assert 'out["username"] = unquote(parsed.username)' in source
    assert 'out["password"] = unquote(parsed.password)' in source


def test_single_proxy_is_not_rejected_by_curl_before_browser_warmup():
    source = BRIDGE.read_text(encoding="utf-8")
    assert "if len(candidates) == 1 and not _WREQ_ON:" in source
    assert "proxy, nprobe = candidates[0], 0" in source
    assert "交给浏览器 warmup 验证" in source


def test_callback_browser_consumes_one_time_code_before_protocol_fallback():
    source = BRIDGE.read_text(encoding="utf-8")
    assert "_orig_consume_callback = AuthFlow._consume_callback_for_session" in source
    assert "session_json = _browser_finish_callback(" in source
    assert "protocol_ok = _orig_consume_callback(self, callback_url)" in source
    patched = source.split("def _patched_consume_callback(self, callback_url):", 1)[1]
    assert patched.index("session_json = _browser_finish_callback(") < patched.index("protocol_ok = _orig_consume_callback(self, callback_url)")
    assert 'if getattr(self, "_turb_callback_navigation_started", False):' in patched
    assert "callback 已由浏览器请求，未重复消费一次性 code" in patched
    assert 'name.startswith("__Host-")' in source
    assert 'name.startswith("__Secure-")' in source
    assert 'item.update({"url": "https://" + host, "secure": True})' in source
    assert "AuthFlow._consume_callback_for_session = _patched_consume_callback" in source
    assert "if _gate_enabled:" in source
    assert "AuthFlow._consume_callback_for_session = _patched_consume_callback" in source.split("if _gate_enabled:", 1)[1]


def test_callback_browser_polls_session_and_backfills_auth_result_without_logging_secrets():
    source = BRIDGE.read_text(encoding="utf-8")
    assert "fetch('/api/auth/session'" in source
    assert "flow.result.access_token = access_token" in source
    assert "flow.result.session_token = session_token" in source
    assert "flow.result.cookie_header = flow._build_chatgpt_cookie_header()" in source
    assert '"有" if access_token else "无"' in source
    assert 'access_token=%s' in source


def test_partial_registration_error_identifies_oauth_session_tail_failure():
    bridge = BRIDGE.read_text(encoding="utf-8")
    auth = AUTH.read_text(encoding="utf-8")
    expected = "账号与密码已创建，但 OAuth Session 收尾失败，未取得 AT/Cookie；账号已保存为待补凭证"
    assert expected in bridge
    assert expected in auth
    assert "多半是卡在等验证码/绑定 2FA" not in bridge



def test_callback_imports_secure_oauth_cookies_and_logs_nonsecret_navigation_result():
    source = BRIDGE.read_text(encoding="utf-8")
    assert '"secure": True' in source
    assert "callback 浏览器导航: mode=%s status=%s final_host=%s imported_cookies=%d" in source
    assert 'urlparse(page.url or "").hostname' in source


def test_callback_tail_recovery_does_not_reconsume_one_time_code():
    source = BRIDGE.read_text(encoding="utf-8")
    assert "quote, unquote, urlparse, urlsplit" in source
    assert "def _protocol_finalize_session(flow) -> bool:" in source
    assert "for attempt, delay in enumerate((0, 1, 2, 4), 1):" in source
    assert "if _protocol_finalize_session(self):" in source
    assert "flow._turb_callback_navigation_started = False" in source
    assert 'page.on("request", _mark_callback_request)' in source
    assert 'target_url = callback_url if consume_callback else "https://chatgpt.com/"' in source


def test_bridge_logging_survives_closed_stderr_pipe():
    source = BRIDGE.read_text(encoding="utf-8")
    assert "def _safe_stderr(message: str) -> None:" in source
    assert "except (OSError, ValueError):" in source
    assert source.count("sys.stderr.write(") == 1
