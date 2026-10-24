from pathlib import Path

BRIDGE = Path(__file__).resolve().parents[1] / "vendor" / "gpt-register-tool" / "协议" / "_turb_bridge.py"


def test_cf_403_otp_error_is_retryable_before_account_creation():
    source = BRIDGE.read_text(encoding="utf-8")
    cf_check = source.index('if any(k in e for k in ("just a moment", "403", "cloudflare", "cf challenge"))')
    otp_check = source.index('if "otp" in e or "验证码" in e')
    assert cf_check < otp_check


def test_explicit_password_failure_beats_early_password_saved_marker():
    source = BRIDGE.read_text(encoding="utf-8")
    failed = source.index('if "注册密码失败" in text:')
    saved = source.index('if "该号已生成密码" in text:')
    assert failed < saved
    assert 'if "账户创建成功" in text or "创建账户成功" in text:' in source


def test_partial_registered_row_does_not_stop_proxy_retry():
    source = BRIDGE.read_text(encoding="utf-8")
    assert 'if last_status in ("success", "completed", "ok") and row:' in source
    assert "仅凭 registered" in source
    assert "丢弃旧 Session/Cookie 并换 IP 重建整链" in source
    assert 'last_status not in ("success", "completed", "ok") and not _account_created_from_log(log_file)' in source


def test_missing_account_created_marker_allows_network_retry():
    source = BRIDGE.read_text(encoding="utf-8")
    block = source[source.index("def _account_created_from_log"):source.index("def _is_retryable_before_account")]
    assert 'if "账户创建成功" in text or "创建账户成功" in text:' in block
    assert block.rstrip().endswith("return False")


def test_oss_registration_forwards_full_proxy_pool():
    source = (BRIDGE.parents[3] / "core" / "oss_protocol_registration.py").read_text(encoding="utf-8")
    assert 'proxy_pool_text = "\\n".join(' in source
    assert "proxy_pool=proxy_pool_text" in source


def test_single_dynamic_proxy_entry_can_be_redialed_after_403():
    source = BRIDGE.read_text(encoding="utf-8")
    assert "if len(candidates) == 1 and not _WREQ_ON:" in source
    block = source[source.index("if len(candidates) == 1 and not _WREQ_ON:"):source.index("else:", source.index("if len(candidates) == 1 and not _WREQ_ON:"))]
    assert "tried.add(proxy)" not in block
    assert "重新拨号" in block
