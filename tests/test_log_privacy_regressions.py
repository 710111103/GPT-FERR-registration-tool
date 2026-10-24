import json
import pytest
from core.task_observability import redact_text
from core import live_check_service as service


@pytest.mark.parametrize("scheme", ["http", "https", "socks4", "socks4a", "socks5", "socks5h"])
def test_proxy_secrets_redacted(scheme):
    text = redact_text(f"proxy={scheme}://fixture-user:fixture-pass@localhost:8080")
    assert "fixture-user" not in text and "fixture-pass" not in text
    assert "localhost:8080" in text


@pytest.mark.parametrize("key", ["password", "access_token", "session_token", "otp", "cookie"])
def test_quoted_secret_with_spaces_is_fully_redacted(key):
    for text in (json.dumps({key: 'fixture secret with "quotes"'}), repr({key: "fixture secret with spaces"})):
        redacted = redact_text(text)
        assert "fixture" not in redacted
        assert "<REDACTED>" in redacted


def test_account_log_redacts_at_write_boundary(tmp_path, monkeypatch):
    target = tmp_path / "fixture.log"
    monkeypatch.setattr(service, "log_path", lambda email: target)
    service._append_log("fixture@example.test", 'error={"password": "fixture secret"} proxy=socks5://user:pass@localhost:80')
    text = target.read_text(encoding="utf-8")
    assert "fixture secret" not in text and "user:pass" not in text


def test_incidental_403_digits_are_not_an_http_challenge():
    assert not service._is_explicit_http_403_challenge("Timeout for account 403 after 4030ms")
    assert service._worker_failure_result(RuntimeError("Timeout for account 403"))["status"] == "failed"
