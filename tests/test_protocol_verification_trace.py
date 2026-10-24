import json
from unittest.mock import patch

from core import protocol_verification_trace as trace_module
from core.account_liveness import _live_stage, protocol_login_trace


def test_trace_records_stages_without_secrets(tmp_path):
    with patch.object(trace_module, "TRACE_DIR", tmp_path):
        trace = trace_module.ProtocolVerificationTrace(64, 1)
        with protocol_login_trace(trace):
            _live_stage("verification", "正在验证密码")
            trace("password_verify_response", {"http_status": 200, "password": "do-not-record", "access_token": "secret", "code": "ok"})
        records = [json.loads(line) for line in trace.path.read_text(encoding="utf-8").splitlines()]
    assert [record["event"] for record in records] == ["stage", "password_verify_response"]
    assert records[1]["http_status"] == 200
    assert "do-not-record" not in trace.path.read_text(encoding="utf-8")
    assert "secret" not in trace.path.read_text(encoding="utf-8")
