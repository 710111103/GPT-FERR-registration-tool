from core.registration_stage import RegistrationStage, classify_stage_error


def test_registration_stage_keeps_independent_facts():
    stage = RegistrationStage(flow="protocol")
    stage.password_set = True
    stage.otp_sent = True
    stage.fail("credential", "TimeoutError")
    data = stage.snapshot()
    assert data["password_set"] is True
    assert data["otp_sent"] is True
    assert data["account_created"] is False
    assert data["credential_acquired"] is False
    assert data["failure_stage"] == "credential"
    assert "password" not in data or isinstance(data["password_set"], bool)


def test_registration_stage_error_classification():
    assert classify_stage_error(TimeoutError("timed out")) == "timeout"
    assert classify_stage_error(RuntimeError("session missing")) == "credential"
    assert classify_stage_error(RuntimeError("OTP invalid")) == "otp"
from core.registration_stage import from_protocol_bridge


def test_bridge_partial_does_not_imply_created_or_password_set():
    stage = from_protocol_bridge({
        "ok": False,
        "partial": True,
        "result": {"password": "REDACTED", "session_token": "REDACTED"},
        "error": "waiting for OTP",
    }).snapshot()
    assert stage["flow"] == "protocol_bridge"
    assert stage["account_created"] is False
    assert stage["password_set"] is False
    assert stage["credential_acquired"] is False
    assert stage["error_code"] == "bridge_failed"
    assert "REDACTED" not in str(stage)


def test_bridge_uses_explicit_facts_and_access_token():
    stage = from_protocol_bridge({
        "ok": True,
        "partial": True,
        "result": {"access_token": "REDACTED"},
        "registration_stage": {
            "account_created": True,
            "password_set": True,
            "otp_sent": True,
            "otp_verified": True,
        },
    }).snapshot()
    assert stage["account_created"] is True
    assert stage["password_set"] is True
    assert stage["credential_acquired"] is True
    assert "REDACTED" not in str(stage)
