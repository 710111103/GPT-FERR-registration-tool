from __future__ import annotations

import pytest

from core import db
from core.account_liveness import TotpVerificationRejectedError
from core import twofa_rotation_service as service


def test_rotation_db_only_commits_secret_after_success(monkeypatch):
    rows = [{"id": 9, "email": "a@example.com", "totp_secret": "OLDSECRET"}]
    monkeypatch.setattr(db, "_load_accounts", lambda: rows)
    monkeypatch.setattr(db, "_save_accounts", lambda value: None)

    assert db.claim_account_totp_rotation(9)
    assert db.mark_account_totp_rotation_running(9)
    assert db.update_account_totp_rotation(9, {
        "status": "prepared", "candidate_secret": "NEWSECRET",
    })
    assert rows[0]["totp_secret"] == "OLDSECRET"
    assert rows[0]["totp_rotation_candidate_secret"] == "NEWSECRET"

    assert db.update_account_totp_rotation(9, {
        "ok": True, "status": "success", "totp_secret": "NEWSECRET",
    })
    assert rows[0]["totp_secret"] == "NEWSECRET"
    assert rows[0]["totp_rotation_candidate_secret"] is None


def test_verify_pair_requires_new_acceptance_and_explicit_old_rejection(monkeypatch):
    def login(email, source, proxy, secret, label):
        if secret == "NEWSECRET":
            return {"accessToken": "fresh-at"}
        raise TotpVerificationRejectedError("TOTP_REJECTED")

    monkeypatch.setattr(service, "_login_with_secret", login)
    monkeypatch.setattr(service.time, "sleep", lambda _: None)
    data, rejected = service._verify_rotation_pair(
        email="a@example.com", email_source="generic_api", proxy=None,
        old_secret="OLDSECRET", candidate_secret="NEWSECRET",
    )
    assert data["accessToken"] == "fresh-at"
    assert rejected is True


def test_verify_pair_does_not_treat_network_error_as_old_key_rejection(monkeypatch):
    def login(email, source, proxy, secret, label):
        if secret == "NEWSECRET":
            return {"accessToken": "fresh-at"}
        raise ConnectionError("proxy closed")

    monkeypatch.setattr(service, "_login_with_secret", login)
    monkeypatch.setattr(service.time, "sleep", lambda _: None)
    with pytest.raises(ConnectionError, match="proxy closed"):
        service._verify_rotation_pair(
            email="a@example.com", email_source="generic_api", proxy=None,
            old_secret="OLDSECRET", candidate_secret="NEWSECRET",
        )


def test_verify_pair_rejects_when_old_secret_still_logs_in(monkeypatch):
    monkeypatch.setattr(
        service,
        "_login_with_secret",
        lambda *args, **kwargs: {"accessToken": "still-valid"},
    )
    monkeypatch.setattr(service.time, "sleep", lambda _: None)
    with pytest.raises(RuntimeError, match="旧 TOTP 密钥仍被服务端接受"):
        service._verify_rotation_pair(
            email="a@example.com", email_source="generic_api", proxy=None,
            old_secret="OLDSECRET", candidate_secret="NEWSECRET",
        )


def test_recover_candidate_commits_when_candidate_works_and_old_is_rejected(monkeypatch):
    def login(email, source, proxy, secret, label):
        if secret == "NEWSECRET":
            return {"accessToken": "candidate-at"}
        raise TotpVerificationRejectedError("TOTP_REJECTED")

    monkeypatch.setattr(service, "_login_with_secret", login)
    monkeypatch.setattr(service.time, "sleep", lambda _: None)
    mode, data = service._recover_candidate(
        email="a@example.com", email_source="generic_api", proxy=None,
        old_secret="OLDSECRET", candidate_secret="NEWSECRET",
    )
    assert mode == "candidate"
    assert data["accessToken"] == "candidate-at"


def test_recover_candidate_restarts_when_candidate_rejected_and_old_works(monkeypatch):
    def login(email, source, proxy, secret, label):
        if secret == "NEWSECRET":
            raise TotpVerificationRejectedError("TOTP_REJECTED")
        return {"accessToken": "old-at"}

    monkeypatch.setattr(service, "_login_with_secret", login)
    mode, data = service._recover_candidate(
        email="a@example.com", email_source="generic_api", proxy=None,
        old_secret="OLDSECRET", candidate_secret="NEWSECRET",
    )
    assert mode == "old"
    assert data["accessToken"] == "old-at"

