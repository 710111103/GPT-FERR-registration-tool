# -*- coding: utf-8 -*-
from unittest.mock import MagicMock, patch

from core import registration_service as service


def _account(account_id=718, status="registering", password="pw"):
    return {"id": account_id, "email": f"a{account_id}@example.test", "status": status, "registration_password": password}


def test_empty_ids_returns_without_queueing():
    result = service.submit_registration_resume([])
    assert result == {"ok": True, "started_count": 0, "skipped_count": 0, "jobs": [], "skipped": []}


def test_invalid_status_and_missing_password_are_skipped():
    accounts = {1: _account(1, "success"), 2: _account(2, "interrupted", "")}
    with patch.object(service.db, "get_account", side_effect=lambda i: accounts.get(i)), \
         patch.object(service.db, "get_registration_password", side_effect=lambda a: a.get("registration_password", "")):
        result = service.submit_registration_resume([1, 2, 999])
    assert result["started_count"] == 0
    assert {item["reason"] for item in result["skipped"]} == {"状态不需要续跑", "没有已确认注册密码", "账号不存在"}


def test_resume_creates_job_with_checkpoint_fields():
    account = _account()
    created = {"id": 42, "log_file": "resume.log", "status": "pending"}
    executor = MagicMock()
    with patch.object(service.db, "get_account", return_value=account), \
         patch.object(service.db, "get_registration_password", return_value="pw"), \
         patch.object(service.db, "list_jobs", return_value=[]), \
         patch.object(service.db, "create_job", return_value=created) as create_job, \
         patch.object(service.db, "update_job") as update_job, \
         patch.object(service.db, "get_job", return_value=created), \
         patch.object(service, "get_executor", return_value=executor):
        result = service.submit_registration_resume([718], workers=1)
    assert result["started_count"] == 1
    create_job.assert_called_once_with(email_source="generic_api")
    update_job.assert_called_once_with(
        42,
        email="a718@example.test",
        account_id=718,
        resume_account_id=718,
        resume_from="password_checkpoint_saved",
    )
    executor.submit.assert_called_once_with(service._run_one_job, 42, "resume.log")


def test_active_resume_job_is_skipped():
    account = _account()
    active = {"status": "running", "resume_account_id": 718}
    with patch.object(service.db, "get_account", return_value=account), \
         patch.object(service.db, "get_registration_password", return_value="pw"), \
         patch.object(service.db, "list_jobs", return_value=[active]):
        result = service.submit_registration_resume([718])
    assert result["started_count"] == 0
    assert result["skipped"][0]["reason"] == "已有续跑任务"


def test_route_accepts_ids_alias(monkeypatch):
    from webui.app import create_app
    called = {}
    monkeypatch.setattr(service, "submit_registration_resume", lambda ids, workers=1: called.update(ids=ids, workers=workers) or {"ok": True})
    response = create_app().test_client().post("/api/accounts/registration-resume", json={"ids": [718], "workers": 2})
    assert response.status_code == 200
    assert called == {"ids": [718], "workers": 2}
