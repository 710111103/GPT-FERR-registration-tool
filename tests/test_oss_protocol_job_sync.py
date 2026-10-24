from flask import Flask


class _InlinePool:
    def submit(self, fn, *args, **kwargs):
        fn(*args, **kwargs)


class _FakeDb:
    def __init__(self, log_file):
        self.log_file = str(log_file)
        self.created = []
        self.updates = []

    def create_job(self, email_source):
        row = {"id": 901 + len(self.created), "email_source": email_source, "log_file": self.log_file}
        self.created.append(row)
        return row

    def update_job(self, job_id, **kwargs):
        self.updates.append((job_id, kwargs))


def _client(monkeypatch, tmp_path, result):
    import core.db as db
    import core.oss_protocol_registration as registration
    import webui.oss_protocol_page as page

    fake_db = _FakeDb(tmp_path / "oss-main-job.log")
    monkeypatch.setattr(db, "create_job", fake_db.create_job)
    monkeypatch.setattr(db, "update_job", fake_db.update_job)
    monkeypatch.setattr(registration, "run_oss_protocol_registration", lambda **kwargs: result)
    monkeypatch.setattr(page, "_POOL", _InlinePool())
    page._JOBS.clear()

    app = Flask(__name__, template_folder=str(tmp_path))
    page.register_oss_protocol_page(app)
    return app.test_client(), fake_db


def test_oss_success_is_written_to_common_registration_jobs(monkeypatch, tmp_path):
    result = {
        "success": True,
        "email": "registered@example.com",
        "account_id": 733,
        "network_traffic": {"available": True, "sent_bytes": 10, "received_bytes": 20},
        "error": None,
    }
    client, fake_db = _client(monkeypatch, tmp_path, result)

    response = client.post("/api/oss-protocol/register", json={
        "email_source": "outlook",
        "email": "registered@example.com",
        "proxy": "http://127.0.0.1:8080",
    })

    assert response.status_code == 202
    payload = response.get_json()
    assert payload["main_job_id"] == 901
    assert fake_db.created[0]["email_source"] == "outlook"
    assert any(update.get("status") == "running" for _, update in fake_db.updates)
    completed = [update for _, update in fake_db.updates if update.get("status") == "success"][-1]
    assert completed["email"] == "registered@example.com"
    assert completed["account_id"] == 733
    assert completed["completed_at"]
    assert completed["network_traffic"]["available"] is True


def test_oss_failure_is_written_to_common_registration_jobs(monkeypatch, tmp_path):
    result = {
        "success": False,
        "email": "failed@example.com",
        "account_id": None,
        "network_traffic": {"available": True, "sent_bytes": 7, "received_bytes": 9},
        "error": "OAuth Session 收尾失败",
    }
    client, fake_db = _client(monkeypatch, tmp_path, result)

    response = client.post("/api/oss-protocol/register", json={
        "email_source": "outlook",
        "email": "failed@example.com",
        "proxy": "http://127.0.0.1:8080",
    })

    assert response.status_code == 202
    completed = [update for _, update in fake_db.updates if update.get("status") == "failed"][-1]
    assert completed["email"] == "failed@example.com"
    assert completed["error"] == "OAuth Session 收尾失败"
    assert completed["completed_at"]
    assert completed["network_traffic"]["available"] is True


def test_oss_batch_creates_independent_jobs(monkeypatch, tmp_path):
    result = {"success": True, "email": "auto@example.com", "account_id": 733,
              "network_traffic": {"available": True}, "error": None}
    client, fake_db = _client(monkeypatch, tmp_path, result)
    response = client.post("/api/oss-protocol/register", json={
        "email_source": "outlook", "count": 5, "workers": 3,
        "proxy": "http://127.0.0.1:8080",
    })
    assert response.status_code == 202
    payload = response.get_json()
    assert payload["submitted"] == 5
    assert payload["workers"] == 3
    assert len(payload["job_ids"]) == 5
    assert len(set(payload["job_ids"])) == 5
    assert payload["main_job_ids"] == [901, 902, 903, 904, 905]
    assert len(fake_db.created) == 5


def test_oss_batch_rejects_reusing_fixed_email(monkeypatch, tmp_path):
    result = {"success": True, "email": "unused@example.com", "account_id": 733, "error": None}
    client, fake_db = _client(monkeypatch, tmp_path, result)
    response = client.post("/api/oss-protocol/register", json={
        "email_source": "outlook", "count": 2, "workers": 2,
        "email": "same@example.com", "proxy": "http://127.0.0.1:8080",
    })
    assert response.status_code == 400
    assert "邮箱必须留空" in response.get_json()["error"]
    assert fake_db.created == []
