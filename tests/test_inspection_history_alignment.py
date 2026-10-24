import json
import sqlite3
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from flask import Flask
from core import db
from webui.inspection_history import register_inspection_history


@pytest.fixture
def isolated_db(tmp_path,monkeypatch):
    path=tmp_path/"turb.sqlite3"
    with sqlite3.connect(path) as c:
        c.execute("CREATE TABLE storage_meta (key TEXT PRIMARY KEY,value TEXT NOT NULL)")
        c.execute("INSERT INTO storage_meta VALUES ('legacy_import_completed','test')")
    monkeypatch.setattr(db,"_active_sqlite_path",lambda:path)
    monkeypatch.setattr(db,"_SQLITE_READY",False)
    monkeypatch.setattr(db,"_SQLITE_READY_PATH",None)
    monkeypatch.setattr(db,"_DATA_DIR",tmp_path)
    monkeypatch.setattr(db,"_LOG_DIR",tmp_path/"logs")
    db._ensure_sqlite()
    return path


def test_empty_history_does_not_create_runs(isolated_db):
    assert db.list_account_inspections()=={"items":[],"total":0,"active":None}
    assert db.list_account_inspection_failures(999) is None


def test_history_is_terminal_immutable_and_failure_is_atomic(isolated_db):
    run,created=db.create_account_inspection([3,2,3],workers=2)
    assert created and run["account_ids"]==[3,2]
    duplicate,created=db.create_account_inspection([4])
    assert not created and duplicate["id"]==run["id"]
    with sqlite3.connect(isolated_db) as c:
        payload=json.loads(c.execute("SELECT payload FROM account_inspections").fetchone()[0])
        assert "account_ids" not in payload
    run.update(status="running",checked_count=1,live_failed_count=1)
    assert db.save_account_inspection(run,failure={"account_id":3,"email":"test@example.com","status":"failed","error":"HTTP 403"})
    details=db.list_account_inspection_failures(run["id"])
    assert details["items"][0]["error"]=="HTTP 403"
    assert details["total"]==1 and details["details_available"] is True
    assert "account_ids" not in details["task"]
    run["status"]="completed"
    assert db.save_account_inspection(run)
    run["status"]="running"
    assert not db.save_account_inspection(run,failure={"account_id":2})
    assert db.list_account_inspections()["items"][0]["status"]=="completed"
    assert db.list_account_inspection_failures(run["id"])["total"]==1


def test_archived_snapshot_does_not_modify_accounts(isolated_db):
    with sqlite3.connect(isolated_db) as c:
        for i,archived in [(1,0),(2,1)]:
            c.execute("INSERT INTO accounts(id,email,archived,payload) VALUES(?,?,?,?)",(i,f"{i}@example.com",archived,json.dumps({"id":i,"access_token":"fixture"})))
    run,created=db.create_account_inspection(archived="only")
    assert run["account_ids"]==[2]
    with sqlite3.connect(isolated_db) as c:
        assert c.execute("SELECT count(*) FROM accounts").fetchone()[0]==2


@pytest.fixture
def client(isolated_db):
    app=Flask(__name__,template_folder=str(Path(__file__).resolve().parents[1]/"webui/templates"))
    register_inspection_history(app)
    return app.test_client()


@pytest.mark.parametrize("value",["0","-1","abc",str(2**64)])
def test_invalid_pagination(client,value):
    assert client.get("/api/accounts/inspections?page="+value).status_code==400
    assert client.get("/api/accounts/inspections/1/failures?page="+value).status_code==400


def test_readonly_routes_upstream_shape(client):
    response=client.get("/api/accounts/inspections")
    assert response.status_code==200
    assert response.json=={"ok":True,"items":[],"total":0,"active":None}
    assert client.get("/api/accounts/inspections/99/failures").status_code==404
    assert client.post("/api/accounts/inspections").status_code==405
    assert client.get("/account-inspections").status_code==200
    assert db.list_account_inspections()["total"]==0


def test_history_page_javascript_parses(tmp_path):
    node=shutil.which("node")
    if not node: pytest.skip("Node unavailable")
    html=(Path(__file__).resolve().parents[1]/"webui/templates/inspection_history.html").read_text(encoding="utf-8")
    for index,script in enumerate(re.findall(r"<script>([\s\S]*?)</script>",html)):
        p=tmp_path/f"history-{index}.js";p.write_text(script,encoding="utf-8")
        r=subprocess.run([node,"--check",str(p)],capture_output=True,text=True)
        assert r.returncode==0,r.stderr
