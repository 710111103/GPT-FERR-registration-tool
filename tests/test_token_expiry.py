import base64
import json
import subprocess
import re
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest
from core.token_expiry import access_token_expires_at
from core import db


def token(payload):
    return "e30." + base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=") + ".sig"


@pytest.mark.parametrize("payload", [{}, {"exp": True}, {"exp": "2000000000"}, {"exp": -1}, {"exp": 1e100}, [], {"exp": float("nan")}])
def test_unknown_expiry(payload):
    assert access_token_expires_at(token(payload)) is None


def test_expiry_parsed_and_persisted_without_network():
    at = token({"exp": 2000000000})
    assert access_token_expires_at(at) == "2033-05-18T03:33:20Z"
    rows = [{"id": 1, "email": "test@example.com", "access_token": at}]
    with patch.object(db, "_save_collection") as save:
        db._save_accounts(rows)
    assert save.call_args.args[1][0]["token_expires_at"] == "2033-05-18T03:33:20Z"
    assert db._decorate_account(rows[0])["token_expires_at"] == "2033-05-18T03:33:20Z"


def test_unknown_token_does_not_use_session_expiry():
    row = {"access_token": "opaque", "expires_at": "2033-05-18T03:33:20Z", "token_expires_at": "old"}
    assert db._decorate_account(row)["token_expires_at"] is None


@pytest.mark.parametrize("expiry,invalid,label", [("2000-01-01T00:00:00Z",False,"AT失效（自动刷新）"),("2099-01-01T00:00:00Z",False,"AT剩余"),(None,False,"AT有效期未知"),("2099-01-01T00:00:00Z",True,"AT失效（自动刷新）")])
def test_token_cell_displays_expiry(expiry, invalid, label):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node unavailable")
    html = (Path(__file__).resolve().parents[1]/"webui/templates/index.html").read_text(encoding="utf-8")
    fn = re.search(r"function _tokenCellV2\(r\) \{.*?\n\}(?=\nfunction _accountStatusCellV2Body)", html, re.S)
    assert fn
    row = {"id":1,"has_access_token":True,"token_expires_at":expiry,"token_expired":invalid}
    js = "const esc = s => String(s ?? '');\n" + fn.group() + "\nconsole.log(_tokenCellV2(" + json.dumps(row) + "));"
    result = subprocess.run([node,"-e",js],capture_output=True,text=True,encoding="utf-8")
    assert result.returncode == 0, result.stderr
    assert label in result.stdout


def test_refresh_success_saves_the_new_token_expiry():
    rows = [{"id": 1, "email": "test@example.com", "access_token": "old", "token_expires_at": "old", "token_expired": True}]
    with patch.object(db,"_load_accounts",return_value=rows), patch.object(db,"_save_collection"):
        assert db.update_account_liveness(1, {"ok":True,"access_token":token({"exp":2000000000})})
    assert rows[0]["token_expires_at"] == "2033-05-18T03:33:20Z"
    assert rows[0]["token_expired"] is False


def test_expired_at_persists_once_without_marking_unknown_or_archived():
    from datetime import datetime, timezone
    old = token({"exp": 1000000000})
    future = token({"exp": 2000000000})
    rows = [
        {"id": 1, "access_token": old},
        {"id": 2, "access_token": future},
        {"id": 3, "access_token": "opaque"},
        {"id": 4, "access_token": old, "archived": True},
    ]
    with patch.object(db, "_load_accounts", return_value=rows), patch.object(db, "_save_accounts") as save:
        assert db.mark_expired_access_tokens(now=datetime(2026, 10, 20, tzinfo=timezone.utc)) == 1
        assert db.mark_expired_access_tokens(now=datetime(2026, 10, 20, tzinfo=timezone.utc)) == 0
    assert save.call_count == 1
    assert rows[0]["token_expired"] is True
    assert not any(r.get("token_expired") for r in rows[1:])
