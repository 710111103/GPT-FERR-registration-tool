"""Only a confirmed liveness status marks an account as deactivated in the UI."""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.parametrize("status", ["deactivated", "failed"])
@pytest.mark.parametrize("token_expired", [True, False])
def test_dead_account_status_requires_confirmed_liveness(status, token_expired):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js not installed")
    html = (Path(__file__).resolve().parents[1] / "webui" / "templates" / "index.html").read_text(encoding="utf-8")
    functions = []
    for name, next_name in [
        ("_tokenCellV2", "_accountStatusCellV2Body"),
        ("_accountStatusCellV2Body", "_accountStatusCellV2"),
        ("_planCellBody", "_planCell"),
    ]:
        match = re.search(rf"function {name}\(r\) \{{.*?\n\}}(?=\nfunction {next_name}\()", html, re.S)
        assert match, f"Could not locate {name}"
        functions.append(match.group())
    row = {
        "id": 339,
        "has_access_token": True,
        "token_expired": token_expired,
        "live_check_status": status,
        "live_check_error": "account_deactivated",
        "plan_check_status": "failed",
        "plan_check_error": "account_deactivated",
    }
    js = "const esc = s => String(s ?? '');\nconst _planFailureLabel = () => 'unknown';\n" + "\n".join(functions) + "\n"
    js += f"const r = {json.dumps(row)}; console.log(JSON.stringify([_tokenCellV2(r), _accountStatusCellV2Body(r), _planCellBody(r)]));"
    result = subprocess.run([node, "-e", js], capture_output=True, text=True, encoding="utf-8")
    assert result.returncode == 0, result.stderr
    cells = json.loads(result.stdout)
    if status == "deactivated":
        assert all("死号" in cell for cell in cells)
        assert all("Token失效" not in cell for cell in cells)
    else:
        assert all("死号" not in cell for cell in cells)
        if token_expired:
            assert "Token失效" in cells[1]
        else:
            assert "查活: 失败" in cells[0]
            assert "检测失败" in cells[1]


def test_expired_at_oauth_callback_challenge_is_not_misreported_as_dead_account():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js not installed")
    html = (Path(__file__).resolve().parents[1] / "webui" / "templates" / "index.html").read_text(encoding="utf-8")
    functions = []
    for name, next_name in [
        ("_tokenCellV2", "_accountStatusCellV2Body"),
        ("_accountStatusCellV2Body", "_accountStatusCellV2"),
        ("_planCellBody", "_planCell"),
    ]:
        match = re.search(rf"function {name}\(r\) \{{.*?\n\}}(?=\nfunction {next_name}\()", html, re.S)
        assert match, f"Could not locate {name}"
        functions.append(match.group())
    row = {
        "id": 105,
        "has_access_token": True,
        "token_expired": True,
        "live_check_status": "failed",
        "live_check_error": "AT\u5df2\u8fc7\u671f/\u5931\u6548 (token_expired)\uff1b[oauth_callback] \u91cd\u65b0\u767b\u5f55\u88ab\u9a8c\u8bc1\u9875\u62e6\u622a (HTTP 403)",
        "plan_check_status": "failed",
        "plan_check_error": "token_expired",
    }
    js = "const esc = s => String(s ?? '');\nconst _planFailureLabel = () => 'unknown';\n" + "\n".join(functions) + "\n"
    js += f"const r = {json.dumps(row)}; console.log(JSON.stringify([_tokenCellV2(r), _accountStatusCellV2Body(r), _planCellBody(r)]));"
    result = subprocess.run([node, "-e", js], capture_output=True, text=True, encoding="utf-8")
    assert result.returncode == 0, result.stderr
    cells = json.loads(result.stdout)
    assert all("AT\u5931\u6548\u00b7\u56de\u8c03\u53d7\u963b" in cell for cell in cells)
    assert all("\u6b7b\u53f7" not in cell for cell in cells)
    assert all("[oauth_callback]" in cell for cell in cells)
