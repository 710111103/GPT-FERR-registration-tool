import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.parametrize("selected,rows,expected",[([1,2,3],[2],[2]),([1,2],[1,2],[1,2]),([1,2],[3,4],[]),([1,2],[],[]),([1,2],[2,3],[2])])
def test_selection_and_toolbar_are_limited_to_visible_rows(selected,rows,expected):
    node=shutil.which("node")
    if not node:pytest.skip("Node unavailable")
    html=(Path(__file__).resolve().parents[1]/"webui/templates/index.html").read_text(encoding="utf-8")
    functions=[]
    for name in ("pruneAccountSelection","updateAccountSelectionUi"):
        m=re.search(r"function "+name+r"\([^\n]*\) \{.*?\n\}",html,re.S)
        assert m,name
        functions.append(m.group())
    setup="const ACCOUNTS="+json.dumps([{"id":x} for x in rows])+";const ACCOUNT_SELECTED=new Set("+json.dumps(selected)+");const SHOW_ARCHIVED_ACCOUNTS=false;const els={};const document={getElementById:id=>els[id]??=( {classList:{toggle(){}}})};const $=s=>document.getElementById(s.slice(1));"
    js=setup+"\n"+"\n".join(functions)+"\nupdateAccountSelectionUi();console.log(JSON.stringify({ids:[...ACCOUNT_SELECTED],label:els.accountsToolbarSelectedCountV2.textContent,disabled:els.btnDeleteSelectedAccountsV2.disabled}));"
    result=subprocess.run([node,"-e",js],capture_output=True,text=True,encoding="utf-8")
    assert result.returncode==0,result.stderr
    data=json.loads(result.stdout)
    assert data["ids"]==expected
    assert str(len(expected)) in data["label"]
    assert data["disabled"]==(not expected)


def test_render_prunes_before_building_checkboxes():
    html=(Path(__file__).resolve().parents[1]/"webui/templates/index.html").read_text(encoding="utf-8")
    assert "function renderAccounts() {\n  pruneAccountSelection();" in html
