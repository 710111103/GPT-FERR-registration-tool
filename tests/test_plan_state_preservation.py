from unittest.mock import patch
import pytest
from core import db


@pytest.mark.parametrize("state",["success","queued","running"])
def test_liveness_does_not_clear_eligibility_state(state):
    row={"id":1,"email":"test@example.com","access_token":"old","plan_check_status":state,"plan_check_ok":True,"plan_checked_at":"2026-10-18T12:00:00","plus_trial_eligible":False}
    with patch.object(db,"_load_accounts",return_value=[row]),patch.object(db,"_save_accounts"):
        assert db.update_account_liveness(1,{"ok":True,"access_token":"new"})
    assert row["plan_check_status"]==state
    assert row["plan_checked_at"]=="2026-10-18T12:00:00"
    assert row["plus_trial_eligible"] is False


def test_new_token_clears_only_stale_auth_failure():
    row={"id":1,"email":"test@example.com","plan_check_status":"failed","plan_check_error":"token_expired"}
    with patch.object(db,"_load_accounts",return_value=[row]),patch.object(db,"_save_accounts"):
        db.update_account_liveness(1,{"ok":True,"access_token":"new"})
    assert row["plan_check_status"]==""
    assert row["plan_check_error"] is None


def test_other_failures_remain_visible():
    row={"id":1,"email":"test@example.com","plan_check_status":"failed","plan_check_error":"ProxyError"}
    with patch.object(db,"_load_accounts",return_value=[row]),patch.object(db,"_save_accounts"):
        db.update_account_liveness(1,{"ok":True,"access_token":"new"})
    assert row["plan_check_error"]=="ProxyError"


@pytest.mark.parametrize("status,disabled",[("",False),("success",False),("running",True),("queued",True)])
def test_plan_button_clears_transient_label_without_revision_change(status,disabled):
    import json,re,shutil,subprocess
    from pathlib import Path
    node=shutil.which("node")
    if not node:pytest.skip("Node unavailable")
    html=(Path(__file__).resolve().parents[1]/"webui/templates/index.html").read_text(encoding="utf-8")
    fn=re.search(r"async function checkOnePlan\(.*?\n\}(?=\n\nasync function checkOnePayment)",html,re.S).group()
    js="const ACCOUNTS=[{id:1,plan_check_status:"+json.dumps(status)+"}]; const api=async()=>({});const showToast=()=>{};const pollAccountPlanStatuses=async()=>{};\n"+fn+"\nconst btn={disabled:false,textContent:'check',isConnected:true};checkOnePlan(1,btn).then(()=>console.log(JSON.stringify(btn)));"
    r=subprocess.run([node,"-e",js],capture_output=True,text=True,encoding="utf-8")
    assert r.returncode==0,r.stderr
    d=json.loads(r.stdout);assert d["disabled"]==disabled
    if not disabled:assert d["textContent"]=="check"
