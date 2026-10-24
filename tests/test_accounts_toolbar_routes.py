"""Prevent single/bulk account toolbar actions from silently changing semantics."""
from pathlib import Path

HTML = (Path(__file__).resolve().parents[1] / "webui/templates/index.html").read_text(encoding="utf-8")


def test_standard_plan_button_does_not_receive_click_event_as_multi_region_flag():
    assert "bind('btnCheckSelectedPlansV2', () => checkSelectedPlans(false));" in HTML
    assert "bind('btnCheckSelectedPlanRegionsV2', () => checkSelectedPlans(true));" in HTML


def test_row_and_toolbar_liveness_share_handler_and_api():
    assert 'id="btnCheckSelectedLiveV2" onclick="checkSelectedLive()"' in HTML
    assert 'onclick="checkSelectedLive([Number(\'${esc(r.id)}\')], this); return false;"' in HTML
    assert "const ids = idsArg || Array.from(ACCOUNT_SELECTED);" in HTML
    assert "const r = await api('/api/accounts/check-live-bulk', {" in HTML
    assert "body: JSON.stringify({account_ids: ids})," in HTML


def test_challenge_is_not_hidden_behind_expired_token_badge():
    section = HTML.split('function _accountStatusCellV2Body(r) {', 1)[1].split('function _accountStatusCellV2(r)', 1)[0]
    assert section.index("if (s === 'failed' && err.includes('验证页'))") < section.index('if (isTokenExpired)')
    token = HTML.split('function _tokenCellV2(r) {', 1)[1].split('function _accountStatusCellV2Body', 1)[0]
    assert token.index("liveErr.includes('验证页')") < token.index('else if (isTokenExpired)')


def test_liveness_polling_reloads_after_login_completes():
    poll = HTML.split('async function pollAccountPlanStatuses()', 1)[1].split('function _codexCell', 1)[0]
    assert "const wasLiveChecking = ['queued', 'running'].includes(account?.live_check_status);" in poll
    assert '(wasLiveChecking && !isLiveChecking)' in poll
    assert 'account?.token_expired !== item.token_expired' in poll
    token = HTML.split('function _tokenCellV2(r) {', 1)[1].split('function _accountStatusCellV2Body', 1)[0]
    assert token.index("else if (live === 'queued')") < token.index('else if (isTokenExpired)')


def test_ant_headless_refresh_is_separate_from_standard_liveness():
    assert 'id="btnRefreshExpiredAtV2" onclick="refreshExpiredAt()"' in HTML
    assert 'refreshExpiredAt([Number(\'${esc(r.id)}\')], this)' in HTML
    assert "api('/api/accounts/refresh-expired-at'" in HTML
    assert "api('/api/accounts/check-live-bulk'" in HTML


def test_ant_refresh_button_never_promises_visible_browser():
    assert "刷新失效AT（无头）</button>" in HTML
    assert "有头刷新AT</button>" not in HTML
