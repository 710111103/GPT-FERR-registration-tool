"""Single-account browser refresh diagnostics; never persist credentials or tokens."""
import argparse
import json
import logging
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--account', type=int, required=True)
    parser.add_argument('--mode', choices=['headed', 'headless'], required=True)
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    from core import db
    from core import antbrowser_liveness as flow
    from core.chatgpt_plan import resolve_plan_check_route
    from core.live_check_service import _verify_browser_token
    account = db.get_account(args.account)
    if not account:
        raise SystemExit('account not found')
    route = resolve_plan_check_route(explicit_proxy=None)
    proxy = route.get('proxy')
    if not proxy:
        raise SystemExit('proxy missing; no direct fallback')
    output = Path(__file__).resolve().parents[1] / 'verification' / 'browser-refresh'
    output.mkdir(parents=True, exist_ok=True)
    path = output / f'{args.account}-{args.mode}-{time.time_ns()}.jsonl'
    start = time.monotonic()
    safe_segments = set('api auth accounts session csrf providers signin openai callback login authorize email password verify verification otp validate mfa challenge continue token backend-api wham usage oauth'.split())
    def emit(event, **fields):
        row = dict(event=event, elapsed_s=round(time.monotonic()-start, 2), **fields)
        with path.open('a', encoding='utf-8') as handle:
            handle.write(json.dumps(row, ensure_ascii=True)+'\n')
        print(json.dumps(row), flush=True)
    def endpoint(url):
        u = urlsplit(url)
        if u.hostname not in ('chatgpt.com', 'auth.openai.com'):
            return None
        return dict(host=u.hostname, path='/'.join(part if part in safe_segments or not part else '{segment}' for part in u.path.split('/')))
    captures = []
    original = flow.build_ant_driver
    def build(*a, **kw):
        emit('browser_start', headless=kw.get('force_headless'))
        driver, opened = original(*a, **kw)
        from core.browser_auth_capture import BrowserAuthCapture
        captures.append(BrowserAuthCapture(driver.page, emit))
        emit('browser_ready')
        return driver, opened
    emit('start', account_id=args.account, mode=args.mode, proxy_used=True)
    try:
        with patch.object(flow, 'build_ant_driver', side_effect=build):
            result = flow.refresh_recent_login_browser(
                str(account['email']), email_source=account.get('email_source'),
                proxy=proxy, force_headless=args.mode=='headless',
                progress_callback=lambda message: emit('flow_progress'))
        token = str(result.get('accessToken') or '')
        emit('session_received', token_present=bool(token), identity_match=str((result.get('user') or {}).get('email') or '').casefold()==str(account['email']).casefold(), token_changed=bool(token and token!=account.get('access_token')))
        _verify_browser_token(token, result, account, str(account['email']), result.get('_network_proxy') or proxy)
        emit('complete', verified=True, database_written=False)
    except Exception as exc:
        text = str(exc).lower()
        category = 'challenge_or_403' if '403' in text or 'challenge' in text else 'timeout' if 'timeout' in text or '超时' in text else 'other'
        blocked = any(status == 403 for capture in captures for status in capture.last_status.values())
        emit('complete', verified=False, error_type=type(exc).__name__, category=category, auth_403_observed=blocked, database_written=False)
    print('evidence='+str(path), flush=True)

if __name__ == '__main__':
    main()
