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
    parser.add_argument('--mode', choices=['headed', 'headless', 'standalone-headed', 'ant-headless'], required=True)
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
    latest_state = {'host': 'unknown', 'path': '/', 'title_class': 'unknown'}
    def page_state(page):
        # No DOM text, URL query, cookie, or credential is written to evidence.
        try:
            parsed = urlsplit(str(page.url))
            target = endpoint(str(page.url))
            title = str(page.title() or '').lower()
            title_class = ('challenge' if any(w in title for w in ('just a moment', 'cloudflare', 'checking your browser', '请稍候'))
                           else 'other')
            state = dict(host=parsed.hostname or 'unknown', path=(target or {}).get('path', '{other}'), title_class=title_class)
            if state != latest_state:
                latest_state.update(state)
                emit('page_state', **state)
        except Exception:
            pass
    def on_page_event(frame):
        try:
            if frame == frame.page.main_frame:
                page_state(frame.page)
        except Exception:
            pass
    original = flow.build_ant_driver
    def build(*a, **kw):
        if args.mode == 'standalone-headed':
            from core import antbrowser_driver as ant_driver
            effective = ant_driver._normalize_proxy(kw.get('proxy'))
            locale = ant_driver._build_ant_locale_options(effective)
            emit('browser_start', headless=False, browser_engine='standalone_playwright')
            driver, opened = ant_driver._build_standalone_playwright_driver(effective, locale, headless=False)
        else:
            emit('browser_start', headless=kw.get('force_headless'), browser_engine='ant_headless' if kw.get('ant_headless') else 'ant_or_playwright')
            driver, opened = original(*a, **kw)
        from core.browser_auth_capture import BrowserAuthCapture
        captures.append(BrowserAuthCapture(driver.page, emit))
        driver.page.on('framenavigated', on_page_event)
        page_state(driver.page)
        emit('browser_ready')
        return driver, opened
    emit('start', account_id=args.account, mode=args.mode, proxy_used=True)
    try:
        with patch.object(flow, 'build_ant_driver', side_effect=build):
            result = flow.refresh_recent_login_browser(
                str(account['email']), email_source=account.get('email_source'),
                proxy=proxy, force_headless=args.mode in ('headless', 'ant-headless'),
                ant_headless=args.mode=='ant-headless',
                progress_callback=lambda message: emit('flow_progress'))
        token = str(result.get('accessToken') or '')
        emit('session_received', token_present=bool(token), identity_match=str((result.get('user') or {}).get('email') or '').casefold()==str(account['email']).casefold(), token_changed=bool(token and token!=account.get('access_token')))
        _verify_browser_token(token, result, account, str(account['email']), result.get('_network_proxy') or proxy)
        emit('complete', verified=True, database_written=False)
    except Exception as exc:
        text = str(exc).lower()
        blocked = any(status == 403 for capture in captures for status in capture.last_status.values())
        category = 'challenge_or_403' if blocked or '403' in text or 'challenge' in text else 'timeout' if 'timeout' in text or '超时' in text else 'other'
        emit('complete', verified=False, error_type=type(exc).__name__, category=category, auth_403_observed=blocked, last_page_state=latest_state, database_written=False)
    print('evidence='+str(path), flush=True)

if __name__ == '__main__':
    main()
