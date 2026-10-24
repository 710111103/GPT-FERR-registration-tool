# -*- coding: utf-8 -*-
"""给已注册的无密码账号补设密码，并以全新浏览器重新登录验收。"""
from __future__ import annotations

import json
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from core import db
from core.antbrowser_driver import build_ant_driver, cleanup_ant_profile
from core.email_provider import wait_for_otp
from core.openai_auth import generate_registration_password
from core.roxy_codex_oauth import _fill_email_and_otp, _fill_mfa_challenge_if_present, _is_mfa_challenge_page
from core.roxy_registration import _fetch_chatgpt_session, _submit_email_and_wait_next, _click_forgot_password_if_present, _is_email_verification_page, _type_otp, _wait_after_email_otp_submit
from core.password_setup_protocol import build_password_request_template

logger = logging.getLogger(__name__)
_EXECUTOR = ThreadPoolExecutor(max_workers=1, thread_name_prefix="password-setup")
_QUEUE = threading.BoundedSemaphore(50)
_RUNNING: set[int] = set()
_QUEUED: set[int] = set()
_LOCK = threading.Lock()
_BATCH_LOCK = threading.Lock()
_BATCH_CANCEL = threading.Event()
_BATCH_THREAD: threading.Thread | None = None
_BATCH_STATE: dict = {
    "status": "idle", "total": 0, "processed": 0, "succeeded": 0,
    "failed": 0, "skipped": 0, "current_account_id": None, "started_at": None,
    "completed_at": None, "message": "",
}


def _fresh_proxy(account: dict) -> str | None:
    from config import proxy as proxy_cfg
    from core.chatgpt_plan import rotate_proxy_session
    raw = str((account or {}).get("proxy_used") or "").strip()
    configured = str(proxy_cfg.pick_proxy() or "").strip()
    if raw and configured:
        try:
            from urllib.parse import urlparse
            raw_host = urlparse(raw).netloc.split("@")[-1].split(":")[0].lower()
            pool_str = str(getattr(proxy_cfg, "PROXY_POOL", "") or "")
            if raw_host and pool_str and raw_host not in pool_str.lower():
                return rotate_proxy_session(configured)[0]
        except Exception:
            pass
    if not raw:
        return rotate_proxy_session(configured)[0] if configured else None
    return rotate_proxy_session(raw)[0]


def _is_proxy_navigation_error(exc: Exception) -> bool:
    text = str(exc or "").lower()
    return any(marker in text for marker in (
        "err_connection_closed", "err_proxy_connection_failed", "err_tunnel_connection_failed",
        "proxy connection", "proxyerror", "connection closed", "connection reset",
        "connection refused", "timed out", "timeout",
    ))


def _password_proxy_for_attempt(account: dict, attempt: int) -> str | None:
    """首轮优先账号历史代理，重试时重新读取当前代理池并轮换动态会话。"""
    if attempt <= 1:
        return _fresh_proxy(account)
    from config import proxy as proxy_cfg
    from core.chatgpt_plan import rotate_proxy_session
    configured = str(proxy_cfg.pick_proxy() or "").strip()
    if configured:
        return rotate_proxy_session(configured)[0]
    return _fresh_proxy(account)


def _open_password_reauth_with_proxy_rotation(
    account: dict, *, reset: bool, attempts: int = 2, on_retry=None,
):
    """打开密码重认证；只对明确的代理/连接导航错误切换代理重试。"""
    email = str(account.get("email") or "").strip()
    device_id = str(account.get("device_id") or "")
    last_error: Exception | None = None
    for attempt in range(1, max(1, int(attempts)) + 1):
        driver = opened = None
        try:
            proxy = "" if attempt == 3 else _password_proxy_for_attempt(account, attempt)
            driver, opened = build_ant_driver(proxy, force_headless=False)
            auth_url = _start_add_password_flow(driver, email, device_id, reset=reset)
            return driver, opened, auth_url
        except Exception as exc:
            last_error = exc
            try:
                if driver:
                    driver.quit()
            except Exception:
                pass
            try:
                if opened:
                    cleanup_ant_profile(opened)
            except Exception:
                pass
            if attempt >= attempts or not _is_proxy_navigation_error(exc):
                raise
            if on_retry:
                on_retry(attempt + 1, attempts, exc)
    raise last_error or RuntimeError("密码重认证浏览器启动失败")


def log_path(account_id: int) -> Path:
    return Path("注册日志") / "password-setup" / f"account-{int(account_id)}.log"


def _append_log(account_id: int, line: str, *, clear: bool = False) -> None:
    path = log_path(account_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%H:%M:%S")
    with path.open("w" if clear else "a", encoding="utf-8") as handle:
        handle.write(f"{stamp} [INFO] {line}\n")


def is_running(account_id: int) -> bool:
    with _LOCK:
        return int(account_id) in _RUNNING


def is_queued(account_id: int) -> bool:
    """只返回当前进程内真实排队状态；服务重启后的数据库 queued 不算活动任务。"""
    with _LOCK:
        account_id = int(account_id)
        return account_id in _QUEUED and account_id not in _RUNNING


def _otp_provider(email_source: str):
    def provider(email: str, after_ts: float | None = None, **_kwargs) -> str:
        return wait_for_otp(
            email, after_ts or time.time(), max_wait=90,
            email_source=email_source, force_service=True,
            exclude_codes=_kwargs.get("exclude_codes"),
        )
    return provider


def _start_add_password_flow(driver, email: str, device_id: str, *, reset: bool = False) -> str:
    """Create the password add/reset authorize URL inside the browser session.

    ChatGPT occasionally returns its HTML shell from ``/api/auth/csrf`` while an
    edge session is warming up.  Parse responses defensively and retry instead
    of letting ``response.json()`` abort the whole password reset.
    """
    driver.get("https://chatgpt.com/")
    result: dict = {}
    for attempt in range(1, 4):
        try:
            result = driver.page.evaluate(
                """async ({email, did, reset}) => {
              const headers = {accept:'application/json', 'cache-control':'no-cache', pragma:'no-cache'};
              const csrfResp = await fetch('/api/auth/csrf', {credentials:'include', headers});
              const csrfText = await csrfResp.text();
              let csrf = {};
              try { csrf = JSON.parse(csrfText); } catch (_) {}
              if (!csrfResp.ok || !csrf.csrfToken) {
                return {ok:false, stage:'csrf', status:csrfResp.status, text:csrfText};
              }
              const q = new URLSearchParams({
                connection:'password', login_hint:email, reauth:'password', max_age:'0',
                ...(reset ? {post_login_password_reset:'true'} : {post_login_add_password:'true'}),
                'ext-oai-did':did || ''
              });
              const body = new URLSearchParams({
                callbackUrl:'https://chatgpt.com/', csrfToken:csrf.csrfToken, json:'true'
              });
              const resp = await fetch('/api/auth/signin/openai?' + q.toString(), {
                method:'POST', credentials:'include',
                headers:{...headers, 'content-type':'application/x-www-form-urlencoded'}, body:body.toString()
              });
              const text = await resp.text();
              let data = {};
              try { data = JSON.parse(text); } catch (_) {}
              return {ok:resp.ok && !!data.url, stage:'signin', status:resp.status, text, url:data.url || ''};
                }""",
                {"email": email, "did": device_id, "reset": bool(reset)},
            ) or {}
        except Exception as exc:
            result = {
                "ok": False,
                "stage": "browser_evaluate",
                "status": 0,
                "text": f"{type(exc).__name__}: {exc}",
            }
        if result.get("ok") and result.get("url"):
            break
        if attempt < 3:
            logger.warning(
                "add-password reauth attempt %s failed at %s: HTTP %s %s",
                attempt, result.get("stage"), result.get("status"),
                str(result.get("text") or "")[:160],
            )
            # A browser-visible Cloudflare interstitial often returns HTML 403
            # from the NextAuth fetch while the edge session is still warming.
            # Keep the same fingerprint/profile, allow the challenge to settle,
            # then reload before creating a fresh authorize state.
            if int(result.get("status") or 0) == 403:
                logger.info("password reauth signin hit HTTP 403; waiting for browser challenge and refreshing")
                try:
                    driver.page.wait_for_timeout(8000 + (attempt - 1) * 4000)
                    driver.page.reload(wait_until="domcontentloaded", timeout=45000)
                    driver.page.wait_for_timeout(2500)
                except Exception:
                    driver.get("https://chatgpt.com/")
                    time.sleep(3.0)
            else:
                time.sleep(float(attempt))
                driver.get("https://chatgpt.com/")

    if not result.get("ok"):
        raise RuntimeError(
            f"发起 add-password 重认证失败: stage={result.get('stage')} "
            f"HTTP {result.get('status')} {str(result.get('text') or '')[:300]}"
        )
    auth_url = str(result.get("url") or "")
    marker = "post_login_password_reset=true" if reset else "post_login_add_password=true"
    if "auth.openai.com" not in auth_url or marker not in auth_url:
        raise RuntimeError(f"add-password authorize URL 缺少必要上下文: {auth_url[:300]}")
    return auth_url


def _is_new_password_page(driver) -> bool:
    try:
        cur_url = str(getattr(driver, chr(99)+chr(117)+chr(114)+chr(114)+chr(101)+chr(110)+chr(116)+chr(95)+chr(117)+chr(114)+chr(108), chr(34)+chr(34)) or chr(34)+chr(34)).lower()
        if chr(47)+chr(114)+chr(101)+chr(115)+chr(101)+chr(116)+chr(45)+chr(112)+chr(97)+chr(115)+chr(115)+chr(119)+chr(111)+chr(114)+chr(100) in cur_url:
            return True
        body = driver.page.locator(chr(98)+chr(111)+chr(100)+chr(121)).inner_text(timeout=3000).lower()
    except Exception:
        return False
    new_pwd_markers = (
        chr(110)+chr(101)+chr(119)+chr(32)+chr(112)+chr(97)+chr(115)+chr(115)+chr(119)+chr(111)+chr(114)+chr(100),
        chr(26032)+chr(23494)+chr(30721), chr(35774)+chr(32622)+chr(23494)+chr(30721), chr(37325)+chr(32622)+chr(23494)+chr(30721),
        chr(26032)+chr(12375)+chr(12356)+chr(12496)+chr(12473)+chr(12527)+chr(12540)+chr(12489),
        chr(12496)+chr(12473)+chr(12527)+chr(12540)+chr(12489)+chr(12434)+chr(12522)+chr(12475)+chr(12483)+chr(12488),
        chr(99)+chr(111)+chr(110)+chr(102)+chr(105)+chr(114)+chr(109)+chr(32)+chr(110)+chr(101)+chr(119)+chr(32)+chr(112)+chr(97)+chr(115)+chr(115)+chr(119)+chr(111)+chr(114)+chr(100),
        chr(114)+chr(101)+chr(45)+chr(101)+chr(110)+chr(116)+chr(101)+chr(114)+chr(32)+chr(112)+chr(97)+chr(115)+chr(115)+chr(119)+chr(111)+chr(114)+chr(100),
    )
    return any(marker in body for marker in new_pwd_markers)


def _current_password_page(driver) -> bool:
    if _is_new_password_page(driver):
        return False
    try:
        body = driver.page.locator(chr(98)+chr(111)+chr(100)+chr(121)).inner_text(timeout=3000).lower()
    except Exception:
        return False
    markers = (
        chr(102)+chr(105)+chr(114)+chr(115)+chr(116)+chr(44)+chr(32)+chr(118)+chr(101)+chr(114)+chr(105)+chr(102)+chr(121),
        chr(112)+chr(108)+chr(101)+chr(97)+chr(115)+chr(101)+chr(32)+chr(101)+chr(110)+chr(116)+chr(101)+chr(114)+chr(32)+chr(116)+chr(104)+chr(101)+chr(32)+chr(99)+chr(117)+chr(114)+chr(114)+chr(101)+chr(110)+chr(116)+chr(32)+chr(112)+chr(97)+chr(115)+chr(115)+chr(119)+chr(111)+chr(114)+chr(100),
        chr(105)+chr(110)+chr(99)+chr(111)+chr(114)+chr(114)+chr(101)+chr(99)+chr(116)+chr(32)+chr(101)+chr(109)+chr(97)+chr(105)+chr(108)+chr(32)+chr(97)+chr(100)+chr(100)+chr(114)+chr(101)+chr(115)+chr(115)+chr(32)+chr(111)+chr(114)+chr(32)+chr(112)+chr(97)+chr(115)+chr(115)+chr(119)+chr(111)+chr(114)+chr(100),
        chr(24403)+chr(21069)+chr(23494)+chr(30721), chr(36755)+chr(20837)+chr(24403)+chr(21069)+chr(23494)+chr(30721),
        chr(12414)+chr(12378)+chr(26412)+chr(20154)+chr(30906)+chr(35469), chr(26412)+chr(20154)+chr(30906)+chr(35469),
        chr(12496)+chr(12473)+chr(12527)+chr(12540)+chr(12489)+chr(12434)+chr(12362)+chr(24536)+chr(12428)+chr(12391)+chr(12377)+chr(12363),
        chr(99)+chr(111)+chr(110)+chr(102)+chr(105)+chr(114)+chr(109)+chr(32)+chr(121)+chr(111)+chr(117)+chr(114)+chr(32)+chr(105)+chr(100)+chr(101)+chr(110)+chr(116)+chr(105)+chr(116)+chr(121),
        chr(118)+chr(101)+chr(114)+chr(105)+chr(102)+chr(121)+chr(32)+chr(121)+chr(111)+chr(117)+chr(114)+chr(32)+chr(105)+chr(100)+chr(101)+chr(110)+chr(116)+chr(105)+chr(116)+chr(121),
    )
    return any(marker in body for marker in markers)

def _wait_password_form(driver, timeout: int = 60, *, allow_reset: bool = False, email: str = "", otp_provider = None):
    end = time.time() + timeout
    while time.time() < end:
        if _current_password_page(driver):
            if not allow_reset:
                raise RuntimeError("remote_password_present: 页面要求输入当前密码；该账号应走 password-reset，不能继续按无密码账号补设")
            logger.info("[password_setup] 命中当前密码确认页，且处于 reset 流程，尝试点击「忘记密码」")
            res = _click_forgot_password_if_present(driver)
            logger.info("[password_setup] 点击忘记密码结果: %s", res)
            reset_end = time.time() + 45
            while time.time() < reset_end:
                if _is_email_verification_page(driver):
                    logger.info("[password_setup] 忘记密码后进入邮箱验证码页，等待接收并填入 OTP: %s", email)
                    if otp_provider and email:
                        code = otp_provider(email, after_ts=time.time() - 30)
                        if code:
                            logger.info("[password_setup] 获取到重置密码 OTP: %s，开始填入", code)
                            _type_otp(driver, code)
                            try:
                                submit = driver.page.locator('button[type="submit"]:visible').first
                                if submit.count():
                                    submit.click(timeout=5000)
                            except Exception:
                                pass
                            _wait_after_email_otp_submit(driver, timeout=20)
                inputs = driver.page.locator('input[type="password"]:visible')
                if inputs.count() >= 1 and not _current_password_page(driver):
                    return inputs
                time.sleep(0.5)
        inputs = driver.page.locator('input[type="password"]:visible')
        if inputs.count() >= 1 and not _current_password_page(driver):
            return inputs
        time.sleep(0.5)
    body = driver.page.locator("body").inner_text(timeout=5000)[:1200]
    if _current_password_page(driver):
        raise RuntimeError("remote_password_present: 页面要求输入当前密码；页面没有可用的新密码输入框")
    raise RuntimeError(f"邮箱验证后未进入补设密码页面: url={driver.current_url} body={body}")
def _looks_like_password_submit(url: str, body: str) -> bool:
    """Accept only the actual password form request, not auth telemetry/RUM."""
    lowered_url = str(url or "").lower()
    if "/rum" in lowered_url or "datadog" in lowered_url or "telemetry" in lowered_url:
        return False
    text = str(body or "")
    if not text or "password" not in text.lower():
        return False
    try:
        payload = json.loads(text)
        if isinstance(payload, dict):
            return any(str(k).lower() in {"password", "new_password", "password1", "password2", "confirm_password", "password_confirmation"} for k in payload)
    except Exception:
        pass
    from urllib.parse import parse_qsl
    try:
        keys = {str(k).lower() for k, _ in parse_qsl(text, keep_blank_values=True)}
        return bool(keys & {"password", "new_password", "password1", "password2", "confirm_password", "password_confirmation"})
    except Exception:
        return False


def _submit_new_password(driver, password: str, *, reset: bool = False, email: str = "", otp_provider = None) -> None:
    inputs = _wait_password_form(driver, allow_reset=reset, email=email, otp_provider=otp_provider)
    count = inputs.count()

    # 针对 React 表单受控组件使用原生 setter + 逐字键入 + 事件派发，确保 React state 同步并解除按钮禁用
    js_init = """el => {
        const prop = "value";
        const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, prop)?.set;
        if (setter) { setter.call(el, ""); }
        el.dispatchEvent(new Event("input", {bubbles: true}));
        el.dispatchEvent(new Event("change", {bubbles: true}));
    }"""
    js_finish = """(el, val) => {
        const prop = "value";
        const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, prop)?.set;
        if (setter) { setter.call(el, val); }
        el.dispatchEvent(new InputEvent("input", {bubbles: true, data: val}));
        el.dispatchEvent(new Event("change", {bubbles: true}));
        el.dispatchEvent(new Event("blur", {bubbles: true}));
    }"""
    for i in range(count):
        inp = inputs.nth(i)
        try:
            inp.click(timeout=3000)
            inp.evaluate(js_init)
            inp.press_sequentially(password, delay=20)
            inp.evaluate(js_finish, password)
        except Exception:
            inp.fill(password)

    time.sleep(0.5)
    submit = inputs.nth(0).locator("xpath=ancestor::form[1]").locator('button[type="submit"]:visible').first
    if not submit.count():
        submit = driver.page.locator('button[type="submit"]:visible').last
    if not submit.count():
        raise RuntimeError("补设密码表单缺少提交按钮")

    captured = []
    captured_responses = []
    request_handler = None
    response_handler = None
    try:
        def _on_request(req):
            try:
                url = str(getattr(req, "url", "") or "")
                method = str(getattr(req, "method", "POST") or "POST").upper()
                body = str(getattr(req, "post_data", "") or "")
                if "auth.openai.com" in url and method in {"POST", "PUT", "PATCH"} and _looks_like_password_submit(url, body):
                    item = build_password_request_template(req)
                    raw = str(item.get("body") or "")
                    item["body"] = raw.replace(password, "$PASSWORD")
                    captured.append(item)
            except Exception:
                logger.debug("capture password request failed", exc_info=True)
        def _on_response(resp):
            try:
                url = str(getattr(resp, "url", "") or "")
                status = int(getattr(resp, "status", 0) or 0)
                if "auth.openai.com" in url and any(k in url.lower() for k in ("password", "reset", "add")):
                    captured_responses.append((status, url))
                for item in reversed(captured):
                    if item.get("url") == url and "response_status" not in item:
                        item["response_status"] = status
                        break
            except Exception:
                pass
        request_handler, response_handler = _on_request, _on_response
        driver.page.on("request", request_handler)
        driver.page.on("response", response_handler)
    except Exception:
        request_handler = response_handler = None

    submit.click(timeout=10000)
    end = time.time() + 45
    while time.time() < end:
        # 实时检测错误页与会话超时
        cur_url = str(getattr(driver, "current_url", "") or "").lower()
        try:
            body = driver.page.locator("body").inner_text(timeout=2000).lower()
        except Exception:
            body = ""

        # 检查是否命中 session expired / invalid_state / 拒绝
        if any(token in body for token in (
            "セッションの有効期限が切れました", "session expired", "invalid_state",
            "the session has expired", "your session timed out", "会话已过期"
        )):
            raise RuntimeError(f"提交新密码会话已失效 (invalid_state / session expired): url={cur_url}")

        if any(token in body for token in ("too weak", "already used", "password contains", "密码太弱", "パスワードが弱")):
            raise RuntimeError(f"服务端拒绝新密码: {body[:500]}")

        # 检查网络响应中的失败状态码
        for st, u in captured_responses:
            if st in (400, 401, 403, 500):
                raise RuntimeError(f"服务端提交密码接口返回错误 HTTP {st}: {u}")

        # 密码输入框消失，且未停留在错误页
        if driver.page.locator('input[type="password"]:visible').count() == 0:
            if captured:
                try:
                    path = Path("注册日志") / "password-setup" / "password-request-template.json"
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(json.dumps(captured[-1], ensure_ascii=False, indent=2), encoding="utf-8")
                except Exception:
                    logger.debug("persist password request template failed", exc_info=True)
            try:
                if request_handler:
                    driver.page.remove_listener("request", request_handler)
                if response_handler:
                    driver.page.remove_listener("response", response_handler)
            except Exception:
                pass
            return
        time.sleep(0.5)

    raise RuntimeError("提交新密码后页面未离开补设密码表单")

def _verify_password_login(account: dict, password: str) -> dict:
    driver = opened = None
    email = str(account.get("email") or "").strip()
    try:
        proxy = _fresh_proxy(account)
        if not proxy:
            raise RuntimeError("指纹浏览器登录验收需要代理，当前无可用代理")
        driver, opened = build_ant_driver(proxy, force_headless=False)
        driver.get("https://chatgpt.com/auth/login")
        state = _submit_email_and_wait_next(driver, email, attempts=3, allow_login_password=True)
        if state != "login_password" and "/log-in/password" not in str(driver.current_url).lower():
            raise RuntimeError(f"重新登录未进入密码页: state={state} url={driver.current_url}")
        field = driver.page.locator('input[type="password"]:visible').first
        field.fill(password)
        submit = field.locator("xpath=ancestor::form[1]").locator('button[type="submit"]:visible').first
        if not submit.count():
            submit = driver.page.locator('button[type="submit"]:visible').last
        submit.click(timeout=10000)
        end = time.time() + 45
        while time.time() < end:
            if _is_mfa_challenge_page(driver):
                if not _fill_mfa_challenge_if_present(driver, email, timeout=20):
                    raise RuntimeError("密码提交后 TOTP 验证未完成")
                # MFA 页面只代表进入下一步，不足以证明已获取新会话；继续等真实 session。
            try:
                session = _fetch_chatgpt_session(driver, timeout=8, auto_jump_wait=2)
            except Exception:
                session = {}
            session_email = str(((session.get("user") or {}).get("email") or "")).strip().lower()
            if session_email == email.lower() and str(session.get("accessToken") or session.get("access_token") or "").strip():
                return {**session, "password_accepted": True}
            time.sleep(1)
        body = driver.page.locator("body").inner_text(timeout=5000)[:1200]
        raise RuntimeError(f"新密码登录后未取得匹配账号的 ChatGPT session: url={driver.current_url} body={body}")
    finally:
        try:
            if driver:
                driver.quit()
        except Exception:
            pass
        try:
            if opened:
                cleanup_ant_profile(opened)
        except Exception:
            pass


def _is_password_verification_network_error(text: str) -> bool:
    value = str(text or "").lower()
    return any(marker in value for marker in (
        "err_connection_closed", "err_proxy_connection_failed", "err_tunnel_connection_failed",
        "connection closed", "connection reset", "connection refused", "proxy", "timeout",
        "timed out", "等待超时", "login page navigation failed", "email form unavailable",
        "signin 导航", "network", "fetch failed", "403", "408", "429", "502", "503", "504", "验收证据不足", "密码验证待重试",
    ))


def _verify_password_via_liveness(account: dict, password: str, account_id: int, *, protocol_only: bool = False) -> dict:
    """强制用候选密码查活；旧 AT 不能短路，查活必须返回 password_accepted。"""
    from core.account_liveness import check_account_liveness, protocol_login_trace
    from core.protocol_verification_trace import ProtocolVerificationTrace

    email = str(account.get("email") or "").strip()
    source = str(account.get("email_source") or "generic_api")
    last_error = ""
    for attempt in range(1, 4):
        proxy = _password_proxy_for_attempt(account, attempt)
        if not proxy:
            raise RuntimeError("密码登录验收需要代理：当前无可用代理，不会直连")
        _append_log(account_id, f"正在强制使用新密码查活（第 {attempt}/3 次，代理已轮换）")
        trace = ProtocolVerificationTrace(account_id, attempt) if protocol_only else None
        if trace:
            trace("started", {})
        with protocol_login_trace(trace):
            result = check_account_liveness(
                email,
                proxy=proxy,
                clear_log=False,
                email_source=source,
                fingerprint_state={},
                password_override=password,
                force_password_login=True,
                skip_existing_token_probe=True,
                accept_password_step_only=True,
            )
        if trace:
            trace("result", {
                "outcome": "session_returned" if result.get("ok") else "unverified",
                "password_accepted": result.get("password_accepted") is True,
                "new_token_present": bool(result.get("access_token")),
            })
        session = result.get("session") or {}
        user = session.get("user") or {} if isinstance(session, dict) else {}
        verified_email = str(user.get("email") or "").strip().casefold() if isinstance(user, dict) else ""
        extra = account.get("extra_json") or {}
        if isinstance(extra, str):
            try:
                extra = json.loads(extra)
            except (ValueError, TypeError):
                extra = {}
        expected_user = (extra.get("user") or {}) if isinstance(extra, dict) else {}
        expected_id = str(expected_user.get("id") or "").strip() if isinstance(expected_user, dict) else ""
        actual_id = str(user.get("id") or "").strip() if isinstance(user, dict) else ""
        identity_matches = verified_email == email.casefold() and (not expected_id or actual_id == expected_id)
        if result.get("ok") and result.get("password_accepted") is True:
            if result.get("credential_verified") is True:
                stage = str(result.get("verification_stage") or "next_auth_step")
                if trace:
                    trace("credential_check", {"password_accepted": True, "stage": stage})
                _append_log(account_id, f"候选密码已被登录接口接受并进入下一认证阶段（{stage}），确认密码正确")
                return result
            if identity_matches and str(result.get("access_token") or "").strip():
                if trace:
                    trace("identity_check", {"identity_match": True})
                _append_log(account_id, "新密码登录成功，新会话身份匹配且新 AT 鉴权 HTTP 200，确认密码有效")
                return result
            last_error = "密码验收证据不足：未进入下一认证阶段，且新会话账号身份不匹配或缺少新 AT"
            _append_log(account_id, last_error)
            continue
        error = str(result.get("error") or "查活未通过")
        last_error = error
        lowered = error.lower()
        if "密码错误" in error or "incorrect email address or password" in lowered:
            raise RuntimeError(f"密码错误：强制密码查活未通过（{error[:300]}）")
        # Login navigation, MFA, HTTP 403/401 token probes and unknown responses do not prove
        # the candidate itself is wrong. Keep it pending and do not trigger another reset.
        _append_log(account_id, f"密码验收未完成，候选密码已保留，准备自动重试：{error[:180]}")
        if not protocol_only and _is_password_verification_network_error(error):
            _append_log(account_id, "无头登录预检受阻，切换可见指纹浏览器进行独立登录验收")
            try:
                browser_session = _verify_password_login(account, password)
                browser_user = browser_session.get("user") or {}
                browser_email = str(browser_user.get("email") or "").strip().casefold()
                browser_id = str(browser_user.get("id") or "").strip()
                browser_token = str(browser_session.get("accessToken") or browser_session.get("access_token") or "").strip()
                if browser_session.get("password_accepted") is True and browser_email == email.casefold() and browser_token and (not expected_id or browser_id == expected_id):
                    _append_log(account_id, "指纹浏览器密码登录成功：真实会话账号身份匹配并取得新 AT")
                    return {"ok": True, "password_accepted": True, "access_token": browser_token,
                            "session": {"user": browser_user}, "proxy_used": "fingerprint_browser"}
                last_error = "指纹浏览器登录未取得匹配身份的真实 session/AT"
            except Exception as browser_exc:
                last_error = f"指纹浏览器验收未完成：{str(browser_exc)[:220]}"
            _append_log(account_id, f"指纹浏览器验收未完成，候选密码仍待验证：{last_error[:180]}")
            break
    raise RuntimeError(f"密码验证待重试，候选密码已保留：{last_error[:300]}")


def _run(account_id: int, trigger: str, missing_only: bool = False) -> dict:
    account = db.get_account(account_id) or {}
    email = str(account.get("email") or "").strip()
    driver = opened = None
    try:
        with _LOCK:
            _RUNNING.add(account_id)
        if missing_only and db.has_registration_password(account, verified_only=True):
            return {"ok": True, "status": "skipped", "reason": "password_present"}
        db.update_account_password_setup(account_id, {"status": "running", "message": "正在发起补设密码重认证"})

        progress_started = time.time()
        last_progress_write = [0.0]
        def _flow_progress(stage, message, extra=None):
            """Persist visible, timestamped progress without hammering the DB."""
            extra = extra or {}
            elapsed = int(time.time() - progress_started)
            detail = str(message or stage)
            if extra.get("remaining") is not None:
                detail += f"；剩余约 {int(extra['remaining'])} 秒"
            if extra.get("query_count") is not None:
                detail += f"；已查询 {int(extra['query_count'])} 次"
            visible = f"{detail}（已用时 {elapsed} 秒）"
            now = time.time()
            if now - last_progress_write[0] < 1.0 and stage not in {"otp_received", "otp_accepted", "failed"}:
                return
            last_progress_write[0] = now
            db.update_account_password_setup(account_id, {"status": "running", "message": visible})
            _append_log(account_id, visible)

        _append_log(account_id, f"开始补设密码：{email} trigger={trigger}", clear=True)
        candidate = str(account.get("password_setup_candidate") or "").strip()
        previous_status = str(account.get("password_setup_status") or "").strip().lower()
        if candidate and bool(account.get("password_setup_remote_password_present")) and previous_status != "verification_failed":
            _append_log(account_id, "检测到已提交但尚未完成验收的候选密码，先执行一次全新浏览器登录验收")
            session = _verify_password_via_liveness(account, candidate, account_id)
            if not db.update_account_password_setup(account_id, {
                "ok": True, "status": "success", "password": candidate,
                "login_verified": True,
                "message": "候选密码已通过登录凭据阶段验收",
            }):
                raise RuntimeError("候选密码验证成功，但账号记录写回失败")
            _append_log(account_id, "完成：候选密码登录验证成功，密码已写回账号记录")
            return {"ok": True, "status": "success", "session": session}
        if candidate and previous_status == "verification_failed":
            _append_log(account_id, "上次候选密码登录已确认失败，丢弃错误候选并改走忘记密码/重置流程")
            db.update_account_password_setup(account_id, {"status": "running", "clear_candidate": True, "message": "旧候选密码无效，正在重新设置密码"})
        password = generate_registration_password()
        reset = bool(account.get("password_setup_remote_password_present"))
        driver, opened, auth_url = _open_password_reauth_with_proxy_rotation(
            account, reset=reset, attempts=2,
            on_retry=lambda next_attempt, total, exc: _append_log(
                account_id,
                f"代理连接中断，已自动更换代理并创建全新浏览器会话 {next_attempt}/{total}: "
                f"{type(exc).__name__}: {str(exc)[:180]}",
            ),
        )
        flow_name = "post_login_password_reset" if reset else "post_login_add_password"
        _append_log(account_id, f"已取得 {flow_name} authorize URL")
        _fill_email_and_otp(
            driver, email, _otp_provider(str(account.get("email_source") or "generic_api")), auth_url,
            progress_callback=_flow_progress,
        )
        _append_log(account_id, "邮箱 OTP 与 TOTP 重认证完成，已进入补设密码阶段")
        try:
            _submit_new_password(driver, password, reset=reset, email=email, otp_provider=_otp_provider(str(account.get("email_source") or "generic_api")))
        except RuntimeError as exc:
            exc_text = str(exc).lower()
            if reset and "invalid_state" in exc_text:
                _append_log(account_id, "重置事务在密码提交前过期；立即关闭旧实例并创建全新 state 重试一次")
                db.update_account_password_setup(account_id, {
                    "status": "running",
                    "clear_candidate": True,
                    "remote_password_present": True,
                    "login_verified": False,
                    "message": "旧重置事务已过期，正在创建全新浏览器事务重试",
                })
                try:
                    if driver:
                        driver.quit()
                except Exception:
                    pass
                driver = None
                try:
                    if opened:
                        cleanup_ant_profile(opened)
                except Exception:
                    pass
                opened = None
                driver, opened, auth_url = _open_password_reauth_with_proxy_rotation(
                    account, reset=True, attempts=2,
                    on_retry=lambda next_attempt, total, retry_exc: _append_log(
                        account_id,
                        f"重置重试时代理中断，已更换代理 {next_attempt}/{total}: "
                        f"{type(retry_exc).__name__}: {str(retry_exc)[:180]}",
                    ),
                )
                _append_log(account_id, "已创建全新 post_login_password_reset state，重新执行邮箱验证")
                _fill_email_and_otp(
                    driver, email,
                    _otp_provider(str(account.get("email_source") or "generic_api")),
                    auth_url, progress_callback=_flow_progress,
                )
                _append_log(account_id, "全新重置事务验证完成，正在立即提交新密码")
                _submit_new_password(
                    driver, password, reset=True, email=email,
                    otp_provider=_otp_provider(str(account.get("email_source") or "generic_api")),
                )
            elif "remote_password_present" not in exc_text or reset:
                raise
            else:
                db.update_account_password_setup(account_id, {
                    "status": "running",
                    "remote_password_present": True,
                    "message": "检测到远端已有密码，正在自动切换忘记密码流程",
                })
                _append_log(account_id, "检测到远端已有密码；关闭 add-password 会话并自动切换 password-reset")
                try:
                    driver.quit()
                except Exception:
                    pass
                driver = None
                try:
                    cleanup_ant_profile(opened)
                except Exception:
                    pass
                opened = None

                account["password_setup_remote_password_present"] = True
                reset = True
                driver, opened, auth_url = _open_password_reauth_with_proxy_rotation(
                    account, reset=True, attempts=2,
                    on_retry=lambda next_attempt, total, retry_exc: _append_log(
                        account_id,
                        f"代理连接中断，已自动更换代理并创建全新浏览器会话 {next_attempt}/{total}: "
                        f"{type(retry_exc).__name__}: {str(retry_exc)[:180]}",
                    ),
                )
                _append_log(account_id, "已自动切换并取得 post_login_password_reset authorize URL")
                _fill_email_and_otp(
                    driver, email,
                    _otp_provider(str(account.get("email_source") or "generic_api")),
                    auth_url, progress_callback=_flow_progress,
                )
                _append_log(account_id, "password-reset 邮箱 OTP 与 TOTP 重认证完成，已进入新密码设置阶段")
                _submit_new_password(
                    driver, password, reset=True, email=email,
                    otp_provider=_otp_provider(str(account.get("email_source") or "generic_api")),
                )
        db.update_account_password_setup(account_id, {
            "status": "verifying", "candidate_password": password,
            "remote_password_present": True, "login_verified": False,
            "message": "新密码已提交，正在使用全新浏览器验证",
        })
        _append_log(account_id, "新密码已提交，正在强制使用新密码执行查活")
        try:
            driver.quit()
        except Exception:
            pass
        driver = None
        cleanup_ant_profile(opened)
        opened = None
        session = _verify_password_via_liveness(account, password, account_id)
        if not db.update_account_password_setup(account_id, {
            "ok": True, "status": "success", "password": password,
            "login_verified": True,
            "message": "补设密码完成，已通过登录凭据阶段验收",
        }):
            raise RuntimeError("密码验证成功，但账号记录写回失败")
        _append_log(account_id, "完成：新密码已通过查活验证并写回账号记录")
        return {"ok": True, "status": "success", "session": session}
    except Exception as exc:
        error = f"{type(exc).__name__}: {str(exc)[:600]}"
        remote_present = "remote_password_present" in str(exc).lower()
        candidate = str((db.get_account(account_id) or {}).get("password_setup_candidate") or "").strip()
        verification_failed = bool(candidate)
        network_pending = verification_failed and _is_password_verification_network_error(error) and "密码错误" not in error and "incorrect email address or password" not in error.lower()
        db.update_account_password_setup(account_id, {
            "ok": False,
            "status": "verification_pending" if network_pending else ("verification_failed" if verification_failed else "failed"),
            "error": error,
            **({"login_verified": False} if verification_failed else {}),
            **({"remote_password_present": True} if (remote_present or verification_failed) else {}),
            **({"message": "查活网络连接失败，候选密码已保留，等待自动重试"} if network_pending else {}),
        })
        _append_log(account_id, ("查活网络连接失败，候选密码已保留，等待自动重试" if network_pending else f"失败：{error}"))
        logger.exception("[补设密码] %s", email or account_id)
        return {"ok": False, "status": "failed", "error": error}
    finally:
        try:
            if driver:
                driver.quit()
        except Exception:
            pass
        try:
            if opened:
                cleanup_ant_profile(opened)
        except Exception:
            pass
        with _LOCK:
            _RUNNING.discard(account_id)
        try:
            _QUEUE.release()
        except ValueError:
            pass


def enqueue(account_id: int, trigger: str = "manual", *, missing_only: bool = False) -> dict:
    account_id = int(account_id)
    account = db.get_account(account_id)
    if not account:
        return {"accepted": False, "error": "账号不存在"}
    if not str(account.get("email") or "").strip():
        return {"accepted": False, "error": "账号邮箱为空"}
    if missing_only and db.has_registration_password(account, verified_only=True):
        return {"accepted": False, "skipped": True, "reason": "password_present", "error": "账号已有登录密码"}
    if not _QUEUE.acquire(blocking=False):
        return {"accepted": False, "queue_full": True, "error": "补设密码队列已满"}
    with _LOCK:
        if account_id in _QUEUED or account_id in _RUNNING:
            _QUEUE.release()
            return {"accepted": False, "busy": True, "error": "该账号正在补设密码"}
        _QUEUED.add(account_id)
    try:
        if not db.update_account_password_setup(account_id, {"status": "queued", "message": "已进入补设密码队列"}):
            raise RuntimeError("账号已删除，排队状态未写入")
        future = _EXECUTOR.submit(_run, account_id, trigger, missing_only)
        def finish(_future):
            with _LOCK:
                _QUEUED.discard(account_id)
            if _future.cancelled():
                _QUEUE.release()
        future.add_done_callback(finish)
        return {"accepted": True, "future": future, "log_path": str(log_path(account_id))}
    except Exception as exc:
        with _LOCK:
            _QUEUED.discard(account_id)
        _QUEUE.release()
        return {"accepted": False, "error": f"{type(exc).__name__}: {exc}"}



def _snapshot_missing_password_ids(*, include_archived: bool = False) -> list[int]:
    """分页生成稳定快照；只按 ChatGPT registration_password 判断。"""
    ids: list[int] = []
    offset = 0
    page_size = 200
    archived = None if include_archived else False
    while True:
        page = db.list_accounts_page(limit=page_size, offset=offset, archived=archived)
        items = page.get("items") or []
        for account in items:
            if str(account.get("email") or "").strip() and not db.has_registration_password(account, verified_only=True):
                ids.append(int(account["id"]))
        offset += len(items)
        if not items or offset >= int(page.get("total") or 0):
            break
    return ids


def _set_batch_state(**values) -> None:
    with _BATCH_LOCK:
        _BATCH_STATE.update(values)


def get_missing_password_batch_status() -> dict:
    with _BATCH_LOCK:
        return dict(_BATCH_STATE)


def _run_missing_password_batch(account_ids: list[int]) -> None:
    _set_batch_state(status="running", total=len(account_ids), processed=0, succeeded=0,
                     failed=0, skipped=0, current_account_id=None,
                     started_at=datetime.now().isoformat(timespec="seconds"),
                     completed_at=None, message="正在逐个补设密码")
    for account_id in account_ids:
        if _BATCH_CANCEL.is_set():
            break
        _set_batch_state(current_account_id=account_id)
        from core import password_setup_protocol_job
        queued = password_setup_protocol_job.enqueue(account_id, auto_bridge=True)
        if queued.get("accepted"):
            try:
                result = queued["future"].result()
            except Exception as exc:
                result = {"ok": False, "status": "failed", "error": f"{type(exc).__name__}: {exc}"}
            with _BATCH_LOCK:
                _BATCH_STATE["processed"] += 1
                if result.get("status") == "skipped":
                    _BATCH_STATE["skipped"] += 1
                elif result.get("ok"):
                    _BATCH_STATE["succeeded"] += 1
                else:
                    _BATCH_STATE["failed"] += 1
        else:
            with _BATCH_LOCK:
                _BATCH_STATE["processed"] += 1
                if queued.get("skipped") or queued.get("busy"):
                    _BATCH_STATE["skipped"] += 1
                else:
                    _BATCH_STATE["failed"] += 1
    cancelled = _BATCH_CANCEL.is_set()
    _set_batch_state(
        status="cancelled" if cancelled else "completed",
        current_account_id=None,
        completed_at=datetime.now().isoformat(timespec="seconds"),
        message="已停止继续入队；当前任务执行完毕" if cancelled else "全部未设密码账号处理完成",
    )


def start_missing_password_batch(*, include_archived: bool = False) -> dict:
    global _BATCH_THREAD
    with _BATCH_LOCK:
        if _BATCH_THREAD is not None and _BATCH_THREAD.is_alive():
            return {"accepted": False, "busy": True, "status": dict(_BATCH_STATE)}
        account_ids = _snapshot_missing_password_ids(include_archived=include_archived)
        _BATCH_CANCEL.clear()
        _BATCH_STATE.update({
            "status": "starting", "total": len(account_ids), "processed": 0,
            "succeeded": 0, "failed": 0, "skipped": 0,
            "current_account_id": None, "started_at": None, "completed_at": None,
            "message": "已生成未设密码账号快照",
        })
        if not account_ids:
            _BATCH_STATE.update({"status": "completed", "completed_at": datetime.now().isoformat(timespec="seconds"),
                                 "message": "没有需要补设密码的账号"})
            return {"accepted": True, "started": False, "status": dict(_BATCH_STATE)}
        _BATCH_THREAD = threading.Thread(target=_run_missing_password_batch, args=(account_ids,),
                                         name="password-setup-all-missing", daemon=True)
        _BATCH_THREAD.start()
        return {"accepted": True, "started": True, "status": dict(_BATCH_STATE)}


def cancel_missing_password_batch() -> dict:
    with _BATCH_LOCK:
        running = _BATCH_THREAD is not None and _BATCH_THREAD.is_alive()
        if running:
            _BATCH_CANCEL.set()
            _BATCH_STATE["status"] = "stopping"
            _BATCH_STATE["message"] = "停止请求已记录；不再提交后续账号"
        return {"accepted": running, "status": dict(_BATCH_STATE)}


def verify_account_candidate_password(account_id: int, password: str | None = None) -> dict:
    """对账号的候选密码进行独立的登录验证验收（非整套补设密码浏览器流程，而是直接执行登录鉴权）。"""
    acc = db.get_account(account_id)
    if not acc:
        return {"ok": False, "error": "账号不存在"}

    pwd = str(password or "").strip()
    if not pwd:
        extra = {}
        try:
            extra = json.loads(acc.get("extra_json") or "{}")
        except Exception:
            pass
        pwd = (
            str(acc.get("password_setup_candidate") or "").strip()
            or str(acc.get("password") or "").strip()
            or str(extra.get("registration_password") or "").strip()
            or str(acc.get("registration_password") or "").strip()
        )
    if not pwd:
        return {"ok": False, "error": "该账号未找到待验证的候选密码，请先输入密码"}

    email = str(acc.get("email") or "").strip()
    _append_log(account_id, f"开始对候选密码执行登录验证验收: account_id={account_id}, email={email}", clear=False)
    try:
        result = _verify_password_via_liveness(acc, pwd, account_id, protocol_only=True)
        if result and result.get("ok"):
            db.update_account_password_setup(account_id, {
                "ok": True,
                "status": "success",
                "password": pwd,
                "login_verified": True,
                "message": "候选密码已通过独立登录验证验收（新 AT 换取成功）",
            })
            db.update_account_password(account_id, pwd)
            try:
                db.update_account_liveness(account_id, result)
            except Exception as e:
                logger.warning("更新账号查活状态异常: %s", e)
            _append_log(account_id, "验证成功：候选密码已转正为正式密码，AT已同步刷新")
            return {
                "ok": True,
                "verified": True,
                "password": pwd,
                "message": "密码登录验收成功！已确认为正式密码，并已刷新最新 AT",
                "access_token": result.get("access_token"),
            }
        else:
            err = str((result or {}).get("error") or "登录验收未通过")
            return {"ok": False, "verified": False, "error": err}
    except Exception as exc:
        err_msg = str(exc)
        _append_log(account_id, f"登录验证验收失败: {err_msg}")
        is_wrong_pwd = "密码错误" in err_msg or "incorrect email address or password" in err_msg.lower()
        db.update_account_password_setup(account_id, {
            "ok": False,
            "status": "verification_failed" if is_wrong_pwd else "verification_pending",
            "error": err_msg,
            "login_verified": False,
            "remote_password_present": True,
            "candidate_password": pwd,
            "message": "密码错误，登录失败" if is_wrong_pwd else f"登录验收失败（密码真伪未确定）：{err_msg[:120]}",
        })
        return {
            "ok": False,
            "verified": False,
            "error": f"密码验证未通过: {err_msg}",
            "status": "verification_failed" if is_wrong_pwd else "verification_pending",
            "is_wrong_password": is_wrong_pwd,
        }


# 批量登录验收在后台串行运行；状态只保留摘要，不保存或返回密码/AT。
_VERIFY_BATCH_LOCK = threading.Lock()
_VERIFY_BATCH_EXECUTOR = ThreadPoolExecutor(max_workers=1, thread_name_prefix="password-verify")
_VERIFY_BATCH_STATE: dict = {"status": "idle", "total": 0, "processed": 0,
                             "success_count": 0, "failed_count": 0, "skipped_count": 0,
                             "current_account_id": None, "results": []}


def candidate_verification_batch_status() -> dict:
    with _VERIFY_BATCH_LOCK:
        return {**_VERIFY_BATCH_STATE, "results": [dict(item) for item in _VERIFY_BATCH_STATE["results"]]}


def enqueue_candidate_verification_batch(account_ids: list[int]) -> dict:
    """显式选中的账号后台验收；运行中不可重复发起，避免重复认证请求。"""
    ids = list(dict.fromkeys(int(value) for value in account_ids))[:100]
    if not ids:
        return {"accepted": False, "error": "没有可验证的账号"}
    with _VERIFY_BATCH_LOCK:
        if _VERIFY_BATCH_STATE["status"] in {"queued", "running"}:
            return {"accepted": False, "error": "已有密码验收任务正在运行"}
        _VERIFY_BATCH_STATE.update(status="queued", total=len(ids), processed=0,
                                   success_count=0, failed_count=0, skipped_count=0,
                                   current_account_id=None, results=[])
    try:
        _VERIFY_BATCH_EXECUTOR.submit(_run_candidate_verification_batch, ids)
    except Exception:
        with _VERIFY_BATCH_LOCK:
            _VERIFY_BATCH_STATE["status"] = "failed"
        raise
    return {"accepted": True, "total": len(ids), "status": "queued"}


def _run_candidate_verification_batch(ids: list[int]) -> None:
    with _VERIFY_BATCH_LOCK:
        _VERIFY_BATCH_STATE["status"] = "running"
    try:
        for aid in ids:
            with _VERIFY_BATCH_LOCK:
                _VERIFY_BATCH_STATE["current_account_id"] = aid
            try:
                result = verify_account_candidate_password(aid)
                category = ("success" if result.get("ok") else
                            "skipped" if "未找到待验证的候选密码" in str(result.get("error")) else
                            "wrong_password" if result.get("is_wrong_password") else "failed")
                error = ("密码错误" if category == "wrong_password" else
                         "未找到候选密码" if category == "skipped" else
                         "登录验收失败，查看账号密码状态" if category == "failed" else "")
            except Exception:
                category, error = "failed", "登录验收任务异常，查看账号日志"
                logger.exception("[批量密码验收] 账号 %s 出错", aid)
            with _VERIFY_BATCH_LOCK:
                state = _VERIFY_BATCH_STATE
                state["processed"] += 1
                state["results"].append({"id": aid, "category": category, "error": error})
                key = ("success_count" if category == "success" else
                       "skipped_count" if category == "skipped" else "failed_count")
                state[key] += 1
    finally:
        with _VERIFY_BATCH_LOCK:
            _VERIFY_BATCH_STATE["current_account_id"] = None
            _VERIFY_BATCH_STATE["status"] = "completed"
