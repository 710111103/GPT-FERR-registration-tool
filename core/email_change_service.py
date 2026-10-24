# -*- coding: utf-8 -*-
"""ChatGPT 账号邮箱换绑后台队列。"""
from __future__ import annotations

import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

from core import db
from core.email_provider import (
    acquire_email_from_source, email_material_line,
    release_email_if_unconsumed, wait_for_otp,
)
from core.session import BrowserSession

logger = logging.getLogger(__name__)
_EXECUTOR = ThreadPoolExecutor(max_workers=3, thread_name_prefix="email-change")
_SLOTS = threading.BoundedSemaphore(100)
_RUNNING: set[int] = set()
_LOCK = threading.Lock()
_LOG_DIR = Path(__file__).resolve().parent.parent / "注册日志"
_MIN_ACCOUNT_AGE = timedelta(hours=24)


def log_path(account_id: int) -> Path:
    return _LOG_DIR / f"email-change-{int(account_id)}.log"


def _append_log(account_id: int, message: str, *, clear: bool = False) -> None:
    path = log_path(account_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = "w" if clear else "a"
    with path.open(mode, encoding="utf-8") as fh:
        fh.write(f"{datetime.now().strftime('%H:%M:%S')} [INFO] {message}\n")


def _proxy(value: str | None) -> str:
    text = str(value or "").strip()
    return text if text.lower().startswith(("http://", "https://", "socks4://", "socks5://", "socks5h://")) else ""


def _proxy_label(value: str | None) -> str:
    """日志用代理摘要，保留路由信息但隐藏认证密码。"""
    text = str(value or "").strip()
    if not text:
        return "direct"
    try:
        parsed = urlparse(text)
        auth = "***:***@" if parsed.username or parsed.password else ""
        port = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme}://{auth}{parsed.hostname or '?'}{port}"
    except Exception:
        return "proxy://***"


def _cost(started: float) -> str:
    return f"{time.monotonic() - started:.2f}s"


def _account_age_error(account: dict, now: datetime | None = None) -> str | None:
    """Mirror the server's 24-hour email-change gate before consuming an email."""
    raw = str(account.get("created_at") or "").strip()
    if not raw:
        return None
    try:
        created = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    current = now or (datetime.now(created.tzinfo) if created.tzinfo else datetime.now())
    eligible_at = created + _MIN_ACCOUNT_AGE
    if current >= eligible_at:
        return None
    remaining = eligible_at - current
    total_minutes = max(1, int(remaining.total_seconds() / 60 + 0.999))
    hours, minutes = divmod(total_minutes, 60)
    remaining_text = f"{hours}小时{minutes}分钟" if hours else f"{minutes}分钟"
    return (
        "账号创建未满24小时，服务端暂不允许换绑；"
        f"最早可在 {eligible_at.strftime('%Y-%m-%d %H:%M:%S')} 操作，约剩余{remaining_text}"
    )


def _new_session(account_id: int, proxy, *, email: str = "") -> BrowserSession:
    # 与 2FA/查活统一使用账号级种子。同一账号做敏感操作时保持 device_id、
    # Sentinel sid、浏览器画像稳定，而不是为“换绑”另造一套新设备指纹。
    seed = f"account:{email.lower()}" if email else f"email-change:{account_id}"
    return BrowserSession(proxy=proxy, fingerprint_seed=seed)


def _response_error(resp) -> str:
    try:
        data = resp.json()
        err = data.get("error") if isinstance(data, dict) else None
        if isinstance(err, dict):
            return str(err.get("message") or err.get("code") or data)
        return str(err or data)
    except Exception:
        return str(getattr(resp, "text", "") or f"HTTP {resp.status_code}")[:500]


def _is_reauth_required(exc: BaseException) -> bool:
    text = str(exc or "").lower()
    return "reauth_required" in text or "recent login required" in text


def _post(session: BrowserSession, path: str, token: str, payload: dict) -> dict:
    headers = session.get_chatgpt_headers(referer="https://chatgpt.com/")
    headers.update({
        "authorization": f"Bearer {token}", "oai-device-id": session.device_id,
        "oai-language": session.navigator_language(), "origin": "https://chatgpt.com",
    })
    resp = session.post(f"https://chatgpt.com{path}", headers=headers, data=json.dumps(payload))
    if resp.status_code != 200:
        raise RuntimeError(f"{path} 返回 {resp.status_code}: {_response_error(resp)}")
    data = resp.json()
    if not isinstance(data, dict) or not data.get("success"):
        raise RuntimeError(f"{path} 返回失败: {data}")
    return data


def _post_with_network_retry(
    session: BrowserSession, *, account_id: int, path: str, token: str, payload: dict,
    fingerprint_email: str = "",
) -> tuple[dict, BrowserSession]:
    """TLS reset/超时等传输故障时换会话重试，最后一次明确直连兜底。"""
    last_exc: Exception | None = None
    current = session
    for attempt in range(1, 4):
        attempt_started = time.monotonic()
        _append_log(
            account_id,
            f"HTTP 请求开始：path={path} attempt={attempt}/3 "
            f"route={_proxy_label(getattr(current, 'proxy', None))} "
            f"device_id={str(getattr(current, 'device_id', '') or '')[:12]}...",
        )
        try:
            result = _post(current, path, token, payload)
            _append_log(
                account_id,
                f"HTTP 请求成功：path={path} status=200 attempt={attempt}/3 cost={_cost(attempt_started)}",
            )
            return result, current
        except Exception as exc:
            last_exc = exc
            text = str(exc)
            _append_log(
                account_id,
                f"HTTP 请求失败：path={path} attempt={attempt}/3 cost={_cost(attempt_started)} "
                f"error={type(exc).__name__}: {text[:300]}",
            )
            # 明确的业务 4xx 不重复提交；网络错误、429 和 5xx 才重试。
            if isinstance(exc, RuntimeError) and "返回 4" in text and "返回 429" not in text:
                # reauth_required 也可能是在重试会话上返回；把该会话传回调用方，
                # 后续 Recent Login 必须沿用最后一次有效的 Cookie/代理/设备上下文。
                try:
                    setattr(exc, "_retry_session", current)
                except Exception:
                    pass
                raise
            if attempt >= 3:
                break
            delay = attempt * 2
            next_route = "代理池新会话" if attempt == 1 else "直连兜底"
            _append_log(
                account_id,
                f"请求异常（第 {attempt}/3 次）：{type(exc).__name__}: {text[:300]}；"
                f"{delay}s 后切换到{next_route}重试",
            )
            logger.warning("[邮箱换绑] %s attempt=%s failed: %s", path, attempt, text[:300])
            time.sleep(delay)
            # 第二次从代理池重新选择出口；第三次明确直连，避免坏代理持续 reset。
            current = _new_session(
                account_id, None if attempt == 1 else "", email=fingerprint_email,
            )
    assert last_exc is not None
    raise last_exc


def _enqueue_live_check_after_change(account_id: int, email: str, proxy: str | None = None) -> dict:
    """换绑成功后立即排队查活，用新邮箱重新登录并刷新失效的 AT。"""
    from core import live_check_service

    account = db.get_account(int(account_id)) or {}
    saved_proxy = proxy or str(account.get("proxy_used") or "").strip() or None
    if saved_proxy:
        from core.chatgpt_plan import rotate_proxy_session
        saved_proxy, _ = rotate_proxy_session(saved_proxy)
    result = live_check_service.enqueue_account_live_check(
        account_id=int(account_id), email=str(email),
        trigger="email_change_auto", proxy=saved_proxy,
    )
    if result.get("accepted"):
        logger.info("[邮箱换绑] 已自动加入查活队列 account_id=%s email=%s", account_id, email)
        _append_log(account_id, f"自动查活已入队：email={email}")
    else:
        logger.warning(
            "[邮箱换绑] 换绑成功，但自动查活入队失败 account_id=%s email=%s error=%s",
            account_id, email, result.get("error") or "未知错误",
        )
        _append_log(account_id, f"自动查活入队失败：{result.get('error') or '未知错误'}")
    return result


def _refresh_recent_login(
    session: BrowserSession,
    *,
    account_id: int,
    email: str,
    email_source: str,
    access_token: str,
) -> tuple[BrowserSession, str]:
    """优先执行纯协议 Recent Login 重认证，保留原会话与 Cookie，杜绝桌面弹窗。"""
    from core.account_liveness import (
        _clear_optional_bootstrap_circuit,
        _login_via_reauth,
        _warm_authenticated_session,
    )
    from core.openai_auth import AccountUnusableError

    reauth_started = time.monotonic()
    route_label = _proxy_label(getattr(session, "proxy", None))
    device_id_abbr = str(getattr(session, "device_id", "") or "")[:12]
    _append_log(
        account_id,
        f"开始执行纯协议 Recent Login 重认证：route={route_label} device_id={device_id_abbr}...",
    )

    # 1. 使用已有 AT 对原 session 预热登录态（建立 chatgpt.com 上下文与必要 Cookie）
    try:
        _warm_authenticated_session(session, access_token)
    except Exception as exc:
        logger.warning("[邮箱换绑] 登录态预热出现非致命异常 account_id=%s: %s", account_id, exc)
    finally:
        _clear_optional_bootstrap_circuit(session)

    # 2. 纯协议重认证（带有限重试机制，全链路静默无头；支持密码/2FA直通与原邮箱发码）
    last_exc: Exception | None = None
    for attempt in range(1, 3):
        try:
            _append_log(
                account_id,
                f"协议重认证执行中（第 {attempt}/2 次）：执行密码+TOTP/原邮箱 OTP 验证...",
            )
            otp_after_ts = time.time()
            session_info = _login_via_reauth(
                session,
                email=email,
                otp_after_ts=otp_after_ts,
                email_source=email_source or None,
            )
            fresh_token = str((session_info or {}).get("accessToken") or "").strip()
            if not fresh_token:
                raise RuntimeError("纯协议 Recent Login 完成，但返回的 session 缺少 accessToken")

            _append_log(
                account_id,
                f"纯协议 Recent Login 成功：已获取新鲜 AT，cost={_cost(reauth_started)} "
                f"attempt={attempt}/2",
            )
            return session, fresh_token

        except AccountUnusableError as exc:
            _append_log(account_id, f"账号已被服务端判定废弃（{exc}），中止重认证与换绑")
            raise
        except Exception as exc:
            last_exc = exc
            resp = getattr(exc, "response", None)
            err_detail = str(exc)[:200]
            if resp is not None:
                resp_text = (getattr(resp, "text", "") or "").strip()[:300]
                if resp_text:
                    err_detail += f" | body={resp_text}"
            _append_log(
                account_id,
                f"协议重认证尝试失败（第 {attempt}/2 次）：{type(exc).__name__}: {err_detail}",
            )
            logger.warning(
                "[邮箱换绑] 纯协议重认证失败 account_id=%s attempt=%s/2: %s",
                account_id, attempt, err_detail,
            )
            if attempt < 2:
                _clear_optional_bootstrap_circuit(session)
                time.sleep(2)

    # 纯协议重认证失败（通常为 Cloudflare 403 拦截或 Cookie 丢失），自动回退到 AntBrowser 浏览器兜底
    _append_log(
        account_id,
        f"纯协议重认证未成功（{type(last_exc).__name__}: {str(last_exc)[:100]}），"
        "自动调用 AntBrowser 无头浏览器重试登录与 2FA...",
    )
    try:
        from core.antbrowser_liveness import refresh_recent_login_browser
        session_info = refresh_recent_login_browser(
            email,
            email_source=email_source or None,
            proxy=getattr(session, "proxy", None),
            force_headless=True,
        )
        fresh_token = str((session_info or {}).get("accessToken") or "").strip()
        if not fresh_token:
            raise RuntimeError("AntBrowser 登录完成，但 /api/auth/session 未返回 accessToken")
        # 同步登录状态到 BrowserSession
        new_proxy = session_info.get("_network_proxy") or getattr(session, "proxy", None)
        session = _new_session(account_id, new_proxy, email=email)
        for cookie_name in ("__Secure-next-auth.session-token", "__Secure-next-auth.callback-url", "__Host-next-auth.csrf-token"):
            if cookie_name in session_info:
                session.cookies.set(cookie_name, session_info[cookie_name])
        _warm_authenticated_session(session, fresh_token)
        _append_log(
            account_id,
            f"AntBrowser 兜底重认证成功：已获取新鲜 AT，cost={_cost(reauth_started)}",
        )
        return session, fresh_token
    except Exception as browser_exc:
        logger.exception("[邮箱换绑] AntBrowser 兜底重认证亦失败: account_id=%s", account_id)
        err_msg = f"Recent Login 失败（纯协议失败: {last_exc}，浏览器兜底失败: {browser_exc}）"
        _append_log(account_id, f"重认证流程终止：{err_msg}")
        raise RuntimeError(err_msg) from browser_exc


def _begin_change_with_optional_reauth(
    session: BrowserSession,
    *,
    account_id: int,
    current_email: str,
    current_source: str,
    new_email: str,
    access_token: str,
) -> tuple[BrowserSession, str, float, bool]:
    """优先直接 begin；仅在服务端明确要求 Recent Login 时验证原邮箱。"""
    otp_after_ts = time.time()
    try:
        _, session = _post_with_network_retry(
            session,
            account_id=account_id,
            path="/backend-api/accounts/change_email/begin",
            token=access_token,
            payload={"email": new_email},
            fingerprint_email=current_email,
        )
        _append_log(account_id, "现有 AT 满足 Recent Login 要求，已跳过原邮箱 OTP 重认证")
        return session, access_token, otp_after_ts, False
    except Exception as exc:
        retry_session = getattr(exc, "_retry_session", None)
        if retry_session is not None:
            session = retry_session
            _append_log(
                account_id,
                f"换绑业务响应沿用网络重试后的会话：proxy={_proxy_label(getattr(session, 'proxy', None))} "
                f"device_id={str(getattr(session, 'device_id', '') or '')[:12]}...",
            )
        if not _is_reauth_required(exc):
            raise

    _append_log(account_id, "服务端返回 reauth_required，开始执行原邮箱 OTP 重认证")
    session, fresh_token = _refresh_recent_login(
        session,
        account_id=account_id,
        email=current_email,
        email_source=current_source,
        access_token=access_token,
    )
    # 新邮箱 OTP 的时间基准必须放在第二次 begin 之前，不能沿用重认证前时间。
    otp_after_ts = time.time()
    _, session = _post_with_network_retry(
        session,
        account_id=account_id,
        path="/backend-api/accounts/change_email/begin",
        token=fresh_token,
        payload={"email": new_email},
        fingerprint_email=current_email,
    )
    _append_log(account_id, "原邮箱重认证完成，使用新鲜 AT 重试 begin 成功")
    return session, fresh_token, otp_after_ts, True


def _check_live_in_current_session(
    session: BrowserSession,
    *,
    account_id: int,
    email: str,
    email_source: str,
) -> dict:
    """换绑后复用当前已通过 CF/reauth 的会话重新登录并刷新 AT。"""
    from core.account_liveness import (
        _login_via_password_or_otp,
        _safe_fingerprint_for_account,
        _safe_fingerprint_text_for_account,
    )
    from core.chatgpt_auth import get_csrf_token, signin_openai
    from core.openai_auth import follow_authorize

    live_started = time.monotonic()
    _append_log(account_id, "原会话查活开始：复用 Cookie、CF 状态、出口和当前指纹")
    step_started = time.monotonic()
    csrf = get_csrf_token(session)
    _append_log(account_id, f"原会话查活：CSRF 获取成功，cost={_cost(step_started)}")
    step_started = time.monotonic()
    authorize_url = signin_openai(session, csrf, email)
    _append_log(account_id, f"原会话查活：signin 成功并取得 authorize URL，cost={_cost(step_started)}")
    otp_after_ts = time.time()
    step_started = time.monotonic()
    follow_authorize(session, authorize_url)
    _append_log(account_id, f"原会话查活：authorize 跟随完成，进入密码/OTP/MFA 阶段，cost={_cost(step_started)}")
    step_started = time.monotonic()
    session_info = _login_via_password_or_otp(
        session,
        email,
        otp_after_ts,
        email_source=email_source or None,
    )
    access_token = str((session_info or {}).get("accessToken") or "").strip()
    if not access_token:
        raise RuntimeError("换绑后原会话查活未获取到 access_token")
    _append_log(account_id, f"原会话查活：登录验证及 session 获取成功，cost={_cost(step_started)}")
    result = {
        "ok": True,
        "status": "live",
        "checked_at": datetime.now().isoformat(timespec="seconds"),
        "access_token": access_token,
        "session": session_info,
        "proxy_used": session.proxy or None,
        "fingerprint": _safe_fingerprint_for_account(session),
        "fingerprint_text": _safe_fingerprint_text_for_account(session),
    }
    db.update_account_liveness(account_id, result)
    _append_log(account_id, f"原会话查活成功：最新 AT 已写回，total={_cost(live_started)}")
    return result


def _check_live_after_change_protocol(
    session: BrowserSession,
    *,
    account_id: int,
    email: str,
    email_source: str,
) -> dict:
    """优先使用纯协议建立新邮箱身份，遇风控自动回退至浏览器兜底。"""
    from core.account_liveness import check_account_liveness
    from datetime import datetime

    started = time.monotonic()
    _append_log(account_id, "换绑后新邮箱登录开始：优先使用纯协议建立新身份 session")
    proxy = getattr(session, "proxy", None)
    result = check_account_liveness(
        email,
        proxy=proxy,
        clear_log=False,
        email_source=email_source or None,
    )
    if not result.get("ok") or not result.get("access_token"):
        _append_log(
            account_id,
            f"纯协议登录新邮箱未成功（{result.get('error') or '未知错误'}），调用 AntBrowser 本地浏览器兜底...",
        )
        from core.antbrowser_liveness import refresh_recent_login_browser
        try:
            session_info = refresh_recent_login_browser(
                email,
                email_source=email_source or None,
                proxy=proxy,
                force_headless=True,
            )
            token = str((session_info or {}).get("accessToken") or "").strip()
            if not token:
                raise RuntimeError("AntBrowser 登录完成，但 /api/auth/session 未返回 accessToken")
            result = {
                "ok": True,
                "status": "active",
                "access_token": token,
                "error": None,
                "checked_at": datetime.now().isoformat(timespec="seconds"),
            }
        except Exception as b_exc:
            raise RuntimeError(f"换绑后登录新邮箱失败（协议与浏览器均失败）：{b_exc}") from b_exc

    db.update_account_liveness(account_id, result)
    _append_log(account_id, f"换绑后新邮箱登录成功：新 AT 已写回，cost={_cost(started)}")
    return result


# 兼容旧命名，全面切至纯协议
_check_live_after_change_browser = _check_live_after_change_protocol


def _run(account_id: int, source: str) -> dict:
    new_email = ""
    task_started = time.monotonic()
    stage = "初始化"
    with _LOCK:
        _RUNNING.add(account_id)
    try:
        _append_log(account_id, f"任务执行开始：account_id={account_id} source={source}")
        stage = "读取账号"
        account = db.get_account(account_id)
        if not account:
            raise RuntimeError("账号不存在")
        token = str(account.get("access_token") or "").strip()
        if not token:
            raise RuntimeError("账号缺少 access_token，请先查活刷新 AT")
        stage = "领取新邮箱"
        acquire_started = time.monotonic()
        new_email = acquire_email_from_source(source)
        _append_log(account_id, f"新邮箱领取成功：source={source} email={new_email} cost={_cost(acquire_started)}")
        if new_email.lower() == str(account.get("email") or "").lower():
            raise RuntimeError("领取到的邮箱与当前邮箱相同")
        if not db.mark_account_email_change_running(account_id, new_email):
            raise RuntimeError("换绑任务状态已失效")

        stage = "创建网络会话"
        saved_proxy = _proxy(account.get("proxy_used"))
        if saved_proxy:
            from core.chatgpt_plan import rotate_proxy_session
            saved_proxy, _ = rotate_proxy_session(saved_proxy)
        # 账号没有可复用的真实代理 URL 时，先按全局代理池选路，而不是直接裸连。
        current_email = str(account.get("email") or "").strip()
        current_source = str(account.get("email_source") or "").strip().lower()
        session = _new_session(account_id, saved_proxy or None, email=current_email)
        _append_log(
            account_id,
            f"网络会话已创建：route={'账号代理' if saved_proxy else '全局代理池/默认网络'} "
            f"proxy={_proxy_label(getattr(session, 'proxy', None))}",
        )
        _append_log(account_id, f"指纹摘要：{session.fingerprint_summary_text()}")

        logger.info("[邮箱换绑] begin account_id=%s old=%s new=%s source=%s", account_id, account.get("email"), new_email, source)
        _append_log(account_id, f"开始换绑：原邮箱={account.get('email') or '-'}，新邮箱={new_email}，来源={source}")
        stage = "发送新邮箱验证码/按需重认证"
        session, token, after_ts, reauthenticated = _begin_change_with_optional_reauth(
            session,
            account_id=account_id,
            current_email=current_email,
            current_source=current_source,
            new_email=new_email,
            access_token=token,
        )
        _append_log(
            account_id,
            f"新邮箱验证码发送成功，开始等待 OTP；reauth={'yes' if reauthenticated else 'no'}",
        )
        stage = "等待新邮箱 OTP"
        otp_started = time.monotonic()
        try:
            otp = wait_for_otp(new_email, after_ts=after_ts, email_source=source, force_service=True)
        except Exception as first_otp_exc:
            is_timeout = "超时" in str(first_otp_exc) or "timeout" in str(first_otp_exc).lower()
            if not is_timeout:
                raise
            _append_log(account_id, f"新邮箱首轮等待 OTP 超时（{first_otp_exc}），重新请求发送验证码并开始第二轮等待...")
            logger.warning("[邮箱换绑] 新邮箱首轮等待 OTP 超时 account_id=%s，触发重发...", account_id)
            after_ts = time.time()
            _, session = _post_with_network_retry(
                session,
                account_id=account_id,
                path="/backend-api/accounts/change_email/begin",
                token=token,
                payload={"email": new_email},
                fingerprint_email=current_email,
            )
            _append_log(account_id, "新邮箱验证码已重新发送，开始第二轮等待...")
            otp = wait_for_otp(new_email, after_ts=after_ts, email_source=source, force_service=True)
        _append_log(account_id, f"新邮箱 OTP 获取成功：source={source} cost={_cost(otp_started)}（验证码不写入日志）")
        stage = "验证新邮箱 OTP"
        _, session = _post_with_network_retry(
            session, account_id=account_id,
            path="/backend-api/accounts/change_email/verify", token=token,
            payload={"email": new_email, "code": otp},
            fingerprint_email=current_email,
        )
        _append_log(account_id, "新邮箱 OTP 服务端验证成功，开始更新本地账号记录")

        stage = "更新本地账号"
        # 尝试立即在当前存活会话中拉取新 Token，省去排队走慢速查活
        fresh_at = None
        try:
            from core.account_export import fetch_session
            fresh_session_info = fetch_session(session)
            fresh_at = str((fresh_session_info or {}).get("accessToken") or "").strip()
            if fresh_at:
                _append_log(account_id, "换绑验证成功后已立即在当前会话中刷新获取到最新 AT！")
        except Exception as sess_exc:
            logger.debug("[邮箱换绑] 会话级即时获取 AT 未通过，后续交给查活队列: %s", sess_exc)

        db_started = time.monotonic()
        db.finish_account_email_change(
            account_id, ok=True, new_email=new_email, source=source,
            material_line=email_material_line(new_email, source),
        )
        if fresh_at:
            db.update_account_access_token(account_id, fresh_at)
            _append_log(account_id, f"本地账号更新成功：current_email={new_email}，最新 AT 已即时写回！cost={_cost(db_started)}")
        else:
            _append_log(account_id, f"本地账号更新成功：current_email={new_email}，旧 AT 已清空，cost={_cost(db_started)}")

        # verify 后旧 AT 会立即失效。若未在当前会话直接拿到 AT，交给独立查活队列
        stage = "换绑后自动刷新AT"
        live_result = _enqueue_live_check_after_change(
            account_id, new_email, proxy=getattr(session, "proxy", None),
        )
        live_accepted = bool(live_result.get("accepted"))
        live_mode = "immediate_refreshed" if fresh_at else ("queued" if live_accepted else "pending_retry")
        logger.info(
            "[邮箱换绑] 成功 account_id=%s new=%s；刷新 AT 状态=%s",
            account_id, new_email, live_mode,
        )
        _append_log(account_id, f"换绑任务完成：live_check_mode={live_mode} total={_cost(task_started)}")
        return {
            "ok": True, "id": account_id, "email": new_email,
            "access_token": fresh_at,
            "live_check_started": live_accepted,
            "live_check_mode": live_mode,
            "live_check_error": None if (fresh_at or live_accepted) else live_result.get("error"),
        }
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        db.finish_account_email_change(account_id, ok=False, new_email=new_email or None, source=source, error=error)
        _append_log(account_id, f"换绑失败：stage={stage} total={_cost(task_started)} error={error}")
        if new_email:
            try:
                release_email_if_unconsumed(new_email, note=f"账号 #{account_id} 换绑失败: {error[:300]}")
                _append_log(account_id, f"失败邮箱处理完成：已请求回收 email={new_email}")
            except Exception:
                _append_log(account_id, f"失败邮箱回收异常：email={new_email}")
                logger.exception("[邮箱换绑] 回收新邮箱失败: %s", new_email)
        logger.exception("[邮箱换绑] 失败 account_id=%s", account_id)
        return {"ok": False, "id": account_id, "error": error}
    finally:
        with _LOCK:
            _RUNNING.discard(account_id)
        _SLOTS.release()


def enqueue(account_id: int, source: str, trigger: str = "manual") -> dict:
    account_id = int(account_id)
    source = str(source or "").strip().lower()
    account = db.get_account(account_id)
    if not account:
        return {"accepted": False, "error": "账号不存在"}
    age_error = _account_age_error(account)
    if age_error:
        return {"accepted": False, "error": age_error, "code": "email_change_account_too_new"}
    if not _SLOTS.acquire(blocking=False):
        return {"accepted": False, "error": "邮箱换绑队列已满"}
    if not db.claim_account_email_change(account_id, source, trigger):
        _SLOTS.release()
        return {"accepted": False, "busy": True, "error": "账号正在换绑或不存在"}
    _append_log(account_id, f"换绑任务已入队：source={source} trigger={trigger}", clear=True)
    try:
        future = _EXECUTOR.submit(_run, account_id, source)
        return {"accepted": True, "future": future}
    except Exception as exc:
        _SLOTS.release()
        db.finish_account_email_change(account_id, ok=False, error=str(exc))
        _append_log(account_id, f"换绑任务提交失败：{type(exc).__name__}: {exc}")
        return {"accepted": False, "error": str(exc)}


def is_running(account_id: int) -> bool:
    with _LOCK:
        return int(account_id) in _RUNNING
