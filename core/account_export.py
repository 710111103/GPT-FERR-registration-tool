# -*- coding: utf-8 -*-
"""
注册后处理模块：
    1. 拉取 /api/auth/session，从中抽取 accessToken / user 信息
    2. 设置 2FA（TOTP），返回 secret
    3. 把账号信息（邮箱 + accessToken + TOTP secret）保存到 SQLite

整体复用注册阶段的 BrowserSession（同一 cookie jar / 同一 IP / 同一 UA），
避免再起新会话被风控关联或缺失登录态。
"""
import json
import logging
import random
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse

import pyotp

from core.session import BrowserSession
from core.humanize import delay as human_delay

logger = logging.getLogger(__name__)


class RemoteMfaAlreadyEnabledError(RuntimeError):
    """远端已有 MFA 因子，但本地账号记录缺少对应 TOTP secret。"""


def _clear_twofa_session_circuit(
    session: BrowserSession, *, source: str = "可选预热"
) -> None:
    """清理 2FA 可恢复步骤产生的熔断状态。

    登录态 bootstrap 会访问若干非关键前端接口；其中任意一个接口的 403 都会
    触发 BrowserSession 的通用熔断器。预热本身允许失败，因此不能让该熔断继续
    拦截后面的正式重认证请求（尤其是 ``/api/auth/csrf``）。
    """
    blocked_reason = str(getattr(session, "blocked_reason", "") or "")
    reset = getattr(session, "reset_circuit_breaker", None)
    if callable(reset):
        reset()
    elif getattr(session, "blocked_until", 0.0):
        # 兼容测试桩或旧版 BrowserSession。
        session.blocked_until = 0.0
        session.blocked_reason = ""
    if blocked_reason:
        logger.info("[2FA] 已清理%s产生的熔断状态：%s", source, blocked_reason)


_RETRYABLE_REAUTH_HINTS = (
    "403", "408", "425", "429", "500", "502", "503", "504",
    "proxy", "socks", "timeout", "timed out", "connection", "closed",
    "reset", "temporarily unavailable", "熔断冷却",
)


def _is_retryable_reauth_error(exc: BaseException) -> bool:
    """仅重试限流、服务端错误和传输故障，不重试普通业务 4xx。"""
    response = getattr(exc, "response", None)
    try:
        status = int(getattr(response, "status_code", 0) or 0)
    except (TypeError, ValueError):
        status = 0
    if status:
        return status in (403, 408, 425, 429) or status >= 500
    text = str(exc or "").lower()
    return any(hint in text for hint in _RETRYABLE_REAUTH_HINTS)


def _trigger_reauth_with_retry(session: BrowserSession, email: str) -> str:
    """对 CSRF + signin 阶段的临时故障执行有限指数退避重试。"""
    from config import twofa as _twofa_cfg

    max_attempts = max(1, min(8, int(
        getattr(_twofa_cfg, "TWOFA_REAUTH_MAX_ATTEMPTS", 3) or 3
    )))
    base_delay = max(0.0, min(60.0, float(
        getattr(_twofa_cfg, "TWOFA_REAUTH_RETRY_DELAY", 3.0) or 0.0
    )))
    last_exc: BaseException | None = None

    for attempt in range(1, max_attempts + 1):
        try:
            auth_url = _trigger_reauth(session, email)
            if attempt > 1:
                logger.info("[2FA] 重认证发起重试成功：attempt=%s/%s", attempt, max_attempts)
            return auth_url
        except Exception as exc:
            last_exc = exc
            retryable = _is_retryable_reauth_error(exc)
            if attempt >= max_attempts or not retryable:
                logger.warning(
                    "[2FA] 重认证发起失败且不再重试：attempt=%s/%s retryable=%s error=%s: %s",
                    attempt, max_attempts, retryable, type(exc).__name__, str(exc)[:200],
                )
                raise

            # 403/429 已开启 BrowserSession 熔断；不清理会导致下一轮在本地直接失败。
            _clear_twofa_session_circuit(session, source="重认证请求")
            delay = min(120.0, base_delay * (2 ** (attempt - 1)))
            logger.warning(
                "[2FA] 重认证发起临时失败：attempt=%s/%s error=%s: %s；%.1fs 后重试",
                attempt, max_attempts, type(exc).__name__, str(exc)[:200], delay,
            )
            if delay > 0:
                time.sleep(delay)

    assert last_exc is not None
    raise last_exc


def _follow_reauth_with_retry(session: BrowserSession, auth_url: str) -> str:
    """重试跨站 authorize 导航；首个 403 下发的 CF Cookie 可供下一轮复用。"""
    from config import twofa as _twofa_cfg

    max_attempts = max(1, min(8, int(
        getattr(_twofa_cfg, "TWOFA_REAUTH_MAX_ATTEMPTS", 3) or 3
    )))
    base_delay = max(0.0, min(60.0, float(
        getattr(_twofa_cfg, "TWOFA_REAUTH_RETRY_DELAY", 3.0) or 0.0
    )))

    # 新建协议会话此前会从 ChatGPT 直接命中复杂 authorize URL，auth 域没有
    # document/locale/CF Cookie 上下文。先用简单页面做 best-effort 预热；预热
    # 和正式 authorize 仍严格复用同一个 BrowserSession/deviceId/Cookie Jar。
    _warm_auth_document_for_reauth(session)

    for attempt in range(1, max_attempts + 1):
        try:
            result = _follow_reauth(session, auth_url)
            if attempt > 1:
                logger.info("[2FA] authorize 导航重试成功：attempt=%s/%s", attempt, max_attempts)
            return result
        except Exception as exc:
            retryable = _is_retryable_reauth_error(exc)
            if attempt >= max_attempts or not retryable:
                logger.warning(
                    "[2FA] authorize 导航失败且不再重试：attempt=%s/%s retryable=%s error=%s: %s",
                    attempt, max_attempts, retryable, type(exc).__name__, str(exc)[:200],
                )
                raise

            # 403 响应通常会刷新 __cf_bm。清理本地熔断但保留 Cookie Jar，
            # 下一轮继续使用同一 OAuth state 和新 Cookie 导航。
            _clear_twofa_session_circuit(session, source="authorize 导航")
            delay = min(120.0, base_delay * (2 ** (attempt - 1)))
            logger.warning(
                "[2FA] authorize 导航临时失败：attempt=%s/%s error=%s: %s；"
                "%.1fs 后复用 CF Cookie 重试",
                attempt, max_attempts, type(exc).__name__, str(exc)[:200], delay,
            )
            if delay > 0:
                time.sleep(delay)

    raise RuntimeError("authorize 导航重试耗尽")


def _start_reauth_email_verification(
    session: BrowserSession,
    email: str,
    *,
    max_attempts: int = 2,
) -> float:
    """建立可用的 email-verification 会话并显式发码；409 时从 CSRF 开始重建。"""
    from core.openai_auth import send_email_otp

    attempts = max(1, min(4, int(max_attempts or 1)))
    last_exc: BaseException | None = None
    for attempt in range(1, attempts + 1):
        try:
            auth_url = _trigger_reauth_with_retry(session, email)
            logger.info("[2FA] 重认证 authorize URL 已获取（会话 %s/%s）", attempt, attempts)
            human_delay("api")
            final_url = _follow_reauth_with_retry(session, auth_url)
            logger.info("[2FA] 已跟随重认证 authorize URL，落点=%s", final_url)
            final_lower = str(final_url or "").lower()
            if "/email-verification" not in final_lower:
                raise RuntimeError(
                    f"HTTP 409 invalid_state: 重认证未进入 email-verification，落点={final_url}"
                )

            after_ts = time.time()
            send_email_otp(session)
            logger.info("[2FA] 已显式发送邮箱重认证 OTP")
            human_delay("navigate")
            return after_ts
        except Exception as exc:
            last_exc = exc
            text = str(exc or "").lower()
            invalid_state = "invalid_state" in text or "原邮箱 otp 发送返回 409" in text or "http 409" in text
            if not invalid_state or attempt >= attempts:
                raise
            _clear_twofa_session_circuit(session, source="409 invalid_state 重建")
            logger.warning(
                "[2FA] 重认证会话已失效，将从 CSRF 开始建立全新会话（%s/%s）：%s",
                attempt + 1,
                attempts,
                str(exc)[:220],
            )
            time.sleep(2.0)

    raise last_exc if last_exc else RuntimeError("重认证会话建立失败")


def _account_registration_password(email: str) -> str:
    """读取账号保存的 ChatGPT 密码，供 2FA recent-login 重认证使用。"""
    try:
        from core.codex_oauth import _account_registration_password as load_password

        return str(load_password(email) or "").strip()
    except Exception as exc:
        logger.warning("[2FA] 读取账号密码失败：%s: %s", type(exc).__name__, str(exc)[:180])
        return ""


def _start_twofa_reauth(
    session: BrowserSession,
    email: str,
    *,
    max_attempts: int = 2,
) -> dict:
    """根据服务端真实落点完成 2FA recent-login 重认证。

    新注册账号可能被分配到两种合法状态：
    - ``email-verification``：发送并校验邮箱 OTP；
    - ``log-in/password``：提交账号已保存的注册密码，直接交换新 token。

    旧实现把第二种状态误判成 invalid_state，并反复重建相同会话。
    """
    from core.openai_auth import send_email_otp

    attempts = max(1, min(4, int(max_attempts or 1)))
    last_exc: BaseException | None = None
    for attempt in range(1, attempts + 1):
        try:
            auth_url = _trigger_reauth_with_retry(session, email)
            logger.info("[2FA] 重认证 authorize URL 已获取（会话 %s/%s）", attempt, attempts)
            human_delay("api")
            final_url = _follow_reauth_with_retry(session, auth_url)
            logger.info("[2FA] 已跟随重认证 authorize URL，落点=%s", final_url)
            final_lower = str(final_url or "").lower()

            if "/email-verification" in final_lower:
                after_ts = time.time()
                send_email_otp(session)
                logger.info("[2FA] 已显式发送邮箱重认证 OTP")
                human_delay("navigate")
                return {"mode": "email_otp", "after_ts": after_ts}

            if "/log-in/password" in final_lower:
                password = _account_registration_password(email)
                if not password:
                    raise RuntimeError("重认证进入密码页，但账号记录没有可用注册密码")
                from core.account_liveness import _extract_continue_url, _password_verify

                logger.info("[2FA] 重认证进入密码页，提交账号保存密码：%s", email)
                password_result = _password_verify(session, password)
                continue_url = _extract_continue_url(password_result)
                if not continue_url:
                    raise RuntimeError(f"密码重认证响应缺少 continue_url: {password_result}")
                page = password_result.get("page") if isinstance(password_result, dict) else {}
                page = page if isinstance(page, dict) else {}
                page_type = str(page.get("type") or "").strip().lower()
                if "/mfa-challenge/" in continue_url or page_type == "mfa_challenge":
                    factor_id = ""
                    payload = page.get("payload") if isinstance(page.get("payload"), dict) else {}
                    factor_id = str(payload.get("factor_id") or "").strip()
                    if not factor_id and "/mfa-challenge/" in continue_url:
                        factor_id = continue_url.rstrip("/").rsplit("/", 1)[-1]
                    raise RemoteMfaAlreadyEnabledError(
                        "远端账号已启用 2FA，但本地没有对应 TOTP 密钥"
                        + (f"（factor_id={factor_id}）" if factor_id else "")
                    )
                logger.info("[2FA] 密码重认证通过，开始交换 recent-login token")
                new_token = _exchange_new_token(
                    session,
                    continue_url,
                    referer="https://auth.openai.com/log-in/password",
                )
                return {"mode": "token", "access_token": new_token}

            raise RuntimeError(f"重认证落点不受支持：{final_url}")
        except Exception as exc:
            last_exc = exc
            text = str(exc or "").lower()
            retryable = _is_retryable_reauth_error(exc) or "invalid_state" in text
            if attempt >= attempts or not retryable:
                raise
            _clear_twofa_session_circuit(session, source="2FA 重认证重建")
            logger.warning(
                "[2FA] 重认证状态临时失效，将建立新会话（%s/%s）：%s",
                attempt + 1,
                attempts,
                str(exc)[:220],
            )
            time.sleep(2.0)

    raise last_exc if last_exc else RuntimeError("2FA 重认证建立失败")


def _warm_auth_document_for_reauth(session: BrowserSession) -> None:
    """预热 auth.openai.com 顶层文档；403 时保留新 Cookie 后有限重试。"""
    get_headers = getattr(session, "get_auth_navigate_headers", None)
    request_get = getattr(session, "get", None)
    if not callable(get_headers) or not callable(request_get):
        return
    headers = get_headers(referer="", user_initiated=False)
    for attempt in range(1, 3):
        try:
            resp = request_get(
                "https://auth.openai.com/log-in",
                headers=headers,
                allow_redirects=True,
            )
            status = int(getattr(resp, "status_code", 0) or 0)
            if status < 400:
                logger.info("[2FA] Auth document 预热完成")
                return
            logger.info("[2FA] Auth document 预热返回 HTTP %s，保留响应 Cookie", status)
        except Exception as exc:
            logger.debug("[2FA] Auth document 预热异常：%s: %s", type(exc).__name__, str(exc)[:160])
        _clear_twofa_session_circuit(session, source="Auth document 预热")
        if attempt < 2:
            time.sleep(float(attempt))
    logger.info("[2FA] Auth document 预热未通过，继续正式 authorize 重试链")


def _post_register_dwell_seconds() -> float:
    try:
        from config import register as _register_cfg

        raw = str(getattr(_register_cfg, "POST_REGISTER_DWELL_SECONDS_RANGE", "18,45") or "0,0").strip()
    except Exception:
        raw = "0,0"
    try:
        parts = [float(x.strip()) for x in raw.replace(";", ",").replace("|", ",").split(",") if x.strip()]
        if not parts:
            lo = hi = 0.0
        elif len(parts) == 1:
            lo = hi = parts[0]
        else:
            lo, hi = parts[0], parts[1]
    except Exception:
        lo = hi = 0.0
    lo, hi = max(0.0, lo), max(0.0, hi)
    if hi < lo:
        lo, hi = hi, lo
    seconds = random.uniform(lo, hi) if hi > lo else lo
    return max(0.0, min(300.0, seconds))


def post_register_dwell(email: str, *, label: str = "注册后", driver: Any = None) -> None:
    """注册成功后随机停留一段时间，模拟真实用户浏览与心跳交互。"""
    seconds = _post_register_dwell_seconds()
    if seconds <= 0:
        return
    logger.info("[%s] 注册成功后随机停留 %.1fs 模拟真人浏览与心跳：%s", label, seconds, email)
    end = time.time() + seconds
    last_touch = 0.0
    while time.time() < end:
        if driver is not None and time.time() - last_touch >= random.uniform(3.5, 7.0):
            try:
                page = getattr(driver, "page", None)
                if page is not None and hasattr(page, "evaluate"):
                    page.evaluate("() => { try { window.scrollBy(0, Math.floor(Math.random()*60)-30); } catch(e) {} }")
                elif hasattr(driver, "execute_script"):
                    driver.execute_script("try { window.scrollBy(0, Math.floor(Math.random()*60)-30); } catch(e) {}")
            except Exception:
                pass
            last_touch = time.time()
        time.sleep(random.uniform(0.6, 1.5))


def _account_material_line(email: str, row: dict | None = None) -> str:
    """优先输出 Outlook 原始素材；没有素材时退回邮箱地址。"""
    if row:
        base = row.get("original_email_line") or row.get("email") or email
        from core import db

        # 账号登录密码只有通过独立登录验收后才允许进入导出素材。
        password = db.get_registration_password(row)
        if not password:
            password = str(row.get("password") or "").strip()
        parts = [p for p in str(base or "").split("----") if p != ""]
        if password:
            if not parts:
                base = password
            elif len(parts) == 1:
                if parts[0] != password:
                    parts.insert(1, password)
                base = "----".join(parts)
            elif parts[1] != password:
                looks_like_material = (
                    parts[1].startswith("M.")
                    or parts[1].startswith("m.")
                    or (len(parts[1]) >= 32 and parts[1].count("-") >= 4)
                    or any(ch in parts[1] for ch in ("@", ":", "/", "\\"))
                )
                if looks_like_material:
                    parts.insert(1, password)
                    base = "----".join(parts)
        return base
    return email


def _account_copy_line(
    material_line: str,
    access_token: str,
    gpt_password: str | None = None,
    totp_secret: str | None = None,
) -> str:
    """生成包含 token 的整行归档，方便从批次汇总文件里复制。"""
    parts = [material_line, access_token]
    if gpt_password or totp_secret:
        parts.append(str(gpt_password or ""))
    if totp_secret:
        parts.append(totp_secret)
    return "----".join(parts)


def create_batch_archive_dir(count: int, workers: int = 1) -> None:
    """兼容旧调用方；批次数据现在直接保存到 SQLite，不创建归档目录。"""
    return None


def _append_batch_archive(
    *,
    row_id: int,
    email: str,
    access_token: str,
    totp_secret: str | None,
    email_source: str | None,
    proxy_used: str | None,
    extra: dict,
    batch_dir: Path | None,
) -> None:
    """兼容旧调用方；注册账号已经由 db.insert_account 保存到 SQLite。"""
    from core import db
    # 参数保留是为了兼容注册驱动；不再读取 batch_dir 或写入任何归档文件。
    _ = (db, row_id, email, access_token, totp_secret, email_source, proxy_used, extra, batch_dir)
    return None


def follow_oauth_callback(session: BrowserSession, continue_url: str, referer: str = "https://auth.openai.com/about-you") -> str:
    """
    步骤12.5: 跟随 create_account 返回的 continue_url，完成 OAuth 回调。

    create_account 成功后返回的 continue_url 一般指向
        https://auth.openai.com/authorize/continue?...
    它会再 302 到
        https://chatgpt.com/api/auth/callback/openai?code=...&state=...
    回调请求会让 chatgpt.com 设置 `__Secure-next-auth.session-token` cookie，
    之后 /api/auth/session 才能返回 accessToken。

    Returns:
        重定向链最终落点 URL（一般是 chatgpt.com 站内地址）
    """
    if not continue_url:
        raise ValueError("continue_url 为空，无法完成 OAuth 回调")

    # Rebuild navigation headers at every cross-origin hop. Letting the HTTP
    # client auto-follow auth.openai.com -> chatgpt.com keeps the first hop's
    # fetch metadata, which can complete the redirect without establishing the
    # NextAuth session cookie on the ChatGPT callback.
    current_url = str(continue_url)
    previous_url = str(referer or "")
    redirect_statuses = {301, 302, 303, 307, 308}
    logger.info("[OAuth回调] 逐跳跟随 continue_url 完成 OAuth 回调...")
    for hop in range(1, 11):
        host = (urlparse(current_url).hostname or "").lower()
        if host == "chatgpt.com" or host.endswith(".chatgpt.com"):
            headers = session.get_chatgpt_navigate_headers(
                referer=previous_url,
                user_initiated=(hop == 1),
            )
        else:
            headers = session.get_auth_navigate_headers(
                referer=previous_url,
                user_initiated=(hop == 1),
            )
        resp = session.get(current_url, headers=headers, allow_redirects=False)
        status = int(getattr(resp, "status_code", 0) or 0)
        response_url = str(getattr(resp, "url", "") or current_url)
        parsed = urlparse(response_url)
        safe_location = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        logger.info("[OAuth回调] hop=%s status=%s path=%s", hop, status, safe_location)
        if status not in redirect_statuses:
            if status >= 400:
                # Keep only response metadata: callback URLs and bodies can
                # contain OAuth codes, state, cookies, or account details.
                headers_out = getattr(resp, "headers", {}) or {}
                logger.warning(
                    "[OAuth回调] 请求失败 hop=%s status=%s path=%s content_type=%s cf_mitigated=%s session_cookie_present=%s",
                    hop, status, safe_location,
                    str(headers_out.get("content-type") or "").split(";")[0][:50],
                    str(headers_out.get("cf-mitigated") or "")[:24],
                    bool(extract_nextauth_session_token(session)),
                )
            resp.raise_for_status()
            logger.info("[OAuth回调] 完成, 最终落点: %s", response_url)
            return response_url
        location = str((getattr(resp, "headers", {}) or {}).get("Location") or "").strip()
        if not location:
            raise RuntimeError(f"OAuth 回调第 {hop} 跳返回 {status}，但缺少 Location")
        previous_url = response_url
        current_url = urljoin(response_url, location)
    raise RuntimeError("OAuth 回调重定向超过 10 跳")


def fetch_session(session: BrowserSession) -> dict:
    """
    GET https://chatgpt.com/api/auth/session
    注册成功后立刻调用，拿到 accessToken / user / account / expires。

    Returns:
        完整 session JSON，包含字段:
            - accessToken: str (Bearer token, 用于 backend-api 调用)
            - user: {id, name, email, idp, iat, mfa}
            - account: {id, planType, structure, ...}
            - expires: ISO 时间字符串
    """
    url = "https://chatgpt.com/api/auth/session"
    headers = session.get_nextauth_headers(referer="https://chatgpt.com/")

    logger.info("[Session] 拉取 ChatGPT session 信息...")
    resp = session.get(url, headers=headers)
    resp.raise_for_status()
    data = resp.json()

    if not data.get("accessToken"):
        logger.error(f"[Session] 响应中没有 accessToken: {data}")
        raise RuntimeError("未拿到 accessToken，登录态可能未建立")

    user = data.get("user") or {}
    account = data.get("account") or {}
    logger.info(
        f"[Session] 成功，user_id={user.get('id')}, email={user.get('email')}, "
        f"plan={account.get('planType')}, mfa={user.get('mfa')}"
    )
    return data


def extract_nextauth_session_token(session: BrowserSession) -> str:
    """读取 NextAuth session cookie，兼容单 Cookie 和分片 Cookie。"""
    jar = getattr(getattr(session, "session", None), "cookies", None)
    if jar is None:
        return ""
    if isinstance(jar, dict):
        cookies = jar
    else:
        try:
            cookies = jar.get_dict()
        except Exception:
            try:
                cookies = {cookie.name: cookie.value for cookie in jar}
            except Exception:
                return ""
    bases = ("__Secure-next-auth.session-token", "next-auth.session-token")
    for base in bases:
        value = str(cookies.get(base) or "")
        if value:
            return value
        chunks = []
        prefix = base + "."
        for name, chunk in cookies.items():
            if str(name).startswith(prefix) and str(name)[len(prefix):].isdigit():
                chunks.append((int(str(name)[len(prefix):]), str(chunk or "")))
        if chunks:
            return "".join(value for _, value in sorted(chunks))
    return ""


def _trigger_reauth(session: BrowserSession, email: str, callback_url: str = "https://chatgpt.com/") -> str:
    """
    步骤2-3: 发起密码重认证，返回 OpenAI authorize URL。
    重定向链会自动触发邮箱发送一份新的 OTP（用于 2FA 重认证）。
    """
    # 重新拿一次 csrf（旧的可能已过期）
    csrf_url = "https://chatgpt.com/api/auth/csrf"
    csrf_resp = session.get(csrf_url, headers=session.get_nextauth_headers(referer="https://chatgpt.com/"))
    csrf_resp.raise_for_status()
    csrf_token = csrf_resp.json()["csrfToken"]
    logger.info(f"[2FA] 重认证 CSRF: {csrf_token[:20]}...")

    # POST /api/auth/signin/openai 带 reauth 参数
    query = {
        "connection": "password",
        "login_hint": email,
        "reauth": "password",
        "max_age": "0",
        "ext-oai-did": session.device_id,
    }
    signin_url = "https://chatgpt.com/api/auth/signin/openai?" + urlencode(query)

    headers = session.get_nextauth_headers(referer="https://chatgpt.com/")
    headers["content-type"] = "application/x-www-form-urlencoded"
    headers["origin"] = "https://chatgpt.com"

    body = urlencode({
        "callbackUrl": callback_url,
        "csrfToken": csrf_token,
        "json": "true",
    })

    logger.info("[2FA] 发起重认证 signin/openai...")
    resp = session.post(signin_url, headers=headers, data=body)
    resp.raise_for_status()
    auth_url = resp.json().get("url")
    if not auth_url:
        raise RuntimeError(f"未拿到 reauth authorize URL: {resp.text}")
    return auth_url


def _follow_reauth(session: BrowserSession, auth_url: str) -> str:
    """
    步骤3: 跟随 authorize URL 触发邮箱 OTP 发送。
    auth.openai.com 会重定向到 /email-verification 页面，期间发送 OTP 邮件。
    如果 curl_cffi 协议请求被 Cloudflare 拦截 (403)，自动降级无缝调用真实静默浏览器跟随。
    """
    headers = session.get_auth_navigate_headers(referer="https://chatgpt.com/")
    logger.info("[2FA] 跟随 authorize URL，触发 OTP 发送...")
    try:
        resp = session.get(auth_url, headers=headers, allow_redirects=True)
        final_url = str(getattr(resp, "url", "") or "")
        # Auth 的 MFA 或 email-verification 页面文档可能被 Cloudflare 拦截（403），
        # 但重定向已建立 auth session 并触发服务端发码，后续 API 请求不受 HTML 文档影响。
        if ("/mfa-challenge/" in final_url or "/email-verification" in final_url) and int(getattr(resp, "status_code", 0) or 0) == 403:
            _clear_twofa_session_circuit(session, source="Auth 页面重定向")
            logger.info("[2FA] 已进入验证页面（状态码 403 页面已放行由后续 API 继续）: %s", final_url)
            return final_url
        resp.raise_for_status()
        logger.info(f"[2FA] 落点 URL: {final_url}")
        return final_url
    except Exception as exc:
        is_cf_block = "403" in str(exc) or "Cloudflare" in str(exc)
        if not is_cf_block:
            raise
        logger.warning("[2FA] 协议跟随 authorize 遇到 Cloudflare 403，无缝切换无头浏览器跟随: %s", exc)
        _clear_twofa_session_circuit(session, source="403切换无头浏览器")
        try:
            from core.browser_environment import follow_authorize_with_headless_browser
            browser_final_url = follow_authorize_with_headless_browser(session, auth_url, timeout_ms=30000)
            logger.info("[2FA] 无头浏览器跟随 authorize，落点: %s", browser_final_url)
            normalized_final = str(browser_final_url or "").lower()
            if (
                not normalized_final
                or normalized_final == str(auth_url or "").lower()
                or "/api/accounts/authorize" in normalized_final
                or "/oauth/authorize" in normalized_final
            ):
                raise RuntimeError(
                    "HTTP 403: 无头浏览器仍停留在 authorize 地址，未建立有效重认证会话"
                )
            return browser_final_url
        except Exception as b_exc:
            logger.error("[2FA] 无头浏览器跟随 authorize 亦失败: %s", b_exc)
            raise b_exc from exc


def _validate_reauth_otp(session: BrowserSession, code: str) -> str:
    """
    步骤4: 提交邮箱 OTP 验证。
    返回 continue_url（带 code 参数的 callback URL，用于跳回 chatgpt.com）。
    """
    from core.openai_auth import request_sentinel_token, build_sentinel_header

    url = "https://auth.openai.com/api/accounts/email-otp/validate"
    headers = session.get_auth_headers(referer="https://auth.openai.com/email-verification")

    # 注入 Sentinel Token，避免 Cloudflare 403 拦截
    try:
        sentinel_resp = request_sentinel_token(session, "authorize_continue")
        sentinel_header, so_header = build_sentinel_header(session, sentinel_resp, "authorize_continue")
        if sentinel_header:
            headers["openai-sentinel-token"] = sentinel_header
        if so_header:
            headers["openai-sentinel-so-token"] = so_header
    except Exception as exc:
        logger.warning(f"[Reauth] Sentinel Token 注入跳过: {exc}")

    body = json.dumps({"code": code})

    logger.info(f"[2FA] 提交重认证 OTP: {code}")
    max_500_retries = 3
    resp = None
    for attempt in range(1, max_500_retries + 1):
        resp = session.post(url, headers=headers, data=body)
        status = int(getattr(resp, "status_code", 0) or 0)
        if status == 500 and attempt < max_500_retries:
            logger.warning(
                "[2FA] 重认证 OTP 遭遇服务端 500 (尝试 %s/%s)，等待 2s 后重试提交相同 OTP...",
                attempt,
                max_500_retries,
            )
            time.sleep(2.0)
            continue
        break

    if int(getattr(resp, "status_code", 0) or 0) != 200:
        logger.warning(
            "[2FA] 重认证 OTP 验证失败 status=%s body=%s",
            getattr(resp, "status_code", None),
            str(getattr(resp, "text", "") or "")[:400],
        )
        resp.raise_for_status()
    data = resp.json()
    continue_url = data.get("continue_url")
    if not continue_url:
        raise RuntimeError(f"OTP 验证响应缺少 continue_url: {data}")
    return continue_url


def _snapshot_existing_reauth_otps(email: str, email_source: str | None) -> set[str]:
    """发码前读取通用 API 邮箱当前可见旧码，避免无时间戳页面把历史码当成新码。"""
    source = str(email_source or "").strip().lower()
    if source not in {"generic_api", "mailalias"}:
        return set()
    try:
        from core.generic_api_mail_client import fetch_latest_otp

        code = fetch_latest_otp(
            email,
            after_ts=0,
            max_wait=15,
            poll_interval=1,
            settle_seconds=0,
        )
        if code:
            logger.info("[2FA] 发码前已记录邮箱当前旧 OTP=%s，本轮首次取码将排除", code)
            return {str(code)}
    except Exception as exc:
        logger.info("[2FA] 发码前未读取到旧 OTP，按正常新码流程继续：%s", str(exc)[:160])
    return set()


def _wait_for_reauth_otp_with_retry(
    session: BrowserSession,
    email: str,
    after_ts: float,
    max_attempts: int = 2,
    *,
    email_source: str | None = None,
    exclude_codes: set[str] | None = None,
) -> tuple[str, float]:
    """Wait for a reauth OTP and explicitly retrigger reauth after a pickup timeout."""
    from core.email_provider import wait_for_otp

    attempts = max(1, int(max_attempts or 1))
    current_after_ts = float(after_ts)
    excluded = set(exclude_codes or set())
    source = str(email_source or "").strip().lower()
    for attempt in range(1, attempts + 1):
        try:
            if source in {"generic_api", "mailalias"}:
                from core.generic_api_mail_client import fetch_latest_otp

                code = fetch_latest_otp(
                    email,
                    after_ts=current_after_ts,
                    exclude_codes=excluded,
                )
            else:
                code = wait_for_otp(
                    email,
                    after_ts=current_after_ts,
                    email_source=email_source,
                )
            return code, current_after_ts
        except Exception as exc:
            is_timeout = "超时" in str(exc).lower() or "timeout" in str(exc).lower()
            if not is_timeout or attempt >= attempts:
                raise
            logger.warning(
                "[2FA] 等待邮箱重认证 OTP 超时，重新发起 reauth 触发新验证码（%s/%s）: %s",
                attempt + 1,
                attempts,
                str(exc)[:180],
            )
            current_after_ts = _start_reauth_email_verification(
                session,
                email,
                max_attempts=2,
            )
            logger.info("[2FA] 已重新建立 reauth 并发送邮箱 OTP")
    raise RuntimeError("2FA 邮箱重认证 OTP 等待流程异常结束")


def _exchange_new_token(
    session: BrowserSession,
    continue_url: str,
    *,
    referer: str = "https://auth.openai.com/email-verification",
) -> str:
    """
    步骤5: 跟随 continue_url 完成回调，再次拉 /api/auth/session 拿到新 accessToken
    （此时 token 内嵌的 pwd_auth_time 是新鲜的，2FA enroll 才会接受）。
    如果协议跟随被 Cloudflare 拦截，自动降级至后台无头浏览器完成 OAuth 回调。
    """
    headers = session.get_auth_navigate_headers(referer=referer)
    logger.info("[2FA] 跟随 continue_url，刷新 session-token cookie...")
    use_browser_fallback = False
    try:
        resp = session.get(continue_url, headers=headers, allow_redirects=True)
        if int(getattr(resp, "status_code", 0) or 0) == 403:
            use_browser_fallback = True
    except Exception as exc:
        logger.warning("[2FA] 协议跟随 continue_url 异常 (%s)，将尝试无头浏览器兜底...", exc)
        use_browser_fallback = True

    if use_browser_fallback:
        _clear_twofa_session_circuit(session, source="continue_url 异常清理")
        try:
            from core.browser_environment import follow_oauth_callback_with_headless_browser
            session_data = follow_oauth_callback_with_headless_browser(session, continue_url, timeout_ms=30000)
            new_token = (session_data or {}).get("accessToken")
            if new_token:
                logger.info("[2FA] 无头浏览器成功刷新 accessToken: %s...", new_token[:40])
                return new_token
        except Exception as b_exc:
            logger.warning("[2FA] 无头浏览器回调兜底未成功 (%s)，继续尝试协议获取...", b_exc)

    # 拿新的 accessToken
    new_session = fetch_session(session)
    new_token = new_session["accessToken"]
    logger.info(f"[2FA] 新 accessToken（含新鲜 pwd_auth_time）: {new_token[:40]}...")
    return new_token


def _enroll_totp(session: BrowserSession, access_token: str) -> tuple[str, str]:
    """
    步骤6: 注册 TOTP，返回 (secret, session_id)
    """
    url = "https://chatgpt.com/backend-api/accounts/mfa/enroll"
    headers = session.get_chatgpt_headers(referer="https://chatgpt.com/")
    headers["authorization"] = f"Bearer {access_token}"
    headers["oai-device-id"] = session.device_id
    headers["oai-language"] = session.navigator_language()

    body = json.dumps({"factor_type": "totp"})

    logger.info("[2FA] 注册 TOTP...")
    resp = session.post(url, headers=headers, data=body)
    if resp.status_code != 200:
        logger.error(f"[2FA] enroll 失败 {resp.status_code}: {resp.text}")
        resp.raise_for_status()
    data = resp.json()
    secret = data.get("secret")
    session_id = data.get("session_id")
    if not secret or not session_id:
        raise RuntimeError(f"enroll 响应字段缺失: {data}")
    logger.info(f"[2FA] TOTP secret 已获取: {secret[:4]}...{secret[-4:]}")
    return secret, session_id


def _activate_totp(
    session: BrowserSession,
    access_token: str,
    secret: str,
    session_id: str,
) -> bool:
    """
    步骤7: 用 secret 生成 6 位 TOTP 码，激活 2FA。
    """
    url = "https://chatgpt.com/backend-api/accounts/mfa/user/activate_enrollment"
    headers = session.get_chatgpt_headers(referer="https://chatgpt.com/")
    headers["authorization"] = f"Bearer {access_token}"
    headers["oai-device-id"] = session.device_id
    headers["oai-language"] = session.navigator_language()

    totp_code = pyotp.TOTP(secret).now()
    body = json.dumps({
        "code": totp_code,
        "factor_type": "totp",
        "session_id": session_id,
    })

    logger.info(f"[2FA] 激活 enrollment, code={totp_code}")
    resp = session.post(url, headers=headers, data=body)
    if resp.status_code != 200:
        logger.error(f"[2FA] activate 失败 {resp.status_code}: {resp.text}")
        resp.raise_for_status()
    data = resp.json()
    if not data.get("success"):
        raise RuntimeError(f"激活返回 success=false: {data}")
    return True


def setup_2fa(
    session: BrowserSession,
    email: str,
    otp_code: str | None = None,
    access_token: str | None = None,
) -> str:
    """
    完整的 2FA 设置流程。
    会触发再发一份邮箱验证码：
        - USE_EMAIL_SERVICE=True 时自动从 Outlook 账号池拉取
        - 否则需要用户手动输入

    Args:
        session: 已完成注册的会话
        email: 账号邮箱（用作 login_hint）
        otp_code: 邮箱验证码（None 则按上述策略获取）

    Returns:
        TOTP secret（Base32 字符串），可直接用于 pyotp.TOTP() 生成 6 位动态码
    """
    # 用模块属性读，支持 WebUI 热加载
    from config import email as _email_cfg
    from core.chatgpt_bootstrap import authenticated_bootstrap

    logger.info("=" * 60)
    logger.info("开始设置 2FA")
    logger.info("=" * 60)

    if access_token:
        try:
            logger.info("[2FA] 使用现有 accessToken 预热登录态...")
            authenticated_bootstrap(session, access_token, strict=False)
            human_delay("navigate")
            logger.info("[2FA] accessToken 预热完成")
        except Exception as exc:
            logger.warning("[2FA] accessToken 预热失败，继续按重认证流程执行：%s: %s", type(exc).__name__, str(exc)[:180])
        finally:
            # authenticated_bootstrap(strict=False) 是可选预热。其非关键接口返回
            # 403 时会开启会话级熔断，若不清理，下一步 CSRF 请求甚至不会发出。
            _clear_twofa_session_circuit(session, source="可选预热")

    # 发码前记录无时间戳通用 API 邮箱当前旧码，避免把历史邮件误认为本轮验证码。
    from core.email_provider import resolve_email_source
    email_source = resolve_email_source(email)
    excluded_otp_codes = _snapshot_existing_reauth_otps(email, email_source)

    # 阶段一：重认证。409 invalid_state 时从 CSRF 开始重建整条会话，不能复用失效 auth state。
    logger.info("[2FA] 阶段1：发起重认证")
    reauth_state = _start_twofa_reauth(
        session,
        email,
        max_attempts=2,
    )

    if reauth_state.get("mode") == "token":
        new_token = str(reauth_state.get("access_token") or "")
        if not new_token:
            raise RuntimeError("密码重认证完成但未取得新 accessToken")
        logger.info("[2FA] 密码 recent-login 重认证完成，跳过邮箱 OTP")
    else:
        reauth_otp_after_ts = float(reauth_state.get("after_ts") or time.time())

        if otp_code is None:
            if _email_cfg.USE_EMAIL_SERVICE:
                logger.info("[2FA] 自动等待邮箱重认证 OTP...")
                otp_code, reauth_otp_after_ts = _wait_for_reauth_otp_with_retry(
                    session,
                    email,
                    after_ts=reauth_otp_after_ts,
                    max_attempts=2,
                    email_source=email_source,
                    exclude_codes=excluded_otp_codes,
                )
                logger.info("[2FA] 已收到邮箱重认证 OTP")
            else:
                logger.info("")
                logger.info("[2FA] 请检查邮箱，输入新收到的 6 位验证码")
                otp_code = input(">>> 2FA 验证码: ").strip()
                logger.info("[2FA] 已手动输入邮箱重认证 OTP")

        human_delay("otp_input")
        logger.info("[2FA] 正在提交邮箱重认证 OTP...")
        try:
            continue_url = _validate_reauth_otp(session, otp_code)
        except Exception as first_exc:
        # 部分取码接口会短暂返回缓存中的上一封邮件。若服务端拒绝验证码（401）或 500 异常耗尽，
        # 重新轮询一次并提交最新候选，避免第一次旧码直接终止整个 2FA 流程。
            status_code = getattr(getattr(first_exc, "response", None), "status_code", None)
            if status_code not in (401, 500) or not bool(getattr(_email_cfg, "USE_EMAIL_SERVICE", False)):
                raise
            logger.warning(
                "[2FA] 首次 OTP 验证未成功 (status=%s)，重建重认证会话并等待新验证码",
                status_code,
            )
        # 错码/持续 500 后不沿用当前 auth state；重新获取 CSRF、authorize 并显式发码。
            reauth_otp_after_ts = _start_reauth_email_verification(
                session,
                email,
                max_attempts=2,
            )

            excluded_otp_codes.add(str(otp_code))
            retry_settle = max(5, int(getattr(_email_cfg, "OTP_SETTLE_SECONDS", 5) or 5))
            if email_source in {"generic_api", "mailalias"}:
                from core.generic_api_mail_client import fetch_latest_otp
                fresh_otp = fetch_latest_otp(
                    email,
                    after_ts=reauth_otp_after_ts,
                    settle_seconds=retry_settle,
                    exclude_codes=excluded_otp_codes,
                )
            else:
                from core.email_provider import wait_for_otp
                fresh_otp = wait_for_otp(
                    email,
                    after_ts=reauth_otp_after_ts,
                    settle_seconds=retry_settle,
                    email_source=email_source,
                )
            if fresh_otp == otp_code:
                raise RuntimeError("重发后取件接口仍只返回已被拒绝的旧 OTP，已停止重复提交")
            logger.info("[2FA] 已获取不同的新 OTP=%s，替换首次候选", fresh_otp)
            otp_code = fresh_otp
            continue_url = _validate_reauth_otp(session, otp_code)
        logger.info("[2FA] 邮箱重认证 OTP 验证通过，continue_url=%s", continue_url)
        human_delay("api")
        logger.info("[2FA] 正在交换新 token...")
        new_token = _exchange_new_token(session, continue_url)
        logger.info("[2FA] 已拿到新 token")
        human_delay("api")

    # 阶段二：enroll + activate
    logger.info("[2FA] 阶段2：开始 enroll TOTP")
    secret, session_id = _enroll_totp(session, new_token)
    logger.info("[2FA] enroll 成功，session_id=%s", session_id)

    # 激活请求结果可能因代理断连而未知；候选密钥必须先持久化。
    from core import db
    acc = db.get_account_by_email(email)
    if not acc or not db.update_account_totp_secret(
        acc["id"], {"totp_secret": secret, "status": "prepared", "message": "密钥已暂存，等待激活确认"}
    ):
        raise RuntimeError("2FA 候选密钥持久化失败，已停止激活")

    human_delay("form")
    logger.info("[2FA] 正在激活 TOTP enrollment")
    _activate_totp(session, new_token, secret, session_id)
    logger.info("[2FA] TOTP 激活完成")

    logger.info("=" * 60)
    logger.info(f"✅ 2FA 设置完成! Secret: {secret[:4]}...{secret[-4:]}")
    logger.info("=" * 60)
    return secret


def save_account_data(
    email: str,
    access_token: str,
    totp_secret: str | None = None,
    extra: dict | None = None,
    output_path: Path | None = None,  # 兼容老接口，已废弃
    email_source: str | None = None,
    proxy_used: str | None = None,
    batch_dir: Path | None = None,
    auto_plan_check: bool | None = None,
    plan_check_proxy: str | None = None,
) -> int:
    """
    将账号信息保存到 SQLite；output_path 仅为兼容旧调用方保留。
    返回新插入/更新的 row id。
    """
    from core.db import insert_account
    extra = dict(extra or {})
    # Remail 的 service token 只存在进程内上下文中。注册成功后把订单上下文
    # 一并保存到账号 extra_json，服务重启时查活即可恢复，不再依赖“同一进程
    # 中先领取邮箱”。普通账号列表不会返回 extra_json。
    if str(email_source or "").strip().lower() == "remail":
        try:
            from core.remail_client import get_account_context_metadata

            remail_metadata = get_account_context_metadata(email)
            if remail_metadata:
                existing_service = extra.get("email_service")
                merged_service = dict(existing_service) if isinstance(existing_service, dict) else {}
                merged_service.update(remail_metadata)
                extra["email_service"] = merged_service
        except Exception as exc:
            # 订单上下文保存失败不应让已经完成的注册失败；后续查活仍会
            # 尝试用 API Key 按邮箱搜索 Remail 订单恢复凭证。
            logger.warning(
                "[Save] 保存 Remail 订单上下文失败，后续将尝试按邮箱恢复：%s: %s",
                type(exc).__name__,
                str(exc)[:180],
            )
    user = extra.get("user") or {}
    account = extra.get("account") or {}
    # 从 extra.codex 抽出顶层 codex 状态/错误，方便 WebUI 直接读账号字段
    codex = extra.get("codex") or {}
    codex_status = codex.get("status")  # success / failed / skipped
    codex_error = None
    if codex_status == "failed":
        codex_error = codex.get("message")

    row_id = insert_account(
        email=email,
        access_token=access_token,
        totp_secret=totp_secret,
        user_id=user.get("id"),
        user_name=user.get("name"),
        plan_type=account.get("planType"),
        expires_at=extra.get("expires"),
        proxy_used=proxy_used,
        email_source=email_source,
        extra=extra,
        codex_status=codex_status,
        codex_error=codex_error,
    )
    batch_folder = _append_batch_archive(
        row_id=row_id,
        email=email,
        access_token=access_token,
        totp_secret=totp_secret,
        email_source=email_source,
        proxy_used=proxy_used,
        extra=extra,
        batch_dir=batch_dir,
    )
    logger.info("[Save] 账号及凭证已保存到 SQLite, id=%s, email=%s", row_id, email)

    auto_twofa = False
    try:
        from config import twofa as _twofa_cfg

        auto_twofa = bool(getattr(_twofa_cfg, "ENABLE_2FA", False))
    except Exception:
        auto_twofa = False
    if auto_twofa and not str(totp_secret or "").strip():
        try:
            from core.twofa_service import enqueue_account_totp_setup

            queued = enqueue_account_totp_setup(
                account_id=row_id,
                email=email,
                access_token=access_token,
                trigger="registration_auto",
                proxy=proxy_used,
            )
            if queued.get("accepted"):
                logger.info(f"[2FA] 注册后自动开启 2FA 已入队: id={row_id}, email={email}")
            elif queued.get("busy"):
                logger.info(f"[2FA] 账号已有 2FA 任务，注册流程不重复入队: id={row_id}, email={email}")
            else:
                logger.warning(f"[2FA] 注册后自动开启 2FA 入队失败（不影响注册结果）: {email}, {queued.get('error')}")
        except Exception as exc:
            logger.warning(
                f"[2FA] 注册后自动开启 2FA 入队异常（不影响注册结果）: "
                f"{email}, {type(exc).__name__}: {str(exc)[:180]}"
            )

    if auto_plan_check is None:
        try:
            from config import register as _register_cfg

            auto_plan_check = bool(getattr(_register_cfg, "AUTO_PLAN_CHECK_AFTER_REGISTER", False))
        except Exception:
            auto_plan_check = False
    if not auto_plan_check:
        logger.info(f"[Plan] 注册后自动套餐查询已跳过: id={row_id}, email={email}")
        return row_id
    # session 中的 account.planType 不能说明 Plus 试用资格。账号落库后只负责
    # 入队，由专用线程池异步查询并回写，避免占用注册工作线程。
    try:
        from core.plan_check_service import enqueue_account_plan_check

        queued = enqueue_account_plan_check(
            account_id=row_id,
            email=email,
            access_token=access_token,
            trigger="registration_auto",
            proxy=plan_check_proxy,
        )
        if queued.get("accepted"):
            logger.info(f"[Plan] 注册后自动查询已入队: id={row_id}, email={email}")
        elif queued.get("busy"):
            logger.info(f"[Plan] 账号已有套餐查询，注册流程不重复入队: id={row_id}, email={email}")
        else:
            logger.warning(f"[Plan] 注册后自动查询入队失败（不影响注册结果）: {email}, {queued.get('error')}")
    except Exception as exc:
        logger.warning(
            f"[Plan] 注册后自动查询入队异常（不影响注册结果）: "
            f"{email}, {type(exc).__name__}: {str(exc)[:180]}"
        )
    return row_id
