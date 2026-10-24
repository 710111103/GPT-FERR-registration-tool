# -*- coding: utf-8 -*-
"""已注册账号查活：优先复用已有 AT 预热后走 reauth OTP，成功刷新 AT 即视为正常。"""
import logging
import json
import threading
import time
import uuid
import pyotp
from datetime import datetime
from contextvars import ContextVar
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
import re

from core import db
from core.session import BrowserSession
from core.proxy_utils import mask_proxy_url
from core.codex_oauth import _account_registration_password, _account_totp_secret, _account_totp_code
from core.humanize import delay as human_delay
from core.chatgpt_auth import get_csrf_token, get_providers, signin_openai
from core.openai_auth import (
    follow_authorize,
    send_email_otp,
    validate_email_otp,
    EmailOtpInvalidError,
    AccountUnusableError,
    AuthChallengeRequiredError,
    detect_account_unusable_response_body,
)
from core.account_export import (
    _follow_reauth_with_retry,
    _trigger_reauth_with_retry,
    _validate_reauth_otp,
    _snapshot_existing_reauth_otps,
    _start_reauth_email_verification,
    fetch_session,
    follow_oauth_callback,
)
from core.email_provider import wait_for_otp

logger = logging.getLogger(__name__)
_LOG_DIR = Path(__file__).resolve().parent.parent / "注册日志"
_RUNNING: set[str] = set()
_RUNNING_LOCK = threading.Lock()

_LIVE_STAGE: ContextVar[str] = ContextVar("live_check_stage", default="-")
_PROTOCOL_TRACE: ContextVar[object] = ContextVar("protocol_login_trace", default=None)


@contextmanager
def protocol_login_trace(callback):
    """Record only stage/status evidence for this invocation, never auth material."""
    token = _PROTOCOL_TRACE.set(callback)
    try:
        yield
    finally:
        _PROTOCOL_TRACE.reset(token)


def _trace_protocol(event: str, **fields) -> None:
    callback = _PROTOCOL_TRACE.get()
    if callback is not None:
        callback(event, fields)


def _live_stage(code: str, label: str) -> None:
    """Log a checkpoint without exposing credentials or request parameters."""
    _LIVE_STAGE.set(code)
    _trace_protocol("stage", code=code)
    logger.info("[查活进度] %s", label)

# 查活网络预检失败（403/429/代理/超时等）多为出口 IP 被 CF 标记或代理池抖动，
# 视为可换新 IP 重试；账号本身问题（废号/邮箱错误等）不重试。
_RETRYABLE_NETWORK_HINTS = (
    "403", "429", "502", "503", "504",
    "proxy", "socks", "timeout", "timed out",
    "connection", "closed", "reset",
    "未拿到 accesstoken", "登录态可能未建立",
)

_SESSION_FINGERPRINT_KEYS = {
    "device_id",
    "sentinel_sid",
    "oai_session_id",
    "auth_session_logging_id",
    "datadog_trace_id",
    "datadog_parent_id",
    "react_listening_key",
    "react_container_key",
    "react_resources_key",
}


class TotpVerificationRejectedError(RuntimeError):
    """服务端明确拒绝当前 TOTP 验证码。"""


def _is_retryable_network_error(exc: BaseException) -> bool:
    if isinstance(exc, AccountUnusableError):
        return False
    text = str(exc or "").lower()
    return any(h in text for h in _RETRYABLE_NETWORK_HINTS)


def _new_fingerprint_pinned_session(
    email: str,
    proxy: str | None,
    fingerprint_state: dict | None = None,
) -> BrowserSession:
    """创建任务独占账号会话；同一路由尝试内固定完整身份与浏览器画像。"""
    state = fingerprint_state if fingerprint_state is not None else {}
    saved_profile = state.get("browser_profile")
    identity = str(email).strip().lower()
    # 每个查活任务生成一次独立 seed；同一任务内所有阶段/重试复用，下一任务及
    # 其他账号均不会继承该组 device/session/sentinel 标识。
    fingerprint_seed = str(state.get("fingerprint_seed") or "").strip()
    if not fingerprint_seed:
        fingerprint_seed = f"live-check:{identity}:{uuid.uuid4()}"
        state["fingerprint_seed"] = fingerprint_seed
    session = BrowserSession(
        proxy=proxy,
        # 首次按当前出口生成地区画像；同一路由内部如需重建则原样复用。
        detect_exit_geo=not bool(saved_profile),
        browser_profile=dict(saved_profile) if isinstance(saved_profile, dict) else None,
        fingerprint_seed=fingerprint_seed,
        device_id=state.get("device_id"),
        auth_session_logging_id=state.get("auth_session_logging_id"),
        oai_session_id=state.get("oai_session_id"),
        sentinel_sid=state.get("sentinel_sid"),
    )
    for key in (
        "device_id", "auth_session_logging_id", "oai_session_id", "sentinel_sid",
    ):
        state.setdefault(key, str(getattr(session, key, "") or ""))
    if not saved_profile:
        generated_profile = getattr(session, "browser_profile", None)
        if isinstance(generated_profile, dict):
            state["browser_profile"] = dict(generated_profile)
    return session


def _warm_login_fingerprint_context(session: BrowserSession) -> None:
    """按真实 Web 顺序建立首页 Cookie、匿名 bootstrap 和 NextAuth 上下文。"""
    from core.chatgpt_bootstrap import anonymous_bootstrap

    logger.info("[查活] 登录前指纹预热：document → anonymous bootstrap → providers")
    try:
        nav = session.get(
            "https://chatgpt.com/",
            headers=session.get_chatgpt_navigate_headers(
                referer="https://chatgpt.com/", user_initiated=False,
            ),
            allow_redirects=True,
        )
        nav.raise_for_status()
    except Exception as exc:
        logger.info("[查活] 首页预热遇到 403/网络波动，保留 CF Cookie 继续：%s", str(exc)[:180])
    finally:
        _clear_optional_bootstrap_circuit(session)

    anonymous_bootstrap(session, strict=False)
    # best-effort bootstrap 中某个非关键接口可能 403 并触发本地熔断；在进入
    # NextAuth 正式链路前清理，但首页 document 的错误已经在上面硬失败。
    _clear_optional_bootstrap_circuit(session)
    try:
        get_providers(session)
    except Exception as exc:
        logger.info("[查活] providers 预热未通过，继续 CSRF 正式链路：%s", str(exc)[:180])
    finally:
        _clear_optional_bootstrap_circuit(session)


def _network_preflight_with_retry(
    email: str,
    proxy: str | None,
    max_attempts: int = 2,
    fingerprint_state: dict | None = None,
) -> tuple[BrowserSession, str]:
    """CSRF → Signin 备用预检；403 结束当前身份，其它网络错误短重试。

    `/api/auth/providers` 只是 NextAuth 的发现接口，signin 端点并不依赖它返回的
    内容。实际运行中该接口很容易先被 Cloudflare 拦截，如果把它作为硬门槛，后续
    本来可用的 CSRF/授权链永远不会执行。因此查活备用链不再把 providers 当作
    必经步骤。

    这里必须原样传递 ``proxy``：``None`` 表示按配置选代理，空字符串表示明确
    直连。之前用 ``proxy if proxy else None`` 把直连兜底误变成了再次抽取代理。
    """
    session: BrowserSession | None = None
    last_exc: BaseException | None = None
    state = fingerprint_state if fingerprint_state is not None else {}
    # 一次网络预检只创建一个 BrowserSession。403 响应下发的新 __cf_bm、
    # OAuth/设备上下文都保留在同一 Cookie Jar 中供下一轮使用。
    session = _new_fingerprint_pinned_session(email, proxy, state)
    for attempt in range(1, max_attempts + 1):
        logger.info(
            "[查活] 复用统一会话：proxy=%s device_id=%s oai_session_id=%s（网络预检第 %s/%s 次）",
            session.proxy or "配置随机/直连", session.device_id,
            str(getattr(session, "oai_session_id", "") or "")[:12] + "...",
            attempt, max_attempts,
        )
        logger.info("[查活] 指纹摘要：%s", session.fingerprint_summary_text())
        try:
            _warm_login_fingerprint_context(session)
            csrf = get_csrf_token(session)
            authorize_url = signin_openai(session, csrf, email)
            return session, authorize_url
        except Exception as exc:
            last_exc = exc
            response = getattr(exc, "response", None)
            challenge = bool(response and any(
                str(k).lower() == "cf-mitigated" and str(v).lower() == "challenge"
                for k, v in (getattr(response, "headers", {}) or {}).items()
            ))
            if challenge:
                try:
                    session.session.close()
                except Exception:
                    pass
                raise AuthChallengeRequiredError(response) from exc
            status = _exception_status_code(exc)
            is_403 = status == 403 or "http error 403" in str(exc).lower()
            if is_403 or attempt >= max_attempts or not _is_retryable_network_error(exc):
                try:
                    session.session.close()
                except Exception:
                    pass
                raise
            _clear_optional_bootstrap_circuit(session)
            logger.warning(
                "[查活] 网络预检遇到短暂网络错误（%s/%s），保留当前 session/deviceId 重试：%s",
                attempt, max_attempts, str(exc)[:200],
            )
            time.sleep(2)
    raise RuntimeError(f"网络预检多次失败：{last_exc}")


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _safe_fingerprint_for_account(session: BrowserSession) -> dict:
    """账号里只记录运行环境画像，不保存会话/设备标识。"""
    fp = session.fingerprint_summary()
    return {k: v for k, v in fp.items() if k not in _SESSION_FINGERPRINT_KEYS}


def _safe_fingerprint_text_for_account(session: BrowserSession) -> str:
    fp = _safe_fingerprint_for_account(session)
    parts = [
        f"proxy={BrowserSession._short_value(fp.get('proxy') or 'direct', 36)}",
        f"ua={BrowserSession._short_value(fp.get('user_agent'), 72)}",
        f"lang={fp.get('accept_language')}",
        f"tz={fp.get('timezone_iana')}({fp.get('timezone_offset_minutes')})",
        f"screen={fp.get('screen_width')}x{fp.get('screen_height')}@{fp.get('device_pixel_ratio')}",
        f"cpu={fp.get('hardware_concurrency')}",
        f"mem={fp.get('device_memory')}",
        f"geo={fp.get('geo_country') or '?'}:{fp.get('geo_city') or '?'}",
    ]
    return " ".join(parts)


def probe_access_token_liveness(session: BrowserSession, token: str) -> dict:
    """
    向 ChatGPT 鉴权接口（/backend-api/wham/usage）探测当前 AT 状态。
    借鉴 https://at.kasou.lol/ 规则：
    - 200: Token 正常有效 (返回 valid=True, token_expired=False)
    - 401 且包含 token_expired: Token 明确已失效/过期 (返回 valid=False, token_expired=True)
    - 401 其它未授权: Token 失效 (返回 valid=False, token_expired=True)
    - 其他状态 (403/429 等): 网络阻断或限流，无法确定 Token 自身有效性 (返回 valid=None, token_expired=None)
    """
    token_str = str(token or "").strip()
    if not token_str:
        return {"valid": False, "token_expired": True, "error": "Token 为空"}

    session_get = getattr(session, "get", None)
    if not callable(session_get):
        return {"valid": None, "token_expired": None, "error": "session 没有 get 方法"}

    get_headers_fn = getattr(session, "get_chatgpt_headers", None)
    if callable(get_headers_fn):
        try:
            headers = dict(get_headers_fn(referer="https://chatgpt.com/"))
        except Exception:
            headers = {}
    else:
        headers = dict(getattr(session, "headers", {}) or {})
    headers["authorization"] = token_str if token_str.lower().startswith("bearer ") else f"Bearer {token_str}"

    url = "https://chatgpt.com/backend-api/wham/usage"

    try:
        resp = session.get(url, headers=headers, timeout=12)
        status = int(getattr(resp, "status_code", 0) or 0)
        resp_text = str(getattr(resp, "text", "") or "")
        if 200 <= status < 300:
            try:
                data = resp.json()
            except Exception:
                data = {}
            return {
                "valid": True,
                "token_expired": False,
                "status_code": status,
                "user_id": data.get("user_id"),
                "plan_type": data.get("plan_type"),
                "data": data,
                "error": None,
            }
        elif status == 401:
            err_code = "token_expired"
            err_msg = "Token 已失效"
            try:
                err_data = resp.json().get("error", {})
                if isinstance(err_data, dict):
                    err_code = err_data.get("code") or err_code
                    err_msg = err_data.get("message") or err_msg
            except Exception:
                pass
            return {
                "valid": False,
                "token_expired": True,
                "status_code": 401,
                "error": f"{err_code}: {err_msg}",
            }
        else:
            return {
                "valid": None,
                "token_expired": None,
                "status_code": status,
                "error": f"HTTP {status}: {resp_text[:120]}",
            }
    except Exception as exc:
        return {
            "valid": None,
            "token_expired": None,
            "status_code": None,
            "error": str(exc)[:160],
        }


def _extract_continue_url(result: dict | None) -> str:
    if not isinstance(result, dict):
        return ""
    page = result.get("page") or {}
    page = page if isinstance(page, dict) else {}
    return str(
        result.get("continue_url")
        or result.get("external_url")
        or result.get("url")
        or page.get("continue_url")
        or page.get("external_url")
        or page.get("url")
        or ""
    ).strip()


def _extract_factor_id(result: dict | None, continue_url: str) -> str:
    if isinstance(result, dict):
        page = result.get("page") or {}
        page = page if isinstance(page, dict) else {}
        payload = page.get("payload") or {}
        if isinstance(payload, dict):
            factor_id = str(payload.get("factor_id") or "").strip()
            if factor_id:
                return factor_id
        if isinstance(page.get("payload"), dict):
            factor_id = str(page["payload"].get("factor_id") or "").strip()
            if factor_id:
                return factor_id
    if "/mfa-challenge/" in continue_url:
        return continue_url.rstrip("/").rsplit("/", 1)[-1]
    return ""


def _password_verify(session: BrowserSession, password: str) -> dict:
    from core.openai_auth import build_sentinel_header, request_sentinel_token

    sentinel_resp = request_sentinel_token(session, "password_verify")
    sentinel_header, so_header = build_sentinel_header(session, sentinel_resp, "password_verify")
    headers = session.get_auth_headers(referer="https://auth.openai.com/log-in/password")
    headers["openai-sentinel-token"] = sentinel_header
    if so_header:
        headers["openai-sentinel-so-token"] = so_header
    resp = session.post(
        "https://auth.openai.com/api/accounts/password/verify",
        headers=headers,
        data=json.dumps({"password": password}),
        allow_redirects=False,
    )
    _trace_protocol("password_verify_response", http_status=int(resp.status_code))
    if resp.status_code == 401:
        body = ""
        try:
            body = resp.text
        except Exception:
            pass
        logger.warning(
            "[查活] 密码验证失败(HTTP 401: 密码错误)，本地记录的密码与 OpenAI 端不匹配！body=%s",
            body[:200],
        )
        raise RuntimeError(f"密码错误(HTTP 401: Incorrect email address or password): {body[:200]}")
    resp.raise_for_status()
    return resp.json()


def _check_mfa_account_unusable(session: BrowserSession, response, factor_id: str) -> None:
    """Distinguish an explicit deactivation page from a generic MFA HTTP 403."""
    code = _confirmed_dead_code(str(getattr(response, "text", "") or ""))
    if not code and int(getattr(response, "status_code", 0) or 0) == 403:
        # The browser renders the diagnostic on the MFA document, not always on
        # the POST response. Only fetch it after the POST was already denied.
        try:
            page = session.get(
                f"https://auth.openai.com/mfa-challenge/{factor_id}",
                headers=session.get_auth_navigate_headers(
                    referer="https://auth.openai.com/log-in/password"
                ),
                allow_redirects=True,
            )
            code = _confirmed_dead_code(str(getattr(page, "text", "") or ""))
        except Exception as exc:
            logger.debug("[查活] MFA 页面诊断不可用: %s", type(exc).__name__)
    if code:
        raise AccountUnusableError("MFA 页面确认账号已删除或停用", error_code=code)


def _mfa_issue_challenge(session: BrowserSession, factor_id: str) -> dict:
    headers = session.get_auth_headers(referer="https://auth.openai.com/mfa-challenge")
    headers.pop("openai-sentinel-token", None)
    headers.pop("openai-sentinel-so-token", None)
    resp = session.post(
        "https://auth.openai.com/api/accounts/mfa/issue_challenge",
        headers=headers,
        data=json.dumps({"id": factor_id, "type": "totp", "force_fresh_challenge": False}),
        allow_redirects=False,
    )
    _check_mfa_account_unusable(session, resp, factor_id)
    resp.raise_for_status()
    return resp.json()


def _mfa_verify(session: BrowserSession, factor_id: str, code: str) -> dict:
    headers = session.get_auth_headers(referer="https://auth.openai.com/mfa-challenge")
    headers.pop("openai-sentinel-token", None)
    headers.pop("openai-sentinel-so-token", None)
    resp = session.post(
        "https://auth.openai.com/api/accounts/mfa/verify",
        headers=headers,
        data=json.dumps({"id": factor_id, "type": "totp", "code": code}),
        allow_redirects=False,
    )
    if int(getattr(resp, "status_code", 0) or 0) != 200:
        body = str(getattr(resp, "text", "") or "")
        lowered = body.lower()
        rejected_hints = (
            "invalid_totp", "invalid totp", "invalid otp", "incorrect otp",
            "incorrect code", "wrong code", "code is invalid", "totp code",
        )
        if int(getattr(resp, "status_code", 0) or 0) in (400, 401) and any(
            hint in lowered for hint in rejected_hints
        ):
            raise TotpVerificationRejectedError(
                f"TOTP_REJECTED status={resp.status_code} body={body[:300]}"
            )
        _check_mfa_account_unusable(session, resp, factor_id)
        resp.raise_for_status()
    return resp.json()


def _follow_continue_and_fetch(
    session: BrowserSession,
    continue_url: str,
    *,
    referer: str,
    max_attempts: int = 6,
) -> dict:
    """完成 OAuth 回调，并等待 NextAuth session cookie 可见。"""
    _live_stage("oauth_callback", "OAuth 回调中")
    follow_oauth_callback(session, continue_url, referer=referer)
    _live_stage("fetch_session", "读取新会话 AT 中")
    last_exc: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            return fetch_session(session)
        except RuntimeError as exc:
            # OAuth 回调设置 Cookie 后，session 端点偶尔会短暂返回空对象。
            # 仅重试这个明确状态；HTTP、JSON 等错误继续原样抛出。
            if "未拿到 accessToken" not in str(exc):
                raise
            last_exc = exc
            if attempt >= max_attempts:
                break
            logger.info(
                "[查活] OAuth 回调已完成，等待 session/accessToken 生效（%s/%s）",
                attempt,
                max_attempts,
            )
            time.sleep(min(attempt, 3))
    raise last_exc if last_exc else RuntimeError("OAuth 回调后未获取到 accessToken")


def _try_saved_web_session_refresh(session: BrowserSession, email: str) -> dict | None:
    """Renew AT from a previously authenticated web session, without password login.

    A blocked/expired cookie is inconclusive. Only a matching user and a
    separately verified AT can be returned to the caller.
    """
    try:
        account = db.get_account_by_email(email) or {}
        extra = account.get("extra_json") or {}
        if isinstance(extra, str):
            extra = json.loads(extra) if extra else {}
        cookie_value = str((extra if isinstance(extra, dict) else {}).get("session_token") or "")
        if not cookie_value:
            return None
        jar = session.session.cookies
        base = "__Secure-next-auth.session-token"
        # NextAuth splits long session cookies into numbered 3 KB chunks.
        chunks = [cookie_value[i:i + 3000] for i in range(0, len(cookie_value), 3000)]
        for index, chunk in enumerate(chunks):
            name = base if len(chunks) == 1 else f"{base}.{index}"
            jar.set(name, chunk, domain="chatgpt.com", path="/")
        try:
            info = fetch_session(session)
            token = str(info.get("accessToken") or "")
            user = info.get("user") or {}
            if not token or str(user.get("email") or "").casefold() != email.casefold():
                logger.info("[查活] 已保存的网页登录态身份未匹配，不采用其 AT")
                return None
            probe = probe_access_token_liveness(session, token)
            if probe.get("valid") is not True or int(probe.get("status_code") or 0) != 200:
                logger.info("[查活] 会话更新取得 AT，但独立鉴权未通过")
                return None
            expected_id = str(account.get("user_id") or user.get("id") or "")
            actual_id = str(probe.get("user_id") or "")
            if expected_id and actual_id and expected_id != actual_id:
                logger.info("[查活] 会话更新 AT 账号 ID 不匹配")
                return None
            logger.info("[查活] 已通过已保存网页登录态刷新 AT 并独立校验")
            return info
        finally:
            # Do not let a stale cookie pollute a subsequent full OAuth login.
            for name in (base, *(f"{base}.{i}" for i in range(len(chunks)))):
                try:
                    jar.clear(domain="chatgpt.com", path="/", name=name)
                except (KeyError, ValueError):
                    pass
    except Exception as exc:
        # Frame locations only: do not dump exception text, locals or cookies.
        import traceback
        frames = traceback.extract_tb(exc.__traceback__)
        locations = " -> ".join(
            f"{Path(frame.filename).name}:{frame.lineno}:{frame.name}" for frame in frames[-6:]
        )
        logger.info(
            "[查活] 已保存网页登录态刷新未完成 (%s)，异常位置=%s，继续完整登录",
            type(exc).__name__, locations or "unknown",
        )
        return None


def _stored_access_token(email: str) -> str:
    """读取本地账号已有 AT，用于先预热登录态再走稳定的 reauth 链。"""
    try:
        account = db.get_account_by_email(email)
        return str((account or {}).get("access_token") or "").strip()
    except Exception as exc:
        logger.debug("[查活] 读取已有 accessToken 失败，改走备用登录链：%s: %s", type(exc).__name__, exc)
        return ""


def _clear_optional_bootstrap_circuit(session: BrowserSession) -> None:
    """清理可选登录态预热造成的本地熔断，不影响后续正式认证请求。

    authenticated_bootstrap 是 best-effort 预热，其中个别旧接口返回 403 不等于
    reauth 链不可用；BrowserSession 的通用熔断器若保留该状态，会直接拦截后续
    `/api/auth/csrf`，导致稳定的 2FA 链也无法开始。
    """
    reset = getattr(session, "reset_circuit_breaker", None)
    if callable(reset):
        reset()
        return
    if getattr(session, "blocked_until", 0.0):
        session.blocked_until = 0.0
        session.blocked_reason = ""


def _warm_authenticated_session(session: BrowserSession, access_token: str) -> None:
    """复用 2FA 已验证的登录态预热流程。预热失败不直接判定账号死亡。"""
    if not access_token:
        return
    from core.chatgpt_bootstrap import authenticated_bootstrap

    try:
        logger.info("[查活] 使用已有 accessToken 预热登录态...")
        authenticated_bootstrap(session, access_token, strict=False)
        logger.info("[查活] accessToken 预热完成，继续走 reauth OTP")
    except Exception as exc:
        # strict=False 已经会吞掉大部分单接口错误；这里仅兜住初始化异常。
        logger.warning("[查活] accessToken 预热失败，继续走 reauth OTP：%s: %s", type(exc).__name__, str(exc)[:180])
    finally:
        _clear_optional_bootstrap_circuit(session)


def _exception_response_text(exc: BaseException) -> str:
    response = getattr(exc, "response", None)
    return str(getattr(response, "text", "") or "")


_CONFIRMED_DEAD_CODES = frozenset(("account_deactivated", "account_deleted", "account_banned"))


def _confirmed_dead_code(text: str, *, redirect: bool = False) -> str:
    """Require a remote error code; don't search arbitrary prose or URLs."""
    text = str(text or "")
    if redirect:
        values = parse_qs(urlsplit(text).query)
        for field in ("error", "error_code"):
            for code in values.get(field, ()):
                if code in _CONFIRMED_DEAD_CODES:
                    return code
        return ""
    code = detect_account_unusable_response_body(text)
    if code in _CONFIRMED_DEAD_CODES:
        return code
    # Official HTML error screen: `error_code: account_deactivated`.
    match = re.search(r"\berror_code\s*[:=]\s*[\"']?(account_deactivated|account_deleted|account_banned)\b", text, re.I)
    return match.group(1).lower() if match else ""


def _exception_status_code(exc: BaseException) -> int | None:
    response = getattr(exc, "response", None)
    try:
        status = int(getattr(response, "status_code", 0) or 0)
    except (TypeError, ValueError):
        return None
    return status or None


def _validate_reauth_with_retry(
    session: BrowserSession,
    email: str,
    otp_after_ts: float,
    max_otp_attempts: int = 2,
    email_source: str | None = None,
    exclude_codes: set[str] | None = None,
) -> str:
    """提交 reauth OTP；验证码错误时重建 auth state，并排除已拒绝的历史码。"""
    current_otp: str | None = None
    last_exc: Exception | None = None
    excluded = set(exclude_codes or set())
    source = str(email_source or "").strip().lower()
    wait_seconds = 90 if source == "cloudflare_domain" else 20
    for attempt in range(1, max_otp_attempts + 1):
        try:
            if current_otp is None:
                logger.info("[查活] 等待重认证 OTP：%s（第 %s/%s 次，限时 %ss）", email, attempt, max_otp_attempts, wait_seconds)
                if source in {"generic_api", "mailalias"}:
                    from core.generic_api_mail_client import fetch_latest_otp
                    current_otp = fetch_latest_otp(
                        email,
                        after_ts=otp_after_ts,
                        max_wait=wait_seconds,
                        exclude_codes=excluded,
                    )
                else:
                    current_otp = wait_for_otp(
                        email,
                        after_ts=otp_after_ts,
                        max_wait=wait_seconds,
                        email_source=email_source,
                    )
            human_delay("otp_input")
            continue_url = _validate_reauth_otp(session, current_otp)
            if not continue_url:
                raise RuntimeError("重认证 OTP 验证响应缺少 continue_url")
            return str(continue_url)
        except AccountUnusableError:
            raise
        except Exception as exc:
            last_exc = exc
            body = _exception_response_text(exc)
            dead_code = _confirmed_dead_code(body)
            if dead_code:
                raise AccountUnusableError(
                    f"账号已废弃（{dead_code}），邮箱不可再用",
                    error_code=dead_code,
                ) from exc

            # 若为取码超时/收件箱为空，表明接码服务订单已结束，直接跳出避免无意义空等
            if "超时" in str(exc) or "timeout" in str(exc).lower() or "空" in str(exc):
                raise

            status = _exception_status_code(exc)
            retryable_otp = status in (400, 401, 422)
            if attempt >= max_otp_attempts or not retryable_otp:
                raise
            logger.warning(
                "[查活] 重认证 OTP 无效/过期，重新发送后再取（%s/%s）：%s",
                attempt,
                max_otp_attempts,
                str(exc)[:180],
            )
            if current_otp:
                excluded.add(str(current_otp))
            send_email_otp(session)
            otp_after_ts = time.time()
            current_otp = None
            time.sleep(1)
    raise last_exc if last_exc else RuntimeError("重认证 OTP 验证失败")



def _collect_password_candidates(email: str) -> list[str]:
    """收集账号的密码候选列表，优先使用本地记录密码，兜底尝试常见通用密码。"""
    primary = str(_account_registration_password(email) or "").strip()
    if not primary:
        return []
    candidates = [primary]
    seen = {primary}
    for p in ("zj783147568.", "zj783147568"):
        if p not in seen:
            seen.add(p)
            candidates.append(p)
    return candidates

def _login_via_reauth(
    session: BrowserSession,
    email: str,
    otp_after_ts: float,
    email_source: str | None = None,
    totp_secret_override: str | None = None,
) -> dict:
    """按 2FA 已验证链路重新认证并刷新 ChatGPT session。"""
    def current_totp_code(secret: str) -> str:
        return pyotp.TOTP(secret).now() if totp_secret_override else _account_totp_code(email)

    auth_url = _trigger_reauth_with_retry(session, email)
    logger.info("[查活] reauth authorize URL 已获取")
    human_delay("api")
    final_url = _follow_reauth_with_retry(session, auth_url)
    dead_code = _confirmed_dead_code(final_url, redirect=True)
    if dead_code:
        raise AccountUnusableError(f"账号已废弃（{dead_code}）", error_code=dead_code)
    human_delay("navigate")
    if "/mfa-challenge/" in final_url:
        factor_id = final_url.rstrip("/").rsplit("/", 1)[-1]
        secret = str(totp_secret_override or _account_totp_secret(email) or "").strip()
        if not factor_id:
            raise RuntimeError(f"重认证进入 MFA，但未取得 factor_id: {final_url}")
        if not secret:
            raise RuntimeError(f"重认证进入 MFA，但账号没有 totp_secret：{email}")
        logger.info("[查活] Recent Login 进入 MFA challenge，开始提交 TOTP：%s", email)
        _mfa_issue_challenge(session, factor_id)
        code = current_totp_code(secret) if secret else ""
        if not code:
            raise RuntimeError(f"重认证生成 TOTP 失败：{email}")
        mfa_result = _mfa_verify(session, factor_id, code)
        continue_url = _extract_continue_url(mfa_result)
        if not continue_url:
            raise RuntimeError(f"重认证 MFA 验证成功但没有 continue_url: {mfa_result}")
        logger.info("[查活] Recent Login TOTP 验证通过，开始交换新 token")
        return _follow_continue_and_fetch(
            session,
            continue_url,
            referer=f"https://auth.openai.com/mfa-challenge/{factor_id}",
        )

    if "/log-in/password" in final_url or "/password" in final_url:
        candidates = _collect_password_candidates(email)
        if candidates:
            logger.info("[查活] reauth 遇到登录密码页，开始尝试候选密码：%s (共%d个)", email, len(candidates))
            password_result = None
            success_password = None
            for idx, cand_pwd in enumerate(candidates):
                try:
                    logger.info("[查活] reauth 尝试第 %d/%d 个候选密码: %s (len=%d)", idx + 1, len(candidates), email, len(cand_pwd))
                    password_result = _password_verify(session, cand_pwd)
                    success_password = cand_pwd
                    logger.info("[查活] reauth 密码验证成功！匹配密码: %s*** (len=%d)", cand_pwd[:4], len(cand_pwd))
                    break
                except RuntimeError as exc:
                    err_text = str(exc).lower()
                    if "密码错误" not in str(exc) and "incorrect email address or password" not in err_text:
                        raise
                    logger.warning("[查活] reauth 候选密码 %d 验证失败(401): %s***", idx + 1, cand_pwd[:4])

            if password_result:
                if success_password:
                    try:
                        from core import db
                        db.save_registration_password_checkpoint(
                            email,
                            success_password,
                            verified=True,
                            stage="reauth_password_verified",
                            create_missing=False,
                        )
                    except Exception as ck_exc:
                        logger.warning("[查活] reauth 密码落盘异常：%s", ck_exc)

                continue_url = _extract_continue_url(password_result)
                page = password_result.get("page") if isinstance(password_result, dict) else {}
                page = page if isinstance(page, dict) else {}
                page_type = str(page.get("type") or "")
                if "/mfa-challenge/" in continue_url or page_type == "mfa_challenge":
                    factor_id = _extract_factor_id(password_result, continue_url)
                    secret = str(totp_secret_override or _account_totp_secret(email) or "").strip()
                    if not factor_id:
                        raise RuntimeError(f"密码认证后进入 MFA 但未得到 factor_id: {password_result}")
                    if not secret:
                        raise RuntimeError(f"密码认证后进入 MFA，但账号没有 totp_secret：{email}")
                    logger.info("[查活] reauth 进入 MFA challenge，开始提交 TOTP：%s factor_id=%s", email, factor_id)
                    _mfa_issue_challenge(session, factor_id)
                    code = current_totp_code(secret) if secret else ""
                    if not code:
                        raise RuntimeError(f"无法计算 TOTP 验证码：{email}")
                    mfa_result = _mfa_verify(session, factor_id, code)
                    mfa_continue_url = _extract_continue_url(mfa_result) or continue_url
                    if not mfa_continue_url:
                        raise RuntimeError(f"MFA 验证成功但没有 continue_url: {mfa_result}")
                    logger.info("[查活] reauth MFA 验证完成，开始跟踪 OAuth callback")
                    return _follow_continue_and_fetch(
                        session,
                        mfa_continue_url,
                        referer=f"https://auth.openai.com/mfa-challenge/{factor_id}",
                    )
                if continue_url:
                    logger.info("[查活] 密码认证直接给到回调地址，立即完成回调：%s", email)
                    return _follow_continue_and_fetch(session, continue_url, referer="https://auth.openai.com/log-in/password")

    # Following the authorize URL does not consistently dispatch a fresh OTP.
    # Explicitly request one after the auth session reaches email verification,
    # then use the request start as the mailbox freshness boundary.
    # 换绑后的 mailalias/dr 页面无可靠 freshness 过滤；发码前先记录当前历史码。
    excluded_otp_codes = _snapshot_existing_reauth_otps(email, email_source)
    otp_after_ts = time.time()
    try:
        _live_stage("verification", "发送并等待邮箱验证码中")
        send_email_otp(session)
        logger.info("[查活] 已跟随 reauth authorize URL，并显式发送邮箱 OTP")
    except Exception as otp_exc:
        # 部分会话在页面跳转时已下发首封 OTP，再次调 /email-otp/send 可能返回 409 会话失效。
        # 此时不中断重认证，直接继续等待并校验系统初次发放的验证码。
        logger.warning("[查活] 显式重发邮箱 OTP 提示(%s)，继续使用进入页面时发放的验证码", otp_exc)
    continue_url = _validate_reauth_with_retry(
        session,
        email,
        otp_after_ts,
        email_source=email_source,
        exclude_codes=excluded_otp_codes,
    )
    # 若账号开启了 2FA，邮箱验证通过后服务端可能重定向到 /mfa-challenge/{factor_id}
    if "/mfa-challenge/" in continue_url:
        factor_id = continue_url.rstrip("/").rsplit("/", 1)[-1]
        secret = str(totp_secret_override or _account_totp_secret(email) or "").strip()
        if not factor_id:
            raise RuntimeError(f"邮箱验证通过后进入 MFA，但未取得 factor_id: {continue_url}")
        if not secret:
            raise RuntimeError(f"邮箱验证通过后进入 MFA，但账号没有 totp_secret：{email}")
        logger.info("[查活] Recent Login 邮箱验证通过后进入 MFA challenge，开始提交 TOTP：%s", email)
        _mfa_issue_challenge(session, factor_id)
        code = current_totp_code(secret) if secret else ""
        if not code:
            raise RuntimeError(f"重认证生成 TOTP 失败：{email}")
        mfa_result = _mfa_verify(session, factor_id, code)
        continue_url = _extract_continue_url(mfa_result)
        if not continue_url:
            raise RuntimeError(f"重认证 MFA 验证成功但没有 continue_url: {mfa_result}")
        logger.info("[查活] Recent Login TOTP 验证通过，开始交换新 token")
        return _follow_continue_and_fetch(
            session,
            continue_url,
            referer=f"https://auth.openai.com/mfa-challenge/{factor_id}",
        )

    logger.info("[查活] reauth OTP 验证通过，开始交换新 token")
    human_delay("api")
    return _follow_continue_and_fetch(
        session,
        continue_url,
        referer="https://auth.openai.com/email-verification",
    )


def _complete_about_you_and_fetch(
    session: BrowserSession,
    email: str,
    continue_url: str,
) -> dict:
    """补齐注册中断账号的资料页，并继续 OAuth callback 获取新 AT。"""
    from core.name_samples import random_display_name
    from core.openai_auth import (
        build_sentinel_header,
        create_account,
        navigate_about_you,
        request_sentinel_token,
    )
    from core.profile_utils import generate_random_birthday

    about_url = str(continue_url or "https://auth.openai.com/about-you").strip()
    if "about-you" not in about_url:
        about_url = "https://auth.openai.com/about-you"

    name = random_display_name()
    birthday = generate_random_birthday()
    logger.info(
        "[查活][资料补齐] 检测到注册中断账号，开始补齐 about-you：%s name=%s birthday=%s",
        email,
        name,
        birthday,
    )
    navigate_about_you(session, about_url)
    sentinel_resp = request_sentinel_token(session, "oauth_create_account")
    sentinel_header, so_header = build_sentinel_header(
        session,
        sentinel_resp,
        "oauth_create_account",
    )
    create_result = create_account(
        session,
        name,
        birthday,
        sentinel_header,
        so_header,
    )
    callback_url = _extract_continue_url(create_result)
    if not callback_url:
        raise RuntimeError(
            f"about-you 资料补齐成功但响应缺少 OAuth continue_url: {create_result}"
        )
    logger.info("[查活][资料补齐] about-you 已提交，继续 OAuth callback：%s", email)
    return _follow_continue_and_fetch(
        session,
        callback_url,
        referer="https://auth.openai.com/about-you",
    )


def _login_via_email_otp(
    session: BrowserSession,
    email: str,
    otp_after_ts: float,
    email_source: str | None = None,
) -> dict:
    """完成邮箱 OTP 登录，并跟随 OAuth callback 后拉取 ChatGPT session。"""
    validate_result = _validate_with_retry(
        session,
        email,
        otp_after_ts,
        email_source=email_source,
    )
    page = validate_result.get("page") if isinstance(validate_result, dict) else {}
    page = page if isinstance(page, dict) else {}
    page_type = str(page.get("type") or "")
    continue_url = _extract_continue_url(validate_result)
    if not continue_url:
        raise RuntimeError(f"OTP 登录成功但没有 OAuth continue_url: {validate_result}")
    if "about-you" in str(continue_url) or page_type in {"about_you", "about-you"}:
        return _complete_about_you_and_fetch(session, email, continue_url)

    if "/mfa-challenge/" in continue_url or page_type == "mfa_challenge":
        factor_id = _extract_factor_id(validate_result, continue_url)
        secret = _account_totp_secret(email)
        if not factor_id:
            raise RuntimeError(f"邮箱 OTP 验证通过后进入 MFA 但未拿到 factor_id: {validate_result}")
        if not secret:
            raise RuntimeError(f"邮箱 OTP 验证通过后进入 MFA，但账号没有 totp_secret：{email}")
        logger.info("[查活] 邮箱 OTP 验证通过后进入 MFA challenge，开始提交 TOTP：%s factor_id=%s", email, factor_id)
        _mfa_issue_challenge(session, factor_id)
        code = _account_totp_code(email)
        if not code:
            raise RuntimeError(f"无法生成 TOTP 验证码：{email}")
        mfa_result = _mfa_verify(session, factor_id, code)
        mfa_continue_url = _extract_continue_url(mfa_result) or continue_url
        if not mfa_continue_url:
            raise RuntimeError(f"MFA 验证成功但没有 continue_url: {mfa_result}")
        logger.info("[查活] MFA 验证完成，开始跟随 OAuth callback")
        return _follow_continue_and_fetch(
            session,
            mfa_continue_url,
            referer=f"https://auth.openai.com/mfa-challenge/{factor_id}",
        )

    logger.info("[查活] 邮箱 OTP 验证完成，开始跟随 OAuth callback")
    return _follow_continue_and_fetch(session, continue_url, referer="https://auth.openai.com/email-verification")


def _login_via_password_or_otp(
    session: BrowserSession,
    email: str,
    otp_after_ts: float,
    email_source: str | None = None,
    landing_url: str = "",
    allow_password: bool = True,
    password_override: str | None = None,
    force_password_login: bool = False,
    accept_password_step_only: bool = False,
) -> dict:
    """按实际登录落点选择首因子，随后完成可能出现的 MFA。"""
    if "/email-verification" in str(landing_url).lower():
        logger.info("[查活] 当前落在邮箱验证码页，先完成邮箱 OTP：%s", email)
        _live_stage("verification", "发送并等待邮箱验证码中")
        send_email_otp(session)
        return _login_via_email_otp(
            session,
            email,
            time.time(),
            email_source=email_source,
        )

    if password_override is not None:
        override = str(password_override or "").strip()
        candidates = [override] if override else []
    else:
        candidates = _collect_password_candidates(email) if allow_password else []
    if not candidates:
        if force_password_login:
            raise RuntimeError("强制密码查活失败：没有可用的新密码")
        logger.info(
            "[查活] 未找到可直接使用的登录密码，回退至邮箱 OTP 登录流程：%s landing=%s",
            email,
            landing_url or "-",
        )
        _live_stage("verification", "发送并等待邮箱验证码中")
        send_email_otp(session)
        return _login_via_email_otp(
            session,
            email,
            time.time(),
            email_source=email_source,
        )

    logger.info("[查活] 账号带有密码或候选密码 (%d个)，优先尝试密码登录：%s", len(candidates), email)
    password_result = None
    success_password = None
    for idx, cand_pwd in enumerate(candidates):
        try:
            logger.info("[查活] 尝试第 %d/%d 个候选密码", idx + 1, len(candidates))
            password_result = _password_verify(session, cand_pwd)
            success_password = cand_pwd
            logger.info("[查活] 密码接口已接受候选密码")
            break
        except RuntimeError as exc:
            error_text = str(exc).lower()
            if "密码错误" not in str(exc) and "incorrect email address or password" not in error_text:
                raise
            logger.warning("[查活] 候选密码 %d 验证失败(401)", idx + 1)

    if not password_result:
        if force_password_login:
            raise RuntimeError("密码错误：强制密码查活未通过")
        logger.warning("[查活] 全部候选密码均验证失败，切换至邮箱 OTP 登录：%s", email)
        _live_stage("verification", "发送并等待邮箱验证码中")
        send_email_otp(session)
        return _login_via_email_otp(
            session,
            email,
            time.time(),
            email_source=email_source,
        )

    if success_password and not force_password_login:
        try:
            from core import db
            db.save_registration_password_checkpoint(
                email,
                success_password,
                verified=True,
                stage="liveness_login_verified",
                create_missing=False,
            )
        except Exception as ck_exc:
            logger.warning("[查活] 密码验证成功但落盘 checkpoint 异常：%s", ck_exc)

    def _mark_password_auth(result: dict) -> dict:
        result = dict(result or {})
        result["password_accepted"] = True
        result["authentication_method"] = "password"
        return result

    continue_url = _extract_continue_url(password_result)
    page = password_result.get("page") if isinstance(password_result, dict) else {}
    page = page if isinstance(page, dict) else {}
    page_type = str(page.get("type") or "")

    if "about-you" in str(continue_url) or page_type in {"about_you", "about-you"}:
        return _mark_password_auth(_complete_about_you_and_fetch(session, email, continue_url))

    if "/mfa-challenge/" in continue_url or page_type == "mfa_challenge":
        if accept_password_step_only:
            logger.info("[查活] 候选密码已被接口接受并进入 MFA 页面，凭据阶段验收通过：%s", email)
            return {
                "credential_verified": True,
                "password_accepted": True,
                "authentication_method": "password",
                "verification_stage": "mfa_challenge",
                "user": {"email": email},
            }
        factor_id = _extract_factor_id(password_result, continue_url)
        secret = _account_totp_secret(email)
        if not factor_id:
            raise RuntimeError(f"密码登录后进入 MFA 但未拿到 factor_id: {password_result}")
        if not secret:
            raise RuntimeError(f"密码登录后进入 MFA，但账号没有 totp_secret：{email}")
        logger.info("[查活] 已进入 MFA challenge，开始提交 TOTP：%s factor_id=%s", email, factor_id)
        _mfa_issue_challenge(session, factor_id)
        code = _account_totp_code(email)
        if not code:
            raise RuntimeError(f"无法生成 TOTP 验证码：{email}")
        mfa_result = _mfa_verify(session, factor_id, code)
        mfa_continue_url = _extract_continue_url(mfa_result) or continue_url
        if not mfa_continue_url:
            raise RuntimeError(f"MFA 验证成功但没有 continue_url: {mfa_result}")
        return _mark_password_auth(_follow_continue_and_fetch(
            session,
            mfa_continue_url,
            referer=f"https://auth.openai.com/mfa-challenge/{factor_id}",
        ))

    if "email-verification" in continue_url or page_type in {"email_verification", "email_otp_send"}:
        if accept_password_step_only:
            logger.info("[查活] 候选密码已被接口接受并进入邮箱验证页面，凭据阶段验收通过：%s", email)
            return {
                "credential_verified": True,
                "password_accepted": True,
                "authentication_method": "password",
                "verification_stage": "email_verification",
                "user": {"email": email},
            }
        logger.info("[查活] 密码登录后仍进入邮箱 OTP，继续完成邮箱验证：%s", email)
        return _mark_password_auth(_login_via_email_otp(
            session,
            email,
            otp_after_ts,
            email_source=email_source,
        ))

    if continue_url:
        logger.info("[查活] 密码登录直接给出回调地址，继续完成回调：%s", email)
        return _mark_password_auth(_follow_continue_and_fetch(session, continue_url, referer="https://auth.openai.com/log-in/password"))

    raise RuntimeError(f"密码登录成功但没有可用 continue_url: {password_result}")


def log_path(email: str) -> Path:
    safe = str(email or "").replace("/", "_").replace("\\", "_").replace(":", "_")
    return _LOG_DIR / f"live-check-{safe}.log"


def is_checking(email: str) -> bool:
    key = str(email or "").strip().lower()
    with _RUNNING_LOCK:
        return key in _RUNNING


def _validate_with_retry(
    session: BrowserSession,
    email: str,
    otp_after_ts: float,
    max_otp_attempts: int = 2,
    email_source: str | None = None,
) -> dict:
    current_otp = None
    last_exc: Exception | None = None
    excluded: set[str] = set()
    source = str(email_source or "").strip().lower()
    wait_seconds = 90 if source == "cloudflare_domain" else 35
    for attempt in range(1, max_otp_attempts + 1):
        try:
            if current_otp is None:
                logger.info("[查活] 等待登录 OTP：%s（第 %s/%s 次，限时 %ss）", email, attempt, max_otp_attempts, wait_seconds)
                if source in {"generic_api", "mailalias"}:
                    from core.generic_api_mail_client import fetch_latest_otp
                    current_otp = fetch_latest_otp(
                        email,
                        after_ts=otp_after_ts,
                        max_wait=wait_seconds,
                        exclude_codes=excluded,
                    )
                else:
                    current_otp = wait_for_otp(
                        email,
                        after_ts=otp_after_ts,
                        max_wait=wait_seconds,
                        email_source=email_source,
                    )
            result = validate_email_otp(session, current_otp, sentinel_header=None, so_header=None)
            return result
        except EmailOtpInvalidError as exc:
            last_exc = exc
            if attempt >= max_otp_attempts:
                break
            logger.warning("[查活] OTP 无效/过期，重新发送后再取：%s", str(exc)[:180])
            if current_otp:
                excluded.add(str(current_otp))
            send_email_otp(session)
            # 以“重新发送请求完成后”为新基准，避免刚刚失败的上一封旧码再次被 after 容忍窗口命中。
            otp_after_ts = time.time()
            current_otp = None
            time.sleep(1)
        except Exception as exc:
            if "超时" in str(exc) or "timeout" in str(exc).lower() or "空" in str(exc):
                raise
            # 提交 OTP 后的网络抖动（连接断开/超时/代理波动）：同一会话重发验证码再验证一次。
            if attempt >= max_otp_attempts or not _is_retryable_network_error(exc):
                raise
            last_exc = exc
            logger.warning("[查活] OTP 验证网络抖动，重新发送后再取（%s/%s）：%s", attempt, max_otp_attempts, str(exc)[:180])
            try:
                send_email_otp(session)
            except Exception:
                raise
            otp_after_ts = time.time()
            current_otp = None
            time.sleep(1)
    raise last_exc if last_exc else RuntimeError("OTP 验证失败")


def check_account_liveness(
    email: str,
    proxy: str | None = None,
    *,
    clear_log: bool = True,
    email_source: str | None = None,
    fingerprint_state: dict | None = None,
    password_override: str | None = None,
    force_password_login: bool = False,
    skip_existing_token_probe: bool = False,
    accept_password_step_only: bool = False,
) -> dict:
    """
    重新登录账号并刷新最新 accessToken。

    返回：
      {
        ok: bool,
        status: live/deactivated/failed,
        access_token: str?,
        session: dict?,
        checked_at: ISO,
        error: str?
      }
    """
    email = str(email or "").strip()
    if not email:
        raise ValueError("email 不能为空")

    checked_at = _now()
    key = email.lower()
    path = log_path(email)
    path.parent.mkdir(parents=True, exist_ok=True)
    if clear_log:
        path.write_text("", encoding="utf-8")

    fh: logging.FileHandler | None = None
    session: BrowserSession | None = None
    stage_token = _LIVE_STAGE.set("initializing")
    root_logger = logging.getLogger()
    thread_name = threading.current_thread().name
    with _RUNNING_LOCK:
        _RUNNING.add(key)
    try:
        fh = logging.FileHandler(str(path), encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%H:%M:%S",
        ))
        fh.addFilter(lambda record: record.threadName == thread_name)
        root_logger.addHandler(fh)
        logger.addHandler(fh)
        logger.setLevel(logging.DEBUG)

        logger.info("[查活] 日志文件：%s", path)
        logger.info("[查活] 开始重新登录/查活：%s", email)
        existing_access_token = _stored_access_token(email)
        has_totp = bool(_account_totp_secret(email))
        session = _new_fingerprint_pinned_session(email, proxy, fingerprint_state)
        logger.info(
            "[查活] 会话创建完成：proxy=%s device_id=%s",
            mask_proxy_url(session.proxy) if session.proxy else "直连/配置随机",
            session.device_id,
        )
        logger.info("[查活] 指纹摘要：%s", session.fingerprint_summary_text())

        # 阶段 1：优先使用当前已有 AT 进行鉴权探测（借鉴 https://at.kasou.lol/ wham/usage 探测机制）
        probe_result: dict | None = None
        if existing_access_token and not skip_existing_token_probe:
            _live_stage("at_probe", "探测旧 AT 中")
            logger.info("[查活] 步骤1：探测当前已有 AT 鉴权状态 (/backend-api/wham/usage)...")
            probe_result = probe_access_token_liveness(session, existing_access_token)
            if probe_result.get("valid") is True:
                user_id = probe_result.get("user_id")
                plan_type = probe_result.get("plan_type") or "free"
                logger.info(
                    "[查活] 当前已有 AT 经探测确认正常有效 (HTTP 200, user_id=%s, plan=%s)",
                    user_id, plan_type,
                )
                fp = _safe_fingerprint_for_account(session)
                return {
                    "ok": True,
                    "status": "live",
                    "token_expired": False,
                    "checked_at": checked_at,
                    "access_token": existing_access_token,
                    "session": {
                        "user": {"id": user_id, "email": email},
                        "account": {"planType": plan_type},
                    },
                    "proxy_used": session.proxy or None,
                    "fingerprint": fp,
                    "fingerprint_text": _safe_fingerprint_text_for_account(session),
                    "password_accepted": False,
                    "authentication_method": "access_token",
                }
            elif probe_result.get("token_expired") is True:
                logger.warning(
                    "[查活] 鉴权探测返回 401，当前 AT 已确认失效/过期 (%s)，准备重新登录刷新 AT...",
                    probe_result.get("error"),
                )
            else:
                logger.info(
                    "[查活] 鉴权探测返回网络状态 (%s)，继续尝试重新登录刷新...",
                    probe_result.get("error"),
                )

        # Existing authenticated web session may issue a fresh AT without
        # another password/OTP ceremony. Never treat a blocked request as dead.
        if not force_password_login:
            _live_stage("web_session_refresh", "尝试复用已保存网页登录态")
            renewed = _try_saved_web_session_refresh(session, email)
            if renewed:
                return {
                    "ok": True, "status": "live", "token_expired": False,
                    "checked_at": checked_at,
                    "access_token": renewed["accessToken"],
                    "session": renewed,
                    "proxy_used": session.proxy or None,
                    "authentication_method": "web_session_cookie",
                }

        # 阶段 2：如果无 AT 或已有 AT 已失效(401)/异常，则执行重新登录流程获取最新 AT
        _live_stage("login_preflight", "登录预检中")
        logger.info("[查活] 步骤2：执行重新登录获取最新 AT...")
        password = str(password_override or "").strip() if password_override is not None else _account_registration_password(email)
        session_info = None
        reauth_exc = None

        # 优先考虑密码登录（如果有密码且有TOTP/OTP，免去邮箱发码依赖）
        if password:
            logger.info("[查活] %s优先通过密码方式登录：%s", "强制使用候选密码，" if force_password_login else "账号保存有注册密码，", email)
            try:
                _live_stage("login_preflight", "登录预检中")
                session_pre, authorize_url = _network_preflight_with_retry(
                    email, proxy, fingerprint_state=fingerprint_state,
                )
                _live_stage("authorize", "登录授权中")
                final_url = follow_authorize(session_pre, authorize_url)
                dead_code = _confirmed_dead_code(final_url, redirect=True)
                if dead_code:
                    return {"ok": False, "status": "deactivated", "checked_at": checked_at, "error": dead_code, "token_expired": True}
                _live_stage("verification", "密码/验证码验证中")
                session_info = _login_via_password_or_otp(
                    session_pre, email, time.time(), email_source=email_source,
                    landing_url=final_url,
                    password_override=password,
                    force_password_login=force_password_login,
                    accept_password_step_only=accept_password_step_only,
                )
                session = session_pre
            except Exception as e:
                logger.warning("[查活] 密码登录未成功 (%s)%s", e, "，强制密码查活终止" if force_password_login else "，尝试备用登录")
                reauth_exc = e
                if force_password_login or isinstance(e, AuthChallengeRequiredError):
                    raise

        if not session_info and not force_password_login and existing_access_token and probe_result and probe_result.get("token_expired") is not True:
            # 原有 reauth 链路
            try:
                logger.info("[查活] 尝试登录态预热 + reauth OTP 刷新：%s", email)
                _live_stage("reauth", "登录态重认证中")
                _warm_authenticated_session(session, existing_access_token)
                human_delay("navigate")
                session_info = _login_via_reauth(
                    session,
                    email,
                    time.time(),
                    email_source=email_source,
                )
            except Exception as e:
                logger.warning("[查活] reauth 链路未成功: %s", e)
                if not reauth_exc:
                    reauth_exc = e

        if not session_info and not force_password_login:
            logger.info("[查活] 尝试 OAuth preflight + 邮箱/密码/MFA 登录：%s", email)
            try:
                _live_stage("login_preflight", "登录预检中")
                session_pre, authorize_url = _network_preflight_with_retry(
                    email, proxy, fingerprint_state=fingerprint_state,
                )
                _live_stage("authorize", "登录授权中")
                final_url = follow_authorize(session_pre, authorize_url)
                dead_code = _confirmed_dead_code(final_url, redirect=True)
                if dead_code:
                    return {"ok": False, "status": "deactivated", "checked_at": checked_at, "error": dead_code, "token_expired": True}
                is_pwd_err = bool(reauth_exc and ("密码错误" in str(reauth_exc) or "401" in str(reauth_exc)))
                _live_stage("verification", "密码/验证码验证中")
                session_info = _login_via_password_or_otp(
                    session_pre, email, time.time(), email_source=email_source,
                    landing_url=final_url,
                    allow_password=not is_pwd_err,
                    password_override=password if password_override is not None else None,
                    force_password_login=force_password_login,
                )
                session = session_pre
            except Exception as e:
                # The fallback is the last attempted path. Report its actual
                # failure (e.g. callback HTTP 403), not an earlier password
                # verification 409 that the fallback subsequently passed.
                reauth_exc = e

        if not session_info and reauth_exc:
            raise reauth_exc

        if force_password_login and accept_password_step_only and (session_info or {}).get("credential_verified") is True:
            _live_stage("complete", "候选密码已通过凭据阶段验收")
            logger.info("[查活] 候选密码已被登录接口接受，已进入下一认证阶段：%s stage=%s", email, (session_info or {}).get("verification_stage"))
            return {
                "ok": True,
                "status": "live",
                "token_expired": None,
                "checked_at": checked_at,
                "access_token": "",
                "session": session_info,
                "proxy_used": session.proxy or None,
                "fingerprint": _safe_fingerprint_for_account(session),
                "fingerprint_text": _safe_fingerprint_text_for_account(session),
                "password_accepted": True,
                "credential_verified": True,
                "verification_stage": (session_info or {}).get("verification_stage") or "next_auth_step",
                "authentication_method": "password",
            }

        _live_stage("identity_check", "校验新会话身份中")
        access_token = str((session_info or {}).get("accessToken") or "")
        if not access_token:
            raise RuntimeError("重新登录后未拿到 accessToken")

        user = session_info.get("user") or {}
        account = session_info.get("account") or {}
        if force_password_login:
            # A password response or OAuth callback alone is not an authenticated account check.
            actual_email = str(user.get("email") or "").strip().casefold()
            if not actual_email or actual_email != str(email or "").strip().casefold():
                raise RuntimeError("密码验收证据不足：新会话账号邮箱缺失或不匹配")
            if session_info.get("password_accepted") is not True:
                raise RuntimeError("密码验收证据不足：未证明本次会话使用候选密码")
            probe = probe_access_token_liveness(session, access_token)
            _trace_protocol("new_token_probe", http_status=probe.get("status_code"), valid=probe.get("valid") is True)
            if probe.get("valid") is not True or int(probe.get("status_code") or 0) != 200:
                raise RuntimeError(f"密码验收证据不足：新 AT 鉴权探测未通过 ({probe.get('error') or probe.get('status_code')})")
            expected_id = str(user.get("id") or "").strip()
            probed_id = str(probe.get("user_id") or "").strip()
            if expected_id and probed_id and expected_id != probed_id:
                raise RuntimeError("密码验收证据不足：新 AT 账号 ID 不匹配")
        _live_stage("complete", "新 AT 已获取")
        logger.info("[查活] 重新登录成功刷新 AT：%s user_id=%s plan=%s", email, user.get("id"), account.get("planType"))
        fp = _safe_fingerprint_for_account(session)
        return {
            "ok": True,
            "status": "live",
            "token_expired": False,
            "checked_at": checked_at,
            "access_token": access_token,
            "session": session_info,
            "session_token": __import__(
                "core.account_export", fromlist=["extract_nextauth_session_token"]
            ).extract_nextauth_session_token(session),
            "proxy_used": session.proxy or None,
            "fingerprint": fp,
            "fingerprint_text": _safe_fingerprint_text_for_account(session),
            "password_accepted": bool((session_info or {}).get("password_accepted")),
            "authentication_method": (session_info or {}).get("authentication_method") or ("password" if password_override is not None else "unknown"),
        }
    except AccountUnusableError as exc:
        code = getattr(exc, "error_code", "") or ""
        if code not in _CONFIRMED_DEAD_CODES:
            return {"ok": False, "status": "failed", "checked_at": checked_at, "error": code or "账号状态未确认", "token_expired": None}
        logger.warning("[查活] 已废号：%s %s", email, code)
        return {"ok": False, "status": "deactivated", "checked_at": checked_at, "error": code, "token_expired": True}
    except Exception as exc:
        code = _confirmed_dead_code(_exception_response_text(exc))
        if code:
            logger.warning("[查活] 已废号：%s %s", email, code)
            return {"ok": False, "status": "deactivated", "checked_at": checked_at, "error": code, "token_expired": True}

        # 如果先前鉴权探测已经明确当前 AT 是 401 token_expired，或者错误文本包含 token_expired
        is_token_expired = False
        if probe_result and probe_result.get("token_expired") is True:
            is_token_expired = True
        elif any(k in str(exc).lower() for k in ("token_expired", "token expired", "unauthorized")):
            is_token_expired = True

        # 保留重新登录阶段的根因；过期 AT 与 403 验证页是两个不同的状态。
        # 仅显示已知的错误类别，避免在 UI/数据库中写入异常携带的敏感 URL。
        failure = str(exc).lower()
        response = getattr(exc, "response", None)
        response_headers = getattr(response, "headers", {}) or {}
        response_status = getattr(response, "status_code", None) or getattr(exc, "code", None)
        is_challenge = isinstance(exc, AuthChallengeRequiredError) or any(
            str(k).lower() == "cf-mitigated" and str(v).lower() == "challenge"
            for k, v in response_headers.items()
        )
        if is_challenge:
            login_failure = "重新登录被验证页拦截 (HTTP 403)"
        elif response_status == 403 or "403" in failure:
            login_failure = "重新登录请求返回 HTTP 403"
        elif response_status == 429 or "429" in failure:
            login_failure = "重新登录请求被限流 (HTTP 429)"
        elif "timeout" in failure or "超时" in failure:
            login_failure = "重新登录等待超时"
        else:
            login_failure = f"{type(exc).__name__}: {str(exc)[:500]}"
        failed_stage = _LIVE_STAGE.get()
        err_text = f"[{failed_stage}] {login_failure}"
        if is_token_expired:
            err_text = f"AT已过期/失效 (token_expired)；[{failed_stage}] {login_failure}"
            logger.warning("[查活] AT 已失效且重新登录失败：%s，原因=%s", email, login_failure)
            return {
                "ok": False,
                "status": "failed",
                "token_expired": True,
                "checked_at": checked_at,
                "failure_stage": failed_stage,
                "error": err_text,
            }

        logger.warning("[查活] 失败：%s %s: %s", email, type(exc).__name__, str(exc)[:260])
        return {"ok": False, "status": "failed", "checked_at": checked_at, "failure_stage": failed_stage, "error": err_text}
    finally:
        try:
            _LIVE_STAGE.reset(stage_token)
            logger.info("[查活] 结束：%s", email)
            if session is not None:
                try:
                    session.session.close()
                except Exception:
                    pass
            if fh is not None:
                root_logger.removeHandler(fh)
                logger.removeHandler(fh)
                fh.close()
        finally:
            with _RUNNING_LOCK:
                _RUNNING.discard(key)
