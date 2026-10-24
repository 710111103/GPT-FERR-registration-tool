# -*- coding: utf-8 -*-
"""
ChatGPT Auth 模块
处理 chatgpt.com 域名下的认证请求（步骤1-3）
"""
import json
import logging
from urllib.parse import urlencode, urlparse, parse_qs

from core.session import BrowserSession
from config import (
    OPENAI_CLIENT_ID, OPENAI_SCOPE, OPENAI_AUDIENCE, OPENAI_REDIRECT_URI
)

logger = logging.getLogger(__name__)

# 2026-07-19 ARE 捕获：ChatGPT Web signin 已使用 5 位 passkey capabilities，
# authorize URL 里还会带 ccaps=login_methods。纯协议保持同形态，避免落入旧/异常 auth 分支。
_PASSKEY_CLIENT_CAPABILITIES = "11111"
_CC_CAPS = "login_methods"


def _ensure_authorize_context(authorize_url: str, session: BrowserSession, email: str) -> str:
    """
    对 NextAuth 返回的 authorize URL 做最后兜底：确保当前前端默认
    login_or_signup 链路的上下文参数没有在重定向生成阶段丢失。
    """
    try:
        parsed = urlparse(authorize_url)
        if not parsed.netloc.endswith("auth.openai.com"):
            return authorize_url
        if "email-verification" in parsed.path or "create-account" in parsed.path or "about-you" in parsed.path:
            return authorize_url
        params = parse_qs(parsed.query, keep_blank_values=True)
        required = {
            "ext-oai-did": session.device_id,
            "auth_session_logging_id": session.auth_session_logging_id,
            "ext-passkey-client-capabilities": _PASSKEY_CLIENT_CAPABILITIES,
            "screen_hint": "login_or_signup",
            "login_hint": email,
            "ccaps": _CC_CAPS,
        }
        changed = False
        for key, value in required.items():
            if not params.get(key):
                params[key] = [value]
                changed = True
        if not changed:
            return authorize_url
        return parsed._replace(query=urlencode(params, doseq=True)).geturl()
    except Exception:
        return authorize_url


def get_providers(session: BrowserSession) -> dict:
    """
    步骤1: 获取 OAuth Providers 列表。
    GET https://chatgpt.com/api/auth/providers

    验证与 chatgpt.com 的连接是否正常，并获取可用的 OAuth 提供商。
    注：如果遇到 403 挑战，降级容错返回默认 openai provider 结构，不阻断注册链路。
    """
    url = "https://chatgpt.com/api/auth/providers"
    headers = session.get_nextauth_headers(referer="https://chatgpt.com/auth/login")

    logger.info("[步骤1] 获取 OAuth Providers...")
    try:
        resp = session.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            logger.info(f"[步骤1] 成功获取 {len(data)} 个 providers: {list(data.keys())}")
            return data
        logger.warning(f"[步骤1] 获取 providers 响应状态码={resp.status_code}，使用默认 provider 配置继续")
    except Exception as exc:
        logger.warning(f"[步骤1] 获取 providers 异常（{exc}），使用默认 provider 配置继续")

    return {
        "openai": {
            "id": "openai",
            "name": "openai",
            "type": "oauth",
            "signinUrl": "https://chatgpt.com/api/auth/signin/openai",
            "callbackUrl": "https://chatgpt.com/api/auth/callback/openai"
        }
    }


def get_csrf_token(session: BrowserSession) -> str:
    """
    步骤2: 获取 CSRF Token。
    GET https://chatgpt.com/api/auth/csrf

    CSRF token 将在后续 signin 请求中使用。
    优先使用真实浏览器环境预热时已提取的 cached_csrf_token。
    """
    cached_token = getattr(session, "cached_csrf_token", None)
    if cached_token:
        logger.info(f"[步骤2] 使用真实浏览器环境预热提取的 CSRF Token: {cached_token[:20]}...")
        return cached_token

    url = "https://chatgpt.com/api/auth/csrf"
    headers = session.get_nextauth_headers(referer="https://chatgpt.com/auth/login")

    logger.info("[步骤2] 获取 CSRF Token...")
    try:
        resp = session.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            csrf_token = data.get("csrfToken", "")
            if csrf_token:
                logger.info(f"[步骤2] 获取 CSRF Token 成功: {csrf_token[:20]}...")
                return csrf_token
        logger.warning(f"[步骤2] 协议获取 CSRF 响应状态码={resp.status_code}，使用预设标识继续")
    except Exception as exc:
        logger.warning(f"[步骤2] 协议获取 CSRF 异常（{exc}），使用预设标识继续")

    # 返回空串或占位符，由步骤3无缝转入无头浏览器原生提交
    return "browser_fallback_csrf"


def signin_openai(session: BrowserSession, csrf_token: str, email: str) -> str:
    """
    步骤3: 发起 OAuth Signin 请求。
    POST https://chatgpt.com/api/auth/signin/openai

    构造 OAuth 授权参数，获取 authorize URL。

    Args:
        session: 浏览器会话
        csrf_token: 从步骤2获取的 CSRF token
        email: 注册邮箱

    Returns:
        authorize_url: auth.openai.com 的授权 URL
    """
    # 构造 URL 查询参数
    query_params = {
        "prompt": "login",
        "ext-oai-did": session.device_id,
        "auth_session_logging_id": session.auth_session_logging_id,
        "ext-passkey-client-capabilities": _PASSKEY_CLIENT_CAPABILITIES,
        "screen_hint": "login_or_signup",
        "login_hint": email,
    }
    url = "https://chatgpt.com/api/auth/signin/openai?" + urlencode(query_params)

    # 构造请求头
    headers = session.get_nextauth_headers(referer="https://chatgpt.com/")
    headers["content-type"] = "application/x-www-form-urlencoded"
    headers["origin"] = "https://chatgpt.com"

    # 构造请求体
    body = urlencode({
        "callbackUrl": "https://chatgpt.com/",
        "csrfToken": csrf_token,
        "json": "true",
    })

    logger.info(f"[步骤3] 发起 OAuth Signin 请求, 邮箱: {email}")
    try:
        resp = session.post(url, headers=headers, data=body)
        resp.raise_for_status()
        data = resp.json()
        authorize_url = data.get("url", "")
    except Exception as exc:
        from config import openai_protocol as _protocol_cfg
        if bool(getattr(_protocol_cfg, "PURE_PROTOCOL_ONLY", False)):
            raise
        logger.warning(f"[步骤3] 协议发起 OAuth Signin 异常 ({exc})，调用无头浏览器无缝执行...")
        from core.browser_environment import signin_with_headless_browser
        authorize_url = signin_with_headless_browser(session, email)

    if not authorize_url:
        raise ValueError(f"[步骤3] 未获取到 authorize URL")

    authorize_url = _ensure_authorize_context(authorize_url, session, email)
    logger.info("[步骤3] 获取 authorize URL 成功，已确认 login_or_signup/oai-did 上下文")
    logger.debug(f"[步骤3] URL: {authorize_url[:160]}...")
    return authorize_url
