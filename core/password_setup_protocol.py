# -*- coding: utf-8 -*-
"""Protocol-first add-password flow for already registered accounts.

This module deliberately keeps the transaction separate from registration.  It
handles the stable NextAuth/OpenAI authorization leg with a ``BrowserSession``
and exposes the remaining account-specific form submission as an injectable
callback, because the auth service may change the final form route.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping
from urllib.parse import parse_qs, urlencode, urlparse

from core.openai_auth import EmailOtpInvalidError, send_email_otp, validate_email_otp

from core.session import BrowserSession

logger = logging.getLogger(__name__)

AUTH_ORIGIN = "https://auth.openai.com"
CHATGPT_ORIGIN = "https://chatgpt.com"


@dataclass
class AddPasswordProtocolResult:
    ok: bool
    status: str
    stage: str
    email: str = ""
    auth_url: str = ""
    final_url: str = ""
    transaction: dict[str, str] = field(default_factory=dict)
    remote_password_present: bool = False
    requires_browser: bool = False
    otp_required: bool = False
    mfa_required: bool = False
    error: str = ""
    response_status: int | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok, "status": self.status, "stage": self.stage,
            "email": self.email, "auth_url": self.auth_url,
            "final_url": self.final_url, "transaction": dict(self.transaction),
            "remote_password_present": self.remote_password_present,
            "requires_browser": self.requires_browser,
            "otp_required": self.otp_required, "mfa_required": self.mfa_required,
            "error": self.error, "response_status": self.response_status,
            "details": dict(self.details),
        }


def _text(response: Any) -> str:
    return str(getattr(response, "text", "") or "")


def _json(response: Any) -> dict[str, Any]:
    try:
        value = response.json()
    except Exception:
        try:
            value = json.loads(_text(response) or "{}")
        except Exception:
            value = {}
    return value if isinstance(value, dict) else {}


def classify_auth_state(url: str = "", body: str = "", status_code: int | None = None) -> str:
    """Classify an auth response without treating a document 403 as fatal."""
    hay = f"{url} {body}".lower()
    if any(x in hay for x in ("first, verify", "current password", "incorrect email address or password", "当前密码")):
        return "current_password_required"
    if any(x in hay for x in ("email-verification", "email verification", "enter the code", "verification code", "验证码")):
        return "email_otp"
    if any(x in hay for x in ("mfa-challenge", "authenticator", "one-time password", "totp", "两步")):
        return "mfa_challenge"
    if any(x in hay for x in ("add-password", "create-account/password", "new password", "set password", "设置密码")):
        return "new_password_form"
    # Cloudflare returns a document challenge (403 + challenge HTML). Keep it
    # distinct from an application rejection so callers can resume the same session.
    if "cf-mitigated" in hay or "just a moment" in hay or "challenges.cloudflare.com" in hay or "challenge-platform" in hay:
        return "needs_challenge"
    # Match explicit denial documents or authoritative HTTP statuses. Generic
    # identifiers such as "error" occur in normal application bundles.
    if any(x in hay for x in ("access denied", "request blocked", "account has been blocked", "you have been blocked")) or status_code in {401, 429}:
        return "blocked"
    if any(x in hay for x in ("/api/auth/callback", "/api/auth/session", "logged in", "已登录")):
        return "completed"
    return "unknown"


def _transaction_from_url(url: str) -> dict[str, str]:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    keys = ("state", "client_id", "redirect_uri", "scope", "response_type", "ext-oai-did", "login_hint")
    return {key: str(query[key][0]) for key in keys if query.get(key)}


def start_add_password_authorize(
    session: BrowserSession,
    email: str,
    *,
    device_id: str | None = None,
    reset: bool = False,
    callback_url: str = f"{CHATGPT_ORIGIN}/",
) -> AddPasswordProtocolResult:
    """Create the independent add-password/password-reset authorization transaction."""
    email = str(email or "").strip()
    if not email:
        return AddPasswordProtocolResult(False, "failed", "input", error="email_required")
    did = str(device_id or getattr(session, "device_id", "") or "")
    try:
        # Bootstrap the same first-party cookie sequence as a fresh login before requesting CSRF.
        # The CSRF endpoint returns 403 when the initial origin cookie has not been established.
        get_bootstrap_headers = getattr(session, "get_chatgpt_headers", None)
        bootstrap_headers = (get_bootstrap_headers(referer=f"{CHATGPT_ORIGIN}/") if callable(get_bootstrap_headers)
                             else session.get_nextauth_headers(referer=f"{CHATGPT_ORIGIN}/"))
        bootstrap_headers.update({"accept": "text/html,application/xhtml+xml", "cache-control": "no-cache"})
        try:
            session.get(f"{CHATGPT_ORIGIN}/", headers=bootstrap_headers, allow_redirects=True)
        except Exception:
            pass
        csrf_resp = session.get(
            f"{CHATGPT_ORIGIN}/api/auth/csrf",
            headers=session.get_nextauth_headers(referer=f"{CHATGPT_ORIGIN}/"),
        )
        csrf = _json(csrf_resp).get("csrfToken")
        if not csrf and int(getattr(csrf_resp, "status_code", 0) or 0) == 403:
            # One clean retry after refreshing the origin cookie jar.
            try:
                session.get(f"{CHATGPT_ORIGIN}/", headers=bootstrap_headers, allow_redirects=True)
                csrf_resp = session.get(
                    f"{CHATGPT_ORIGIN}/api/auth/csrf",
                    headers=session.get_nextauth_headers(referer=f"{CHATGPT_ORIGIN}/"),
                )
                csrf = _json(csrf_resp).get("csrfToken")
            except Exception:
                pass
        if not csrf:
            return AddPasswordProtocolResult(False, "failed", "csrf", email=email,
                                             error="csrf_missing", response_status=getattr(csrf_resp, "status_code", None))
        query = {
            "connection": "password", "login_hint": email, "reauth": "password",
            "max_age": "0", "ext-oai-did": did,
            ("post_login_password_reset" if reset else "post_login_add_password"): "true",
        }
        headers = session.get_nextauth_headers(referer=f"{CHATGPT_ORIGIN}/")
        headers.update({"content-type": "application/x-www-form-urlencoded", "origin": CHATGPT_ORIGIN})
        response = session.post(
            f"{CHATGPT_ORIGIN}/api/auth/signin/openai?{urlencode(query)}",
            headers=headers,
            data=urlencode({"callbackUrl": callback_url, "csrfToken": csrf, "json": "true"}),
        )
        payload = _json(response)
        auth_url = str(payload.get("url") or "")
        if not auth_url:
            return AddPasswordProtocolResult(False, "failed", "authorize", email=email,
                                             error="authorize_url_missing", response_status=getattr(response, "status_code", None),
                                             details={"body": _text(response)[:300]})
        marker = "post_login_password_reset=true" if reset else "post_login_add_password=true"
        if not auth_url.startswith(AUTH_ORIGIN) or marker not in auth_url:
            return AddPasswordProtocolResult(False, "failed", "authorize", email=email, auth_url=auth_url,
                                             error="authorize_context_invalid", response_status=getattr(response, "status_code", None))
        return AddPasswordProtocolResult(True, "started", "authorize", email=email, auth_url=auth_url,
                                         transaction=_transaction_from_url(auth_url), response_status=getattr(response, "status_code", None),
                                         details={"reset": bool(reset), "csrf_obtained": True})
    except Exception as exc:
        logger.debug("add-password authorize failed", exc_info=True)
        return AddPasswordProtocolResult(False, "failed", "authorize", email=email,
                                         error=f"{type(exc).__name__}: {exc}")


def follow_add_password_authorize(session: BrowserSession, result: AddPasswordProtocolResult) -> AddPasswordProtocolResult:
    """Follow the authorization URL and classify the resulting transaction state."""
    if not result.ok or not result.auth_url:
        return result
    try:
        headers = session.get_auth_navigate_headers(referer=f"{CHATGPT_ORIGIN}/")
        response = session.get(result.auth_url, headers=headers, allow_redirects=True)
        final_url = str(getattr(response, "url", "") or result.auth_url)
        state = classify_auth_state(final_url, _text(response), getattr(response, "status_code", None))
        result.final_url = final_url
        result.stage = state
        result.response_status = getattr(response, "status_code", None)
        result.otp_required = state == "email_otp"
        result.mfa_required = state == "mfa_challenge"
        result.remote_password_present = state == "current_password_required"
        result.requires_browser = state in {"email_otp", "mfa_challenge", "new_password_form", "current_password_required"}
        result.status = ("needs_challenge" if state == "needs_challenge" else ("needs_interaction" if result.requires_browser else ("completed" if state == "completed" else "failed")))
        if state == "needs_challenge":
            response_headers = {str(k).lower(): str(v) for k, v in dict(getattr(response, "headers", {}) or {}).items()}
            result.error = "cloudflare_challenge"
            result.requires_browser = False
            result.details.update({
                "cf_mitigated": response_headers.get("cf-mitigated", ""),
                "cf_ray": response_headers.get("cf-ray", ""),
                "challenge_host": urlparse(final_url).netloc,
                "challenge_url": final_url,
                "resume_same_session": True,
            })
        elif state == "blocked":
            result.error = "auth_document_blocked"
        # ``started`` only means the signin transaction was created. The follow-up
        # response is successful only after the auth page is actually reached.
        if state != "completed":
            result.ok = False
        return result
    except Exception as exc:
        result.ok = False
        result.status = "failed"
        result.stage = "authorize_follow"
        result.error = f"{type(exc).__name__}: {exc}"
        return result



def build_password_request_template(request: Any, response: Any = None) -> dict[str, Any]:
    """Extract a replayable password-submit request from a Playwright request."""
    try:
        headers = dict(request.all_headers())
    except Exception:
        headers = dict(getattr(request, "headers", {}) or {})
    try:
        body = request.post_data
    except Exception:
        body = getattr(request, "post_data", None)
    out = {
        "method": str(getattr(request, "method", "POST") or "POST").upper(),
        "url": str(getattr(request, "url", "") or ""),
        "headers": {str(k).lower(): str(v) for k, v in headers.items()
                     if str(k).lower() not in {"cookie", "authorization"}},
        "body": str(body or ""),
    }
    if response is not None:
        out["response_status"] = int(getattr(response, "status", 0) or 0)
    return out


def submit_password_request_template(session: BrowserSession, result: AddPasswordProtocolResult,
                                     new_password: str, template: Mapping[str, Any]) -> dict[str, Any]:
    """Replay a captured password form with only the password value replaced."""
    url = str(template.get("url") or "")
    method = str(template.get("method") or "POST").upper()
    if not url.startswith(AUTH_ORIGIN) or method not in {"POST", "PUT", "PATCH"} or "/rum" in url.lower() or "telemetry" in url.lower():
        return {"ok": False, "error": "password_request_template_invalid"}
    original = str(template.get("body") or "")
    if "$PASSWORD" not in original and not any(key in original.lower() for key in ("password", "new_password", "password1", "password2", "confirm_password", "password_confirmation")):
        return {"ok": False, "error": "password_field_missing"}
    body = original.replace("$PASSWORD", str(new_password))
    if "$PASSWORD" not in original:
        try:
            payload = json.loads(body)
            if isinstance(payload, dict):
                for key in ("password", "new_password", "password1", "password2", "confirm_password", "password_confirmation"):
                    if key in payload:
                        payload[key] = new_password
                body = json.dumps(payload, separators=(",", ":"))
        except Exception:
            from urllib.parse import parse_qsl
            fields = parse_qsl(body, keep_blank_values=True)
            if fields:
                body = urlencode([(k, new_password if "password" in k.lower() else v) for k, v in fields])
    headers = dict(template.get("headers") or {})
    headers.setdefault("content-type", "application/json")
    headers["origin"] = AUTH_ORIGIN
    headers["referer"] = str(result.final_url or result.auth_url or f"{AUTH_ORIGIN}/")
    if hasattr(session, "request"):
        response = session.request(method, url, headers=headers, data=body)
    elif method == "POST" and hasattr(session, "post"):
        response = session.post(url, headers=headers, data=body)
    elif method == "GET":
        response = session.get(url, headers=headers)
    elif hasattr(session, "session") and hasattr(session.session, "request"):
        response = session.session.request(method, url, headers=headers, data=body)
    else:
        response = session.post(url, headers=headers, data=body)
    status = int(getattr(response, "status_code", 0) or 0)
    return {"ok": 200 <= status < 300, "status_code": status, "payload": _json(response)}

def run_add_password_protocol(
    account: Mapping[str, Any],
    new_password: str,
    *,
    session: BrowserSession | None = None,
    otp_provider: Callable[..., str] | None = None,
    mfa_submitter: Callable[..., Any] | None = None,
    submit_password: Callable[..., Any] | None = None,
    reset: bool = False,
    log_callback: Callable[[str, Mapping[str, Any]], None] | None = None,
    account_id: int | None = None,
    resume_result: AddPasswordProtocolResult | None = None,
) -> AddPasswordProtocolResult:
    """Run the protocol leg and optionally delegate the final form submission.

    ``submit_password`` receives ``(session, result, new_password)`` and should
    return a response, mapping, or ``True`` when the auth service accepts the
    password.  Keeping this hook explicit prevents registration's ``user/register``
    endpoint from ever being reused for existing accounts.
    """
    def emit(event: str, **details: Any) -> None:
        payload = {"event": event, "account_id": account_id, "email": str(account.get("email") or ""), **details}
        if log_callback:
            try:
                log_callback(event, payload)
            except Exception:
                logger.debug("protocol log callback failed", exc_info=True)
        logger.info("add-password protocol %s", payload)

    email = str(account.get("email") or "").strip()
    emit("start", reset=bool(reset), has_submitter=bool(submit_password), has_otp_provider=bool(otp_provider), has_mfa_submitter=bool(mfa_submitter))
    own_session = session is None
    if session is None:
        proxy_used = str(account.get("proxy_used") or "") or None
        if proxy_used:
            try:
                from core.chatgpt_plan import rotate_proxy_session
                proxy_used, _ = rotate_proxy_session(proxy_used)
            except Exception:
                pass
        session = BrowserSession(proxy=proxy_used,
                                 device_id=str(account.get("device_id") or "") or None,
                                 fingerprint_seed=f"account:{email.lower()}")
    resume_stage = ""
    if resume_result is None:
        result = start_add_password_authorize(session, email, device_id=str(account.get("device_id") or "") or None, reset=reset)
        emit("authorize", status=result.status, stage=result.stage, ok=result.ok, response_status=result.response_status, error=result.error)
        if not result.ok:
            return result
    else:
        result = resume_result
        resume_stage = str(result.stage or "")
        result.ok = True
        result.status = "started"
        result.stage = "authorize"
        result.error = ""
        emit("authorize_resume", status=result.status, stage=result.stage, ok=True, response_status=result.response_status, error="")
    actionable_resume_stages = {"email_otp", "mfa_challenge", "new_password_form", "current_password_required"}
    bridge_stage = resume_stage if resume_stage in actionable_resume_stages else str((result.details or {}).get("bridge_landed_stage") or "")
    if bridge_stage in {"email_otp", "mfa_challenge", "new_password_form", "current_password_required"}:
        result.stage = bridge_stage
        result.ok = True
        result.status = "needs_interaction"
        result.error = ""
        result.otp_required = bridge_stage == "email_otp"
        result.mfa_required = bridge_stage == "mfa_challenge"
        result.remote_password_present = bridge_stage == "current_password_required"
        result.requires_browser = True
        emit("authorize_bridge_landing", status=result.status, stage=result.stage, ok=True, response_status=result.response_status, error="")
    else:
        result = follow_add_password_authorize(session, result)
        emit("authorize_follow", status=result.status, stage=result.stage, ok=result.ok, response_status=result.response_status, error=result.error)
    if result.remote_password_present:
        result.ok = False
        result.status = 'reset_required'
        result.error = 'remote_password_present'
        emit('reset_required', status=result.status, stage=result.stage, error=result.error)
        return result
    # Auth interaction pages are resumable protocol states, not terminal failures.
    # ``follow_add_password_authorize`` intentionally leaves ``ok=False`` until
    # the OTP/password step completes, so let actionable stages continue here.
    actionable_stages = {"email_otp", "mfa_challenge", "new_password_form"}
    if not result.ok and result.stage not in actionable_stages:
        return result
    def advance_mfa() -> bool:
        if result.stage != "mfa_challenge":
            return True
        result.status = "needs_mfa"
        result.mfa_required = True
        result.details["bridge_landed_stage"] = "mfa_challenge"
        if mfa_submitter is None:
            # 优先检查账号自身是否绑定 2FA TOTP，自动生成动态码推进，无需外部等待
            try:
                from core.codex_oauth import _account_totp_code
                totp_code = _account_totp_code(email)
                if totp_code:
                    from core.account_liveness import _extract_factor_id, _mfa_issue_challenge, _mfa_verify
                    factor_id = _extract_factor_id(result.details, result.final_url)
                    if factor_id:
                        _mfa_issue_challenge(session, factor_id)
                        mfa_payload = _mfa_verify(session, factor_id, totp_code)
                        continue_url = str((mfa_payload or {}).get("continue_url") or "")
                        if continue_url:
                            result.details["password_continue_url"] = continue_url
                        result.stage = "new_password_form"
                        result.mfa_required = False
                        result.ok = True
                        result.status = "needs_interaction"
                        result.error = ""
                        result.requires_browser = True
                        result.details["mfa_validated"] = True
                        result.details["bridge_landed_stage"] = "new_password_form"
                        emit("mfa_validated", status=result.status, stage=result.stage, mfa_validated=True)
                        return True
            except Exception as auto_mfa_exc:
                logger.debug("协议补密自动 2FA 校验未直接通过: %s", auto_mfa_exc)
            emit("mfa_required", status=result.status, stage=result.stage)
            return False
        try:
            mfa_result = mfa_submitter(session, result)
            if mfa_result is False or (isinstance(mfa_result, Mapping) and not mfa_result.get("ok", True)):
                raise RuntimeError("mfa_submission_rejected")
            payload = dict(mfa_result or {}) if isinstance(mfa_result, Mapping) else {}
            page = payload.get("page") if isinstance(payload.get("page"), Mapping) else {}
            page_type = str((page or {}).get("type") or "").strip().lower()
            continue_url = str(payload.get("continue_url") or payload.get("url") or (page or {}).get("continue_url") or "")
            if continue_url:
                parsed = urlparse(continue_url)
                if parsed.netloc in {"", "auth.openai.com"}:
                    result.details["password_continue_url"] = continue_url
            if page_type in {"reset_password_new_password", "create_account_password", "new_password"}:
                result.stage = "new_password_form"
            else:
                result.stage = classify_auth_state(continue_url, json.dumps(payload, ensure_ascii=False))
            if result.stage == "unknown" and continue_url:
                path = urlparse(continue_url).path.lower()
                if "password" in path:
                    result.stage = "new_password_form"
            result.mfa_required = False
            result.ok = True
            result.status = "needs_interaction"
            result.error = ""
            result.requires_browser = result.stage == "new_password_form"
            result.details["mfa_validated"] = True
            result.details["bridge_landed_stage"] = result.stage
            emit("mfa_validated", status=result.status, stage=result.stage, mfa_validated=True)
            return True
        except Exception as exc:
            result.ok = False
            result.status = "needs_mfa"
            result.stage = "mfa_challenge"
            result.mfa_required = True
            result.error = "mfa_not_available"
            result.details["mfa_provider_error_type"] = type(exc).__name__
            emit("mfa_pending", status=result.status, stage=result.stage, error=result.error)
            return False

    if not advance_mfa():
        return result
    if result.stage == "email_otp":
        result.details["otp_provider_available"] = bool(otp_provider)
        if otp_provider is None:
            result.status = "needs_otp"
            emit("otp_required", status=result.status, stage=result.stage)
            return result
        try:
            rejected_codes: set[str] = set()
            otp_after_ts: float | None = None
            otp_result: dict[str, Any] | None = None
            for otp_attempt in range(2):
                if rejected_codes:
                    try:
                        code = otp_provider(email, after_ts=otp_after_ts, exclude_codes=rejected_codes)
                    except TypeError as exc:
                        if "exclude_codes" not in str(exc):
                            raise
                        code = otp_provider(email, after_ts=otp_after_ts)
                else:
                    code = otp_provider(email, after_ts=otp_after_ts)
                try:
                    otp_result = validate_email_otp(session, str(code))
                    break
                except EmailOtpInvalidError:
                    rejected_codes.add(str(code).strip())
                    result.details["otp_rejected_count"] = len(rejected_codes)
                    if otp_attempt >= 1:
                        raise
                    otp_after_ts = time.time()
                    send_email_otp(session)
                    emit("otp_rejected_retry", status="needs_otp", stage="email_otp", rejected_count=len(rejected_codes))
            if otp_result is None:
                raise EmailOtpInvalidError("email OTP validation did not produce a result")
            result.details["otp_validated"] = True
            otp_page = (otp_result.get("page") or {}).get("type") if isinstance(otp_result, dict) else None
            result.details["otp_page"] = otp_page
            continue_url = str((otp_result or {}).get("continue_url") or "")
            if continue_url:
                parsed = urlparse(continue_url)
                if parsed.netloc == "auth.openai.com":
                    result.details["password_continue_url"] = continue_url
            if otp_page in {"reset_password_new_password", "create_account_password", "new_password"}:
                result.stage = "new_password_form"
            else:
                result.stage = classify_auth_state(str((otp_result or {}).get("continue_url") or ""), json.dumps(otp_result or {}))
            result.requires_browser = result.stage in {"mfa_challenge", "new_password_form"}
            emit("otp_validated", status=result.status, stage=result.stage, otp_validated=True)
            if not advance_mfa():
                return result
        except Exception as exc:
            # Keep the exact protocol session resumable when the mailbox API has
            # not produced a fresh code yet. A delayed email is not an auth failure.
            result.ok = False
            result.status = "needs_otp"
            result.stage = "email_otp"
            result.otp_required = True
            result.error = "otp_not_available"
            result.details["otp_provider_error_type"] = type(exc).__name__
            emit("otp_pending", status=result.status, stage=result.stage, error=result.error)
            return result
    if submit_password is None:
        result.status = "needs_browser" if result.requires_browser else result.status
        emit("template_missing", status=result.status, stage=result.stage, requires_browser=result.requires_browser)
        return result
    try:
        submitted = submit_password(session, result, new_password)
        accepted = submitted is True or (isinstance(submitted, Mapping) and submitted.get("ok", True))
        result.ok = bool(accepted)
        result.status = "completed" if accepted else "failed"
        result.stage = "completed" if accepted else "password_submit"
        if not accepted:
            result.error = "password_submission_rejected"
        result.details["submission"] = submitted if isinstance(submitted, Mapping) else {"accepted": bool(accepted)}
        emit("password_submit", status=result.status, stage=result.stage, ok=result.ok, response_status=(submitted.get("status_code") if isinstance(submitted, Mapping) else None), error=result.error)
        return result
    except Exception as exc:
        result.ok = False
        result.status = "failed"
        result.stage = "password_submit"
        result.error = f"{type(exc).__name__}: {exc}"
        emit("password_submit_failed", status=result.status, stage=result.stage, error=result.error)
        return result
    finally:
        if own_session:
            try:
                session.close()
            except Exception:
                pass





