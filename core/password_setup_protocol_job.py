from __future__ import annotations
import json
import time
from urllib.parse import urlparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from core import db, password_setup_service
from core.password_setup_protocol import (
    AddPasswordProtocolResult,
    run_add_password_protocol,
    submit_password_request_template,
)
from core.session import BrowserSession

_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="protocol-password")
_RUNNING: set[int] = set()
_LOCK = __import__('threading').RLock()
# In-memory continuation state. It intentionally keeps the exact CookieJar, proxy,
# device id and OAuth state together. No cookie/token value is exposed by the API/log.
_PENDING: dict[int, dict] = {}
_RESULTS: dict[int, dict] = {}
_PENDING_TTL = 15 * 60


def _normalize_terminal_result(result: AddPasswordProtocolResult) -> AddPasswordProtocolResult:
    """记录“提交结束”，但不把提交结束伪装成密码登录验收成功。"""
    if result.status == "completed" and result.ok:
        result.details["terminal_submission_completed"] = True
    return result


def _public_result(result: AddPasswordProtocolResult | dict | None) -> dict:
    if isinstance(result, AddPasswordProtocolResult):
        value = result.as_dict()
    else:
        value = dict(result or {})
    details = dict(value.get("details") or {})
    # Keep diagnostics, strip values that could contain an authorization state or URL query.
    value["auth_url"] = ""
    value["final_url"] = ""
    value["transaction"] = {}
    details.pop("challenge_url", None)
    value["details"] = details
    return value


def _close_pending(account_id: int) -> None:
    item = _PENDING.pop(int(account_id), None)
    if item:
        try:
            item["session"].close()
        except Exception:
            pass


def _prune_pending() -> None:
    now = time.time()
    with _LOCK:
        expired = [aid for aid, item in _PENDING.items() if now - float(item.get("updated_at") or 0) > _PENDING_TTL]
        for aid in expired:
            _close_pending(aid)
            current = dict(_RESULTS.get(aid) or {})
            current.update({"ok": False, "status": "expired", "error": "protocol_session_expired"})
            _RESULTS[aid] = current
            db.update_account_password_setup(aid, {"status": "expired", "message": "纯协议会话已过期，请重新发起"})


def _load_template(account_id: int):
    log = password_setup_service._append_log
    p = Path("注册日志") / "password-setup" / "password-request-template.json"
    if not p.exists():
        log(account_id, "当前无真实密码提交模板；会话将在实际密码页前保持状态")
        return None
    try:
        template = json.loads(p.read_text(encoding="utf-8"))
        return template if isinstance(template, dict) else None
    except Exception as exc:
        log(account_id, f"模板读取失败：{type(exc).__name__}: {exc}")
        return None


def _verify_submitted_password(account: dict, password: str, account_id: int) -> str:
    """Verify the submitted password with a fresh protocol login.

    The password is considered correct as soon as the password endpoint accepts it
    and advances to MFA/email verification.  Completing that second factor or
    obtaining a new AT is intentionally not required for password persistence.
    """
    receipt = password_setup_service._verify_password_via_liveness(
        account, password, account_id, protocol_only=True,
    )
    if receipt.get("proxy_used") == "fingerprint_browser":
        raise RuntimeError("协议验收证据不足：返回的是浏览器会话")
    if receipt.get("ok") is not True or receipt.get("password_accepted") is not True:
        raise RuntimeError("协议验收证据不足：候选密码未被登录接口接受")
    if receipt.get("credential_verified") is True:
        return "protocol_credential_stage"
    user = (receipt.get("session") or {}).get("user") or {}
    if (not str(receipt.get("access_token") or "").strip()
            or str(user.get("email") or "").strip().casefold()
            != str(account.get("email") or "").strip().casefold()):
        raise RuntimeError("协议验收证据不足：缺少匹配会话或新 AT")
    return "protocol_full_session"


def _run(account_id: int, password: str | None = None, reset: bool = False, resume: bool = False):
    acc = db.get_account(account_id)
    if not acc:
        return {"ok": False, "status": "failed", "error": "account_not_found"}
    log = password_setup_service._append_log
    session = None
    previous = None
    try:
        if not password:
            from core.openai_auth import generate_registration_password
            password = generate_registration_password()
        template = _load_template(account_id)
        submitter = (lambda sess, state, pwd: submit_password_request_template(sess, state, pwd, template)) if template else None
        otp_provider = password_setup_service._otp_provider(str(acc.get("email_source") or "generic_api"))
        totp_secret = str(acc.get("totp_secret") or "").strip()
        mfa_submitter = None
        if totp_secret:
            def mfa_submitter(sess, state):
                import pyotp
                from core.account_liveness import (
                    TotpVerificationRejectedError,
                    _extract_factor_id,
                    _mfa_issue_challenge,
                    _mfa_verify,
                )
                continue_url = str((state.details or {}).get("password_continue_url") or state.final_url or "")
                factor_id = _extract_factor_id({}, continue_url)
                if not factor_id:
                    raise RuntimeError("mfa_factor_id_missing")
                _mfa_issue_challenge(sess, factor_id)
                last_exc = None
                for attempt in range(2):
                    code = pyotp.TOTP(totp_secret).now()
                    try:
                        return _mfa_verify(sess, factor_id, code)
                    except TotpVerificationRejectedError as exc:
                        last_exc = exc
                        if attempt:
                            raise
                        remaining = 30 - (int(time.time()) % 30)
                        time.sleep(min(remaining + 1, 31))
                        _mfa_issue_challenge(sess, factor_id)
                raise last_exc or RuntimeError("mfa_verification_failed")
        if resume:
            with _LOCK:
                pending = _PENDING.get(int(account_id))
            if not pending:
                result = {"ok": False, "status": "expired", "error": "protocol_session_missing"}
                _RESULTS[int(account_id)] = result
                db.update_account_password_setup(account_id, {"status": "expired", "message": "没有可续跑的纯协议会话"})
                return result
            session = pending["session"]
            previous = pending["result"]
            password = pending["password"]
            reset = bool(pending["reset"])
            log(account_id, "继续同一纯协议会话：复用代理、CookieJar、设备 ID 和 OAuth state")
        else:
            session = BrowserSession(
                proxy=str(acc.get("proxy_used") or "") or None,
                device_id=str(acc.get("device_id") or "") or None,
                fingerprint_seed=f"account:{str(acc.get('email') or '').lower()}",
            )
            log(account_id, f"纯协议补密码开始：{acc.get('email') or ''} reset={reset}", clear=True)
        db.update_account_password_setup(account_id, {"status": "running", "message": "纯协议补密码进行中"})

        def plog(event, details):
            safe = {k: v for k, v in details.items() if k not in {"email", "account_id", "auth_url", "final_url", "transaction"}}
            log(account_id, "协议事件 " + event + " " + json.dumps(safe, ensure_ascii=False, separators=(",", ":")))

        result = run_add_password_protocol(
            acc, password, session=session, otp_provider=otp_provider,
            mfa_submitter=mfa_submitter, submit_password=submitter, reset=reset, log_callback=plog,
            account_id=account_id, resume_result=previous,
        )
        submission = result.details.get('submission') if isinstance(result.details, dict) else None
        submission_status = int((submission or {}).get('status_code') or 0) if isinstance(submission, dict) else 0
        stale_template_rejected = result.stage == 'password_submit' and submission_status in {400, 401, 403, 422}
        if result.status == 'needs_browser' or stale_template_rejected:
            continue_url = str((result.details or {}).get('password_continue_url') or '')
            if result.stage == 'password_submit':
                continue_url = continue_url or 'https://auth.openai.com/reset-password/new-password'
            if continue_url:
                from core.browser_environment import capture_and_submit_new_password
                template_file = Path('注册日志') / 'password-setup' / 'password-request-template.json'
                log(account_id, '密码提交模板已过期或缺失，启动后台浏览器重新抓取实时请求并提交...')
                captured_ok = capture_and_submit_new_password(session, continue_url, password, template_file)
                if captured_ok:
                    result.ok = True
                    result.status = 'completed'
                    result.stage = 'completed'
                    result.error = ''
                    # The first authorize request may have returned 403 because
                    # Cloudflare required a browser bridge. Once the actual
                    # password submission succeeds, publish the terminal HTTP
                    # result instead of leaving the initial 403 in the summary.
                    result.remote_password_present = True
                    result.details['template_captured'] = True
                    result.details['template_refreshed_after_rejection'] = stale_template_rejected
                    result.details['terminal_submission_completed'] = True
                    log(account_id, '新密码已提交，实时协议模板已刷新；等待独立登录验收')
                else:
                    result.status = 'needs_template'
                    result.error = 'capture_template_failed'
                    result.details['protocol_only'] = True
            else:
                result.status = 'needs_template'
                result.error = 'request_template_required'
                result.details['protocol_only'] = True

        # 协议 completed 只表示提交步骤结束；必须使用全新浏览器登录后才能公开密码。
        _normalize_terminal_result(result)
        login_verified = False
        terminal_submitted = bool(result.ok and result.status == "completed")
        if terminal_submitted:
            result.remote_password_present = True
            db.update_account_password_setup(account_id, {
                "ok": False, "status": "verifying",
                "candidate_password": password,
                "remote_password_present": True,
                "login_verified": False,
                "message": "纯协议提交结束，正在使用全新协议会话验证密码登录",
            })
            log(account_id, "协议提交结束；开始使用全新协议会话验证候选密码，验证前不会转正")
            try:
                method = _verify_submitted_password(acc, password, account_id)
                login_verified = True
                result.details["password_login_verified"] = True
                result.details["verification_method"] = method
                log(account_id, "候选密码已通过纯协议密码登录验收")
            except Exception as exc:
                verification_error = f"{type(exc).__name__}: {str(exc)[:600]}"
                result.ok = False
                wrong_password = (
                    "密码错误" in verification_error
                    or "incorrect email address or password" in verification_error.lower()
                    or "wrong password" in verification_error.lower()
                )
                result.status = "verification_failed" if wrong_password else "verification_pending"
                result.stage = "password_login_verification"
                result.error = verification_error
                result.details["password_login_verified"] = False
                result.details["submission_completed_but_login_failed"] = True
                log(account_id, "候选密码登录验收失败：" + verification_error)

        public = _public_result(result)
        with _LOCK:
            _RESULTS[int(account_id)] = public
            if result.status in {"needs_challenge", "needs_otp", "needs_mfa", "needs_template"}:
                _PENDING[int(account_id)] = {
                    "session": session, "result": result, "password": password,
                    "reset": reset, "updated_at": time.time(),
                }
                session = None  # retained for explicit resume
            else:
                _close_pending(account_id)
        ui_status = str(result.status or "failed")
        if ui_status not in {"needs_challenge", "needs_otp", "needs_mfa", "needs_template", "needs_interaction", "reset_required", "completed", "verification_failed", "verification_pending", "failed", "expired"}:
            ui_status = "success" if result.ok else "failed"
        if login_verified:
            db.update_account_password_setup(account_id, {
                "ok": True,
                "status": "success",
                "message": "纯协议提交后已通过独立密码登录验收（" + str(result.details.get("verification_method") or "unknown") + "）",
                "error": None,
                "remote_password_present": True,
                "login_verified": True,
                "password": password,
            })
        else:
            pending_statuses = {"needs_challenge", "needs_otp", "needs_mfa", "needs_template"}
            db.update_account_password_setup(account_id, {
                "ok": False,
                "status": ui_status,
                "message": (
                    ("密码错误，登录验收失败" if ui_status == "verification_failed" else "纯协议提交结束，登录验收未完成；密码真伪未确定")
                    if terminal_submitted else "纯协议：" + str(result.error or result.stage)
                ),
                "error": result.error or None,
                "remote_password_present": True if terminal_submitted else result.remote_password_present,
                **({"login_verified": False} if terminal_submitted else {}),
                "candidate_password": password if terminal_submitted or ui_status in pending_statuses else "",
            })
        log(account_id, "纯协议补密码结束 " + json.dumps(public, ensure_ascii=False, separators=(",", ":")))
        return public
    except Exception as exc:
        err = f"{type(exc).__name__}: {exc}"
        result = {"ok": False, "status": "failed", "error": err}
        with _LOCK:
            _RESULTS[int(account_id)] = result
            _close_pending(account_id)
        db.update_account_password_setup(account_id, {"status": "failed", "message": err, "error": err})
        log(account_id, "纯协议补密码异常 " + err)
        return result
    finally:
        if session is not None:
            try:
                session.close()
            except Exception:
                pass
        with _LOCK:
            _RUNNING.discard(int(account_id))



def _bridge_and_resume(account_id: int):
    """Run the pending authorize URL through Chromium, sync cookies, then resume protocol."""
    aid = int(account_id)
    log = password_setup_service._append_log
    with _LOCK:
        pending = _PENDING.get(aid)
    if not pending:
        result = {"ok": False, "status": "expired", "error": "protocol_session_missing"}
        with _LOCK:
            _RESULTS[aid] = result
            _RUNNING.discard(aid)
        db.update_account_password_setup(aid, {"status": "expired", "message": "没有可桥接的纯协议会话"})
        return result
    session = pending["session"]
    previous = pending["result"]
    authorize_url = str(getattr(previous, "auth_url", "") or "")
    if not authorize_url:
        result = {"ok": False, "status": "failed", "error": "authorize_url_missing"}
        with _LOCK:
            _RESULTS[aid] = result
            _RUNNING.discard(aid)
        db.update_account_password_setup(aid, {"status": "failed", "message": "授权地址缺失", "error": "authorize_url_missing"})
        return result
    try:
        from core.browser_environment import follow_authorize_with_headless_browser
        log(aid, "挑战桥接开始：启动单个后台 Chromium，复用原代理、UA、设备 ID、Cookie 和 OAuth state")
        db.update_account_password_setup(aid, {"status": "running", "message": "正在完成验证页并回写协议会话"})
        account = db.get_account(aid) or {}
        setattr(session, "_recover_missing_password", not bool(db.get_registration_password(account)))
        bridge_otp_provider = password_setup_service._otp_provider(str(account.get("email_source") or "generic_api"))
        bridge_template = Path("注册日志") / "password-setup" / "password-request-template.json"
        final_url = follow_authorize_with_headless_browser(
            session, authorize_url, timeout_ms=45000,
            email=str(account.get("email") or ""),
            otp_provider=bridge_otp_provider,
            new_password=str(pending.get("password") or ""),
            template_path=bridge_template,
        )
        single_result = getattr(session, "_single_browser_password_result", None)
        if isinstance(single_result, dict):
            safe_single = {
                "ok": bool(single_result.get("ok")),
                "otp_validated": bool(single_result.get("otp_validated")),
                "submitted": bool(single_result.get("submitted")),
                "response_statuses": list(single_result.get("response_statuses") or []),
                "response_errors": list(single_result.get("response_errors") or []),
                "template_captured": bool(single_result.get("template_captured")),
            }
            log(aid, "同一浏览器事务结果 " + json.dumps(safe_single, ensure_ascii=False))
            if not single_result.get("ok"):
                # A protocol-created OAuth state can become invalid after the
                # Cloudflare bridge. Never retry that state; queue a fresh,
                # browser-owned reset transaction instead.
                response_error_text = json.dumps(
                    safe_single.get("response_errors") or [],
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).lower()
                if "invalid_state" in response_error_text:
                    result = {
                        "ok": True,
                        "status": "browser_fallback_queued",
                        "stage": "invalid_state_fallback",
                        "error": "",
                        "browser_fallback": True,
                        "details": safe_single,
                    }
                    db.update_account_password_setup(aid, {
                        "status": "queued",
                        "clear_candidate": True,
                        "remote_password_present": True,
                        "login_verified": False,
                        "message": "协议授权状态失效，正在从浏览器创建全新密码重置事务",
                        "error": None,
                    })
                    with _LOCK:
                        _RESULTS[aid] = result
                        _close_pending(aid)
                        _RUNNING.discard(aid)
                    log(aid, "密码接口返回 invalid_state；已废弃旧协议会话，转入浏览器原生重置队列")
                    queued = password_setup_service.enqueue(
                        aid,
                        trigger="protocol_invalid_state_fallback",
                        missing_only=True,
                    )
                    result["fallback_enqueue"] = {
                        key: value for key, value in queued.items()
                        if key != "future"
                    }
                    if not queued.get("accepted"):
                        result.update({
                            "ok": False,
                            "status": "browser_fallback_queue_failed",
                            "error": str(queued.get("error") or "browser_fallback_queue_failed"),
                        })
                        db.update_account_password_setup(aid, {
                            "status": "failed",
                            "message": "浏览器原生重置任务入队失败",
                            "error": result["error"],
                        })
                        log(aid, "浏览器原生重置任务入队失败：" + result["error"])
                    else:
                        log(aid, "浏览器原生重置任务已入队，将使用全新 state 完成邮箱 OTP、设密和登录验收")
                    with _LOCK:
                        _RESULTS[aid] = result
                    return result

                result = {
                    "ok": False, "status": "failed", "stage": "single_browser_password_submit",
                    "error": "single_browser_password_submit_failed",
                    "details": safe_single,
                }
                with _LOCK:
                    _RESULTS[aid] = result
                    _close_pending(aid)
                    _RUNNING.discard(aid)
                db.update_account_password_setup(aid, {
                    "status": "failed", "message": "同一浏览器事务未确认密码提交成功",
                    "error": "single_browser_password_submit_failed",
                    "login_verified": False,
                })
                return result

            candidate = str(pending.get("password") or "")
            db.update_account_password_setup(aid, {
                "status": "verifying", "candidate_password": candidate,
                "remote_password_present": True, "login_verified": False,
                "message": "同一浏览器事务已提交密码，正在使用全新协议会话验收",
            })
            log(aid, "同一浏览器已连续完成验证码与密码提交；开始全新协议登录验收")
            verification_error = ""
            try:
                method = _verify_submitted_password(account, candidate, aid)
                result = {
                    "ok": True, "status": "success", "stage": "password_login_verification",
                    "error": "", "details": {**safe_single, "password_login_verified": True, "verification_method": method},
                }
                db.update_account_password_setup(aid, {
                    "ok": True, "status": "success",
                    "message": "同一浏览器事务提交后已通过独立协议密码登录验收",
                    "error": None, "remote_password_present": True,
                    "login_verified": True, "password": candidate,
                })
                log(aid, "完成：同一浏览器事务提交的新密码已通过独立协议登录验收并转正")
            except Exception as exc:
                verification_error = f"{type(exc).__name__}: {str(exc)[:600]}"
                lowered = verification_error.lower()
                wrong_password = (
                    "密码错误" in verification_error
                    or "incorrect email address or password" in lowered
                    or "wrong password" in lowered
                )
                status = "verification_failed" if wrong_password else "verification_pending"
                result = {
                    "ok": False, "status": status, "stage": "password_login_verification",
                    "error": verification_error,
                    "details": {**safe_single, "password_login_verified": False, "submission_completed_but_login_failed": True},
                }
                db.update_account_password_setup(aid, {
                    "ok": False, "status": status,
                    "message": "密码错误，登录验收失败" if wrong_password else "密码已提交，但独立登录验收暂未完成",
                    "error": verification_error, "remote_password_present": True,
                    "login_verified": False, "candidate_password": candidate,
                })
                log(aid, "同一浏览器事务提交完成，但独立登录验收失败：" + verification_error)
            with _LOCK:
                _RESULTS[aid] = result
                _close_pending(aid)
                _RUNNING.discard(aid)
            return result
        bridge_title = str(getattr(session, "_last_bridge_title", "") or "")
        bridge_controls = list(getattr(session, "_last_bridge_controls", []) or [])
        bridge_inputs = list(getattr(session, "_last_bridge_inputs", []) or [])
        log(aid, "挑战桥接诊断 " + json.dumps({"title": bridge_title, "path": urlparse(str(final_url or authorize_url)).path, "controls": bridge_controls, "inputs": bridge_inputs}, ensure_ascii=False))
        # A challenge can keep the target path in the URL while rendering the
        # interstitial. Do not infer OTP/password readiness from the URL alone.
        challenge_markers = ("just a moment", "しばらくお待ちください", "checking your browser", "確認しています")
        if any(marker in bridge_title.lower() for marker in challenge_markers) or any(
            "cloudflare" in str(control).lower() for control in bridge_controls
        ):
            with _LOCK:
                pending["updated_at"] = time.time()
                _RESULTS[aid] = {"ok": False, "status": "needs_challenge", "stage": "challenge_bridge", "error": "challenge_still_visible"}
                _RUNNING.discard(aid)
            db.update_account_password_setup(aid, {"status": "needs_challenge", "message": "验证页仍在显示，协议会话已保留", "error": "challenge_still_visible"})
            log(aid, "挑战桥接后仍为验证页：未将 URL 路径误判为邮箱验证码页面")
            return _RESULTS[aid]
        previous.final_url = str(final_url or previous.final_url or "")
        landing_path = urlparse(str(final_url or "")).path.lower()
        if "email-verification" in landing_path:
            previous.details["bridge_landed_stage"] = "email_otp"
        elif "mfa-challenge" in landing_path:
            previous.details["bridge_landed_stage"] = "mfa_challenge"
        elif "create-account/password" in landing_path or "reset-password/password" in landing_path:
            previous.details["bridge_landed_stage"] = "new_password_form"
        elif landing_path.endswith("/log-in/password"):
            previous.details["bridge_landed_stage"] = "current_password_required"
        previous.details["challenge_bridge_attempted"] = True
        previous.details["challenge_bridge_cookie_sync"] = True
        with _LOCK:
            pending["updated_at"] = time.time()
            _RESULTS[aid] = {"ok": True, "status": "running", "stage": "challenge_bridge_complete", "bridge": True}
        log(aid, "挑战桥接完成：浏览器 Cookie 已回写，立即续跑同一协议事务")
        # _run owns final cleanup and removes the running marker.
        return _run(aid, resume=True)
    except Exception as exc:
        err = f"{type(exc).__name__}: {exc}"
        result = {"ok": False, "status": "needs_challenge", "stage": "challenge_bridge", "error": "challenge_bridge_failed", "details": {"exception": err[:240]}}
        with _LOCK:
            _RESULTS[aid] = result
            if aid in _PENDING:
                _PENDING[aid]["updated_at"] = time.time()
            _RUNNING.discard(aid)
        db.update_account_password_setup(aid, {"status": "needs_challenge", "message": "验证页桥接未完成，可再次尝试", "error": "challenge_bridge_failed"})
        log(aid, "挑战桥接异常 " + err)
        return result


def bridge_challenge(account_id: int):
    """Queue one bounded headless challenge bridge for a retained protocol session."""
    _prune_pending()
    aid = int(account_id)
    with _LOCK:
        if aid in _RUNNING:
            return {"accepted": False, "busy": True, "status": "running"}
        pending = _PENDING.get(aid)
        if not pending:
            return {"accepted": False, "missing": True, "status": "expired", "error": "protocol_session_missing"}
        _RUNNING.add(aid)
        _RESULTS[aid] = {"ok": True, "status": "queued", "stage": "challenge_bridge", "bridge": True}
    db.update_account_password_setup(aid, {"status": "queued", "message": "验证页桥接已进入队列"})
    fut = _EXECUTOR.submit(_bridge_and_resume, aid)
    return {"accepted": True, "queued": True, "status": "queued", "bridge": True, "future": fut}

def enqueue(account_id: int, password: str | None = None, reset: bool = False, *, resume: bool = False, auto_bridge: bool = False):
    _prune_pending()
    aid = int(account_id)
    with _LOCK:
        if aid in _RUNNING:
            return {"accepted": False, "busy": True, "status": "running"}
        if resume and aid not in _PENDING:
            return {"accepted": False, "missing": True, "status": "expired", "error": "protocol_session_missing"}
        if not resume:
            _close_pending(aid)
        _RUNNING.add(aid)
        _RESULTS[aid] = {"ok": True, "status": "queued", "resume": bool(resume)}
    db.update_account_password_setup(aid, {"status": "queued", "message": "已进入纯协议补密码队列"})
    fut = _EXECUTOR.submit(_run, aid, password, reset, resume)
    if auto_bridge and not resume:
        def continue_challenge(done_future):
            try:
                completed = done_future.result()
                if str((completed or {}).get("status") or "") != "needs_challenge":
                    return
                queued_bridge = bridge_challenge(aid)
                if queued_bridge.get("accepted"):
                    password_setup_service._append_log(aid, "批量任务检测到验证页，已自动启动挑战桥接并续跑")
            except Exception as exc:
                password_setup_service._append_log(aid, f"批量任务自动桥接调度失败：{type(exc).__name__}: {exc}")
        fut.add_done_callback(continue_challenge)
    return {"accepted": True, "queued": True, "status": "queued", "resume": bool(resume), "auto_bridge": bool(auto_bridge), "future": fut}


def get_status(account_id: int) -> dict:
    _prune_pending()
    aid = int(account_id)
    with _LOCK:
        value = dict(_RESULTS.get(aid) or {})
        value.setdefault("status", "running" if aid in _RUNNING else "idle")
        value["running"] = aid in _RUNNING
        value["resumable"] = aid in _PENDING
        if aid in _PENDING:
            value["expires_in"] = max(0, int(_PENDING_TTL - (time.time() - _PENDING[aid]["updated_at"])))
    return value


def cancel(account_id: int) -> dict:
    aid = int(account_id)
    with _LOCK:
        if aid in _RUNNING:
            return {"ok": False, "busy": True, "status": "running"}
        existed = aid in _PENDING
        _close_pending(aid)
        _RESULTS[aid] = {"ok": True, "status": "cancelled"}
    db.update_account_password_setup(aid, {"status": "cancelled", "message": "纯协议挂起会话已释放"})
    return {"ok": True, "cancelled": existed, "status": "cancelled"}


def is_running(account_id: int) -> bool:
    with _LOCK:
        return int(account_id) in _RUNNING


