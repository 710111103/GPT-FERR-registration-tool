# -*- coding: utf-8 -*-
"""已有 TOTP 账号的密钥轮换后台任务。"""
from __future__ import annotations

import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from core import db
from core.account_export import _activate_totp, _enroll_totp
from core.account_liveness import TotpVerificationRejectedError, _login_via_reauth
from core.session import BrowserSession
from core.twofa_service import _normalize_proxy, log_path

logger = logging.getLogger(__name__)

_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="twofa-rotate")
_QUEUE_SLOTS = threading.BoundedSemaphore(100)
_RUNNING: set[int] = set()
_LOCK = threading.Lock()


def _append_log(email: str, line: str, *, clear: bool = False) -> None:
    path = log_path(email)
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%H:%M:%S")
    with path.open("w" if clear else "a", encoding="utf-8") as handle:
        handle.write(f"{stamp} [INFO] {line}\n")


def _password_from_account(account: dict) -> str:
    """仅返回已通过独立登录验收的账号密码。"""
    return db.get_registration_password(account)


def _close_session(session: BrowserSession | None) -> None:
    if session is None:
        return
    try:
        session.session.close()
    except Exception:
        pass


def _login_with_secret(email: str, email_source: str, proxy: str | None, secret: str, label: str) -> dict:
    session = BrowserSession(proxy=proxy, fingerprint_seed=f"account:{email.strip().lower()}:{label}")
    try:
        return _login_via_reauth(
            session,
            email,
            time.time(),
            email_source=email_source,
            totp_secret_override=secret,
        )
    finally:
        _close_session(session)


def _verify_rotation_pair(
    *, email: str, email_source: str, proxy: str | None,
    old_secret: str, candidate_secret: str,
) -> tuple[dict, bool]:
    """新密钥必须登录成功；旧密钥必须被服务端明确拒绝。"""

    def verify_new() -> dict:
        return _login_with_secret(email, email_source, proxy, candidate_secret, "totp-new-check")

    def verify_old_rejected() -> bool:
        # 跨过旧验证码最后使用的时间片，避免服务端重放保护造成误判。
        wait_seconds = max(0.0, (int(time.time() // 30) + 1) * 30 + 1 - time.time())
        if wait_seconds:
            time.sleep(wait_seconds)
        try:
            _login_with_secret(email, email_source, proxy, old_secret, "totp-old-check")
        except TotpVerificationRejectedError:
            return True
        raise RuntimeError("旧 TOTP 密钥仍被服务端接受")

    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="twofa-verify") as pool:
        new_future = pool.submit(verify_new)
        old_future = pool.submit(verify_old_rejected)
        new_session_data = new_future.result()
        old_rejected = old_future.result()
    if not str((new_session_data or {}).get("accessToken") or "").strip():
        raise RuntimeError("新 TOTP 登录成功但未返回 accessToken")
    return new_session_data, old_rejected


def _recover_candidate(
    *, email: str, email_source: str, proxy: str | None,
    old_secret: str, candidate_secret: str,
) -> tuple[str, dict]:
    """判定中断候选密钥当前处于已激活还是未激活状态。"""
    try:
        candidate_data = _login_with_secret(
            email, email_source, proxy, candidate_secret, "totp-candidate-recovery",
        )
    except TotpVerificationRejectedError:
        old_data = _login_with_secret(
            email, email_source, proxy, old_secret, "totp-old-recovery",
        )
        return "old", old_data

    wait_seconds = max(0.0, (int(time.time() // 30) + 1) * 30 + 1 - time.time())
    if wait_seconds:
        time.sleep(wait_seconds)
    try:
        _login_with_secret(email, email_source, proxy, old_secret, "totp-old-recovery-check")
    except TotpVerificationRejectedError:
        return "candidate", candidate_data
    raise RuntimeError("候选密钥可用，但旧 TOTP 密钥仍被服务端接受")


def _run_rotation(*, account_id: int, trigger: str) -> dict:
    account = db.get_account(account_id) or {}
    email = str(account.get("email") or "").strip()
    session: BrowserSession | None = None
    candidate = str(account.get("totp_rotation_candidate_secret") or "").strip()
    root_logger = logging.getLogger()
    handler: logging.FileHandler | None = None
    thread_name = threading.current_thread().name
    try:
        with _LOCK:
            _RUNNING.add(account_id)
        if not db.mark_account_totp_rotation_running(account_id):
            raise RuntimeError("账号已删除或轮换状态已重置")
        old_secret = str(account.get("totp_secret") or "").strip()
        if not old_secret or not _password_from_account(account):
            raise RuntimeError("更换 2FA 需要已保存的登录密码和旧 TOTP 密钥")

        _append_log(email, f"[2FA更换] 开始：account_id={account_id} trigger={trigger}", clear=True)
        handler = logging.FileHandler(str(log_path(email)), encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"))
        handler.addFilter(lambda record: record.threadName == thread_name)
        root_logger.addHandler(handler)

        proxy = _normalize_proxy(str(account.get("proxy_used") or "") or None)
        email_source = str(account.get("email_source") or "generic_api")
        if candidate:
            _append_log(email, f"[2FA更换] 检测到中断候选密钥，先恢复核验：{candidate[:4]}...{candidate[-4:]}")
            recovery_mode, recovery_data = _recover_candidate(
                email=email, email_source=email_source, proxy=proxy,
                old_secret=old_secret, candidate_secret=candidate,
            )
            if recovery_mode == "candidate":
                db.update_account_totp_rotation(account_id, {
                    "ok": True, "status": "success", "totp_secret": candidate,
                    "message": "已恢复中断的 2FA 更换；候选密钥有效且旧密钥已失效",
                })
                _append_log(email, "[2FA更换] 中断恢复完成：候选密钥已写回")
                return {"ok": True, "status": "success", "access_token": recovery_data.get("accessToken")}
            db.update_account_totp_rotation(account_id, {
                "status": "running", "clear_candidate": True,
                "message": "候选密钥未激活且旧密钥仍有效，重新发起轮换",
            })
            _append_log(email, "[2FA更换] 候选密钥未激活，旧密钥有效；已清理候选记录并重新轮换")
            candidate = ""
        _append_log(email, "[2FA更换] 使用旧密钥完成密码+TOTP 重认证")
        session = BrowserSession(proxy=proxy, fingerprint_seed=f"account:{email.lower()}:totp-rotate")
        login_data = _login_via_reauth(
            session, email, time.time(), email_source=email_source,
            totp_secret_override=old_secret,
        )
        access_token = str((login_data or {}).get("accessToken") or "").strip()
        if not access_token:
            raise RuntimeError("重认证完成但未取得 accessToken")

        candidate, session_id = _enroll_totp(session, access_token)
        if not candidate or not session_id or candidate.replace("=", "").upper() == old_secret.replace("=", "").upper():
            raise RuntimeError("服务端返回的候选密钥无效")
        db.update_account_totp_rotation(account_id, {
            "status": "prepared", "candidate_secret": candidate,
            "message": "候选密钥已持久化，准备激活",
        })
        _append_log(email, f"[2FA更换] 候选密钥已持久化：{candidate[:4]}...{candidate[-4:]}")
        _activate_totp(session, access_token, candidate, session_id)
        db.update_account_totp_rotation(account_id, {
            "status": "verifying", "candidate_secret": candidate,
            "message": "已激活候选密钥，正在验证新密钥可用且旧密钥失效",
        })
        _close_session(session)
        session = None

        new_session_data, old_rejected = _verify_rotation_pair(
            email=email, email_source=email_source, proxy=proxy,
            old_secret=old_secret, candidate_secret=candidate,
        )
        if not old_rejected:
            raise RuntimeError("旧 TOTP 密钥拒绝状态未确认")
        db.update_account_totp_rotation(account_id, {
            "ok": True, "status": "success", "totp_secret": candidate,
            "message": "2FA 密钥更换完成；新密钥登录验证成功，旧密钥已失效",
        })
        _append_log(email, "[2FA更换] 完成：新密钥已写回，旧密钥已被服务端拒绝")
        return {"ok": True, "status": "success", "access_token": new_session_data.get("accessToken")}
    except Exception as exc:
        error = f"{type(exc).__name__}: {str(exc)[:500]}"
        db.update_account_totp_rotation(account_id, {
            "ok": False, "status": "failed", "candidate_secret": candidate,
            "error": error,
            "message": "更换未完成；本地仍保留原密钥，候选密钥已留存供核验" if candidate else "更换未完成；本地原密钥保持不变",
        })
        if email:
            _append_log(email, f"[2FA更换] 失败：{error}")
        logger.exception("[2FA更换] 后台异常：%s", email or account_id)
        return {"ok": False, "status": "failed", "error": error}
    finally:
        _close_session(session)
        if handler is not None:
            try:
                root_logger.removeHandler(handler)
                handler.close()
            except Exception:
                pass
        with _LOCK:
            _RUNNING.discard(account_id)
        try:
            _QUEUE_SLOTS.release()
        except ValueError:
            pass


def enqueue_account_totp_rotation(*, account_id: int, trigger: str = "manual") -> dict:
    account_id = int(account_id)
    account = db.get_account(account_id)
    if not account:
        return {"accepted": False, "error": "账号不存在"}
    if not str(account.get("totp_secret") or "").strip():
        return {"accepted": False, "error": "本地缺少旧 TOTP 密钥"}
    if not _password_from_account(account):
        return {"accepted": False, "error": "本地缺少登录密码"}
    if not _QUEUE_SLOTS.acquire(blocking=False):
        return {"accepted": False, "queue_full": True, "error": "2FA 更换队列已满"}
    if not db.claim_account_totp_rotation(account_id, trigger=trigger):
        _QUEUE_SLOTS.release()
        return {"accepted": False, "busy": True, "error": "该账号正在执行 2FA 操作"}
    try:
        future = _EXECUTOR.submit(_run_rotation, account_id=account_id, trigger=trigger)
        return {"accepted": True, "future": future, "log_path": str(log_path(str(account.get("email") or "")))}
    except Exception as exc:
        _QUEUE_SLOTS.release()
        db.update_account_totp_rotation(account_id, {"status": "failed", "error": f"{type(exc).__name__}: {exc}"})
        return {"accepted": False, "error": f"{type(exc).__name__}: {exc}"}


