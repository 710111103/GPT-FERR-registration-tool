# -*- coding: utf-8 -*-
"""真正修改远端登录密码，并在全新浏览器中重新登录验收。"""
from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from core import db
from core.antbrowser_driver import build_ant_driver, cleanup_ant_profile
from core.openai_auth import generate_registration_password
from core.password_setup_service import (
    _append_log as _unused_setup_log,
    _fill_email_and_otp,
    _fresh_proxy,
    _otp_provider,
    _open_password_reauth_with_proxy_rotation,
    _start_add_password_flow,
    _submit_new_password,
    _verify_password_login,
)

logger = logging.getLogger(__name__)
_EXECUTOR = ThreadPoolExecutor(max_workers=1, thread_name_prefix="password-change")
_QUEUE = threading.BoundedSemaphore(30)
_RUNNING: set[int] = set()
_QUEUED: set[int] = set()
_LOCK = threading.Lock()


def log_path(account_id: int) -> Path:
    return Path("注册日志") / "password-change" / f"account-{int(account_id)}.log"


def _append_log(account_id: int, line: str, *, clear: bool = False) -> None:
    path = log_path(account_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%H:%M:%S")
    with path.open("w" if clear else "a", encoding="utf-8") as handle:
        handle.write(f"{stamp} [INFO] {line}\n")


def is_running(account_id: int) -> bool:
    with _LOCK:
        return int(account_id) in _RUNNING or int(account_id) in _QUEUED


def _validate_new_password(password: str, old_password: str) -> str:
    value = str(password or "").strip()
    if not value:
        value = generate_registration_password()
    if len(value) < 12:
        raise ValueError("新密码至少 12 个字符")
    if value == old_password:
        raise ValueError("新密码不能与当前密码相同")
    return value


def _run(account_id: int, new_password: str, trigger: str) -> dict:
    driver = opened = None
    account = db.get_account(account_id) or {}
    email = str(account.get("email") or "").strip()
    try:
        with _LOCK:
            _QUEUED.discard(account_id)
            _RUNNING.add(account_id)
        db.update_account_password_change(account_id, {
            "status": "running", "message": "正在通过邮箱验证修改远端密码",
        })
        _append_log(account_id, f"开始远端改密：{email} trigger={trigger}", clear=True)
        driver, opened, auth_url = _open_password_reauth_with_proxy_rotation(
            account, reset=True, attempts=2,
            on_retry=lambda next_attempt, total, exc: _append_log(
                account_id,
                f"代理连接中断，已自动更换代理并创建全新浏览器会话 {next_attempt}/{total}: "
                f"{type(exc).__name__}: {str(exc)[:180]}",
            ),
        )
        _append_log(account_id, "已取得 post_login_password_reset 重认证地址")
        _fill_email_and_otp(
            driver, email,
            _otp_provider(str(account.get("email_source") or "generic_api")),
            auth_url,
        )
        _append_log(account_id, "邮箱 OTP / 2FA 重认证完成，已进入新密码表单")
        _submit_new_password(driver, new_password, reset=True, email=email, otp_provider=_otp_provider(str(account.get("email_source") or "generic_api")))
        db.update_account_password_change(account_id, {
            "status": "verifying", "login_verified": False,
            "message": "远端已提交，正在全新浏览器重新登录验收",
        })
        _append_log(account_id, "新密码已提交；关闭当前会话并启动全新浏览器验收")
        try:
            driver.quit()
        except Exception:
            pass
        driver = None
        cleanup_ant_profile(opened)
        opened = None

        session = _verify_password_login(account, new_password)
        if not db.update_account_password_change(account_id, {
            "ok": True, "status": "success", "password": new_password,
            "login_verified": True,
            "message": "远端改密成功，新密码已通过全新浏览器登录验收",
        }):
            raise RuntimeError("新密码验收成功，但账号记录写回失败")
        _append_log(account_id, "完成：新密码登录成功，已原子替换本地正式密码")
        return {"ok": True, "status": "success", "session": session}
    except Exception as exc:
        error = f"{type(exc).__name__}: {str(exc)[:700]}"
        db.update_account_password_change(account_id, {
            "ok": False, "status": "verification_failed" if "验收" in error or "登录" in error else "failed",
            "login_verified": False, "error": error,
            "message": "改密未通过验收，已保留原有已验证密码",
        })
        _append_log(account_id, f"失败：{error}；原密码记录未被覆盖")
        logger.exception("[远端改密] %s", email or account_id)
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


def enqueue(account_id: int, new_password: str | None = None, trigger: str = "manual") -> dict:
    account_id = int(account_id)
    account = db.get_account(account_id)
    if not account:
        return {"accepted": False, "error": "账号不存在"}
    # 远端已有密码但本地密码错误时，改密本来就应走 password-reset + 邮箱 OTP，
    # 不要求旧密码先通过本地验收；旧候选只用于避免生成完全相同的新密码。
    old_password = db.get_registration_password(account)
    compare_password = old_password or str(account.get("password_setup_candidate") or account.get("password") or "").strip()
    if not old_password and not bool(account.get("password_setup_remote_password_present")):
        return {"accepted": False, "error": "远端尚未确认存在密码，请先执行补设密码"}
    try:
        candidate = _validate_new_password(str(new_password or ""), compare_password)
    except ValueError as exc:
        return {"accepted": False, "error": str(exc)}
    if not _QUEUE.acquire(blocking=False):
        return {"accepted": False, "queue_full": True, "error": "改密队列已满"}
    with _LOCK:
        if account_id in _QUEUED or account_id in _RUNNING:
            _QUEUE.release()
            return {"accepted": False, "busy": True, "error": "该账号正在改密"}
        if not db.claim_account_password_change(account_id, candidate, trigger):
            _QUEUE.release()
            return {"accepted": False, "busy": True, "error": "该账号已有改密任务"}
        _QUEUED.add(account_id)
    try:
        future = _EXECUTOR.submit(_run, account_id, candidate, trigger)
        return {"accepted": True, "future": future, "log_path": str(log_path(account_id)), "generated": not bool(str(new_password or "").strip())}
    except Exception as exc:
        with _LOCK:
            _QUEUED.discard(account_id)
        _QUEUE.release()
        db.update_account_password_change(account_id, {"status": "failed", "error": str(exc)})
        return {"accepted": False, "error": f"{type(exc).__name__}: {exc}"}

