# -*- coding: utf-8 -*-
"""账号 2FA/TOTP 后台设置队列。"""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from config import email as _email_cfg
from config import twofa as _twofa_cfg
from core import db
from core.account_export import setup_2fa
from core.session import BrowserSession

logger = logging.getLogger(__name__)


def _int_setting(name: str, default: int, lower: int, upper: int) -> int:
    try:
        value = int(getattr(_twofa_cfg, name, default) or default)
    except (TypeError, ValueError):
        value = default
    return max(lower, min(upper, value))


_WORKERS = _int_setting("TWOFA_WORKERS", 4, 1, 16)
_QUEUE_LIMIT = _int_setting("TWOFA_QUEUE_LIMIT", 200, _WORKERS, 5000)
_EXECUTOR = ThreadPoolExecutor(max_workers=_WORKERS, thread_name_prefix="twofa")
_QUEUE_SLOTS = threading.BoundedSemaphore(_QUEUE_LIMIT)
_RUNNING: set[int] = set()
_LOCK = threading.Lock()
_LOG_DIR = Path(__file__).resolve().parent.parent / "注册日志"


def log_path(email: str) -> Path:
    safe = str(email or "").replace("/", "_").replace("\\", "_").replace(":", "_")
    return _LOG_DIR / f"twofa-{safe}.log"


def _normalize_proxy(proxy: str | None) -> str | None:
    """
    2FA 入口标准化并刷新代理地址，确保轮换新鲜动态会话 SID。
    """
    text = str(proxy or "").strip()
    from core.chatgpt_plan import rotate_proxy_session
    from config import proxy as _proxy_cfg
    if not text or not text.lower().startswith(("http://", "https://", "socks5://", "socks5h://", "socks4://", "socks4a://")):
        text = str(_proxy_cfg.pick_proxy() or "").strip()
    if text:
        rotated, _ = rotate_proxy_session(text)
        return rotated
    return None


def is_running(acc_id: int) -> bool:
    with _LOCK:
        return int(acc_id) in _RUNNING


def _append_log(email: str, line: str, *, clear: bool = False) -> None:
    p = log_path(email)
    p.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%H:%M:%S")
    mode = "w" if clear else "a"
    with p.open(mode, encoding="utf-8") as f:
        f.write(f"{stamp} [INFO] {line}\n")


def _run_twofa(
    *, account_id: int, email: str, access_token: str, proxy: str | None,
    trigger: str,
) -> dict:
    fh: logging.FileHandler | None = None
    session: BrowserSession | None = None
    root_logger = logging.getLogger()
    thread_name = threading.current_thread().name
    try:
        with _LOCK:
            _RUNNING.add(int(account_id))
        if not db.mark_account_totp_setup_running(account_id):
            return {"ok": False, "status": "failed", "error": "账号已删除或 2FA 状态已被重置"}
        log_file = log_path(email)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        log_file.write_text("", encoding="utf-8")
        fh = logging.FileHandler(str(log_path(email)), encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"))
        fh.addFilter(lambda record: record.threadName == thread_name)
        root_logger.addHandler(fh)
        logger.info("[2FA] 开始后台设置：email=%s trigger=%s", email, trigger)
        real_proxy = _normalize_proxy(proxy)
        identity = email.strip().lower()
        import importlib
        import core.browser_environment
        import core.account_export
        importlib.reload(core.browser_environment)
        importlib.reload(core.account_export)
        secret = None
        for attempt in range(1, 3):
            try:
                session = BrowserSession(proxy=real_proxy, fingerprint_seed=f"account:{identity}")
                _append_log(email, f"[2FA] 会话创建完成(尝试 {attempt}/2)：proxy={session.proxy or 'direct'} device_id={session.device_id}")
                _append_log(email, f"[2FA] 指纹摘要：{session.fingerprint_summary_text()}")
                secret = core.account_export.setup_2fa(session, email, access_token=access_token)
                break
            except Exception as exc:
                err_text = str(exc).lower()
                is_net_err = any(k in err_text for k in ("tunnel", "proxy", "connect", "403", "reset", "closed", "aborted"))
                candidate = bool((db.get_account(account_id) or {}).get("totp_setup_candidate_secret"))
                if attempt < 2 and is_net_err and not candidate:
                    from config import proxy as _proxy_cfg
                    real_proxy = _normalize_proxy(_proxy_cfg.pick_proxy())
                    _append_log(email, f"[2FA] 代理异常({exc})，自动切换代理池新节点重试(2/2)...")
                    logger.warning("[2FA] 代理异常(%s)，切换代理池新节点重试...", exc)
                    time.sleep(2)
                    continue
                raise
        db.update_account_totp_secret(
            account_id,
            {"ok": True, "status": "success", "totp_secret": secret, "message": "2FA 设置完成"},
        )
        _append_log(email, f"[2FA] 完成：secret={secret[:4]}...{secret[-4:]}")
        logger.info("[2FA] 完成：email=%s secret=%s...%s", email, secret[:4], secret[-4:])
        return {"ok": True, "status": "success", "totp_secret": secret, "message": "2FA 设置完成"}
    except Exception as exc:
        remote_enabled = type(exc).__name__ == "RemoteMfaAlreadyEnabledError"
        candidate = bool((db.get_account(account_id) or {}).get("totp_setup_candidate_secret"))
        result = {
            "ok": False,
            "status": "activation_unknown" if candidate else ("remote_enabled" if remote_enabled else "failed"),
            "error": f"{type(exc).__name__}: {str(exc)[:500]}",
            "message": ("候选密钥已保留，激活结果待核验" if candidate else
                        "远端存在 2FA 因子，本地缺少原始密钥" if remote_enabled else None),
        }
        try:
            db.update_account_totp_secret(account_id, result)
        except Exception:
            logger.exception("[2FA] 写回失败状态失败: account_id=%s", account_id)
        try:
            _append_log(email, f"[2FA] 失败：{result['error']}")
        except Exception:
            pass
        logger.exception("[2FA] 后台异常: %s", email)
        return result
    finally:
        if session is not None:
            try:
                session.session.close()
            except Exception:
                pass
        if fh is not None:
            try:
                root_logger.removeHandler(fh)
                fh.close()
            except Exception:
                pass
        with _LOCK:
            _RUNNING.discard(int(account_id))
        try:
            _QUEUE_SLOTS.release()
        except ValueError:
            pass


def queue_settings() -> dict:
    with _LOCK:
        running = len(_RUNNING)
    return {
        "workers": _WORKERS,
        "queue_limit": _QUEUE_LIMIT,
        "running": running,
    }


def enqueue_account_totp_setup(
    *,
    account_id: int,
    email: str,
    access_token: str,
    trigger: str = "manual",
    proxy: str | None = None,
) -> dict:
    account_id = int(account_id)
    email = str(email or "").strip()
    access_token = str(access_token or "").strip()
    if not email:
        return {"accepted": False, "busy": False, "error": "email 为空"}
    if not access_token:
        return {"accepted": False, "busy": False, "error": "缺少 access_token"}
    if not bool(getattr(_email_cfg, "USE_EMAIL_SERVICE", False)):
        return {"accepted": False, "busy": False, "error": "启用 2FA 需要先开启 USE_EMAIL_SERVICE 自动收取邮箱验证码"}
    if not _QUEUE_SLOTS.acquire(blocking=False):
        return {"accepted": False, "busy": False, "queue_full": True, "error": "2FA 队列已满，请稍后重试"}
    if not db.claim_account_totp_setup(acc_id=account_id, trigger=trigger):
        _QUEUE_SLOTS.release()
        return {"accepted": False, "busy": True, "error": "该账号正在设置 2FA"}

    _append_log(email, f"[2FA] 已入队 account_id={account_id} trigger={trigger}", clear=True)
    try:
        future = _EXECUTOR.submit(
            _run_twofa,
            account_id=account_id,
            email=email,
            access_token=access_token,
            proxy=proxy,
            trigger=str(trigger or "manual"),
        )
        return {"accepted": True, "busy": False, "future": future, "log_path": str(log_path(email))}
    except Exception as exc:
        _QUEUE_SLOTS.release()
        db.update_account_totp_secret(account_id, {"ok": False, "status": "failed", "error": f"{type(exc).__name__}: {exc}"})
        return {"accepted": False, "busy": False, "error": f"{type(exc).__name__}: {exc}"}
