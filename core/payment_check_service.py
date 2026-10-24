# -*- coding: utf-8 -*-
"""账号支付方式/账单/订阅只读查询后台队列。

结构与 core/plan_check_service.py 保持一致：统一线程池 + 队列上限 + 请求错峰 +
账号级占用标记，避免批量查询把同一账号重复入队或集中打到 ChatGPT。
"""
from __future__ import annotations

import logging
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from config import proxy as proxy_cfg
from core import db
from core.payment_info import check_account_payment_profile

logger = logging.getLogger(__name__)


def _int_setting(name: str, default: int, lower: int, upper: int) -> int:
    try:
        value = int(getattr(proxy_cfg, name, default) or default)
    except (TypeError, ValueError):
        value = default
    return max(lower, min(upper, value))


def _float_setting(name: str, default: float, lower: float, upper: float) -> float:
    try:
        value = float(getattr(proxy_cfg, name, default) or 0.0)
    except (TypeError, ValueError):
        value = default
    return max(lower, min(upper, value))


_WORKERS = _int_setting("PAYMENT_CHECK_WORKERS", 3, 1, 16)
_QUEUE_LIMIT = _int_setting("PAYMENT_CHECK_QUEUE_LIMIT", 500, _WORKERS, 5000)
_EXECUTOR = ThreadPoolExecutor(max_workers=_WORKERS, thread_name_prefix="payment-check")
_QUEUE_SLOTS = threading.BoundedSemaphore(_QUEUE_LIMIT)
_RATE_LOCK = threading.Lock()
_NEXT_REQUEST_AT = 0.0


def _wait_for_rate_slot() -> None:
    """为所有查询线程分配错开的请求启动时间。"""
    global _NEXT_REQUEST_AT
    min_interval = _float_setting("PAYMENT_CHECK_MIN_INTERVAL", 0.4, 0.0, 30.0)
    jitter = _float_setting("PAYMENT_CHECK_JITTER", 0.3, 0.0, 30.0)
    with _RATE_LOCK:
        now = time.monotonic()
        scheduled = max(now, _NEXT_REQUEST_AT) + (random.uniform(0.0, jitter) if jitter else 0.0)
        _NEXT_REQUEST_AT = scheduled + min_interval
    wait_seconds = scheduled - now
    if wait_seconds > 0:
        time.sleep(wait_seconds)


def _run_payment_check(
    *, account_id: int, email: str, access_token: str, trigger: str, proxy: str | None,
) -> dict:
    try:
        if not db.mark_account_payment_check_running(account_id):
            return {"ok": False, "error": "账号已删除或支付查询状态已被重置"}

        _wait_for_rate_slot()
        result = check_account_payment_profile(access_token, proxy=proxy)
        db.update_account_payment_check(acc_id=account_id, result=result)
        if result.get("ok"):
            logger.info(
                "[Payment] 后台查询成功: %s, 支付方式=%s, 支付档案=%s, trigger=%s",
                email,
                result.get("payment_methods_text") or "未绑卡",
                bool(result.get("has_customer_object")),
                trigger,
            )
        else:
            logger.warning(
                "[Payment] 后台查询失败: %s, trigger=%s, error=%s",
                email, trigger, result.get("error") or "未知错误",
            )
        return result
    except Exception as exc:
        result = {
            "ok": False,
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "error": f"{type(exc).__name__}: {str(exc)[:180]}",
        }
        try:
            db.update_account_payment_check(acc_id=account_id, result=result)
        except Exception:
            logger.exception("[Payment] 写入后台查询异常状态失败: account_id=%s", account_id)
        logger.exception("[Payment] 后台查询异常: %s", email)
        return result
    finally:
        _QUEUE_SLOTS.release()


def enqueue_account_payment_check(
    *, account_id: int, email: str, access_token: str, trigger: str, proxy: str | None = None,
) -> dict:
    """把查询放入统一线程池；重复查询或队列满时不提交。"""
    account_id = int(account_id)
    email = str(email or "").strip()
    access_token = str(access_token or "").strip()
    if not access_token:
        return {"accepted": False, "busy": False, "error": "账号缺少 access_token"}
    if not _QUEUE_SLOTS.acquire(blocking=False):
        return {"accepted": False, "busy": False, "queue_full": True, "error": "支付查询队列已满，请稍后重试"}

    if not db.claim_account_payment_check(acc_id=account_id, trigger=trigger):
        _QUEUE_SLOTS.release()
        return {"accepted": False, "busy": True, "error": "该账号正在查询支付方式"}

    try:
        _EXECUTOR.submit(
            _run_payment_check,
            account_id=account_id,
            email=email,
            access_token=access_token,
            trigger=str(trigger or "manual"),
            proxy=proxy,
        )
    except Exception as exc:
        _QUEUE_SLOTS.release()
        result = {
            "ok": False,
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "error": f"支付查询入队失败: {type(exc).__name__}: {str(exc)[:160]}",
        }
        db.update_account_payment_check(acc_id=account_id, result=result)
        return {"accepted": False, "busy": False, "error": result["error"]}

    return {
        "accepted": True,
        "busy": False,
        "account_id": account_id,
        "email": email,
        "status": "queued",
        "trigger": str(trigger or "manual"),
    }


def queue_settings() -> dict:
    return {
        "workers": _WORKERS,
        "queue_limit": _QUEUE_LIMIT,
        "min_interval": _float_setting("PAYMENT_CHECK_MIN_INTERVAL", 0.4, 0.0, 30.0),
        "jitter": _float_setting("PAYMENT_CHECK_JITTER", 0.3, 0.0, 30.0),
    }
