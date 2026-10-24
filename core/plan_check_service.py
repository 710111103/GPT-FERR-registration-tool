# -*- coding: utf-8 -*-
"""套餐/Plus 资格查询后台队列。"""
from __future__ import annotations

import logging
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

from config import proxy as proxy_cfg
from core import db
from core.chatgpt_plan import check_account_plan, check_account_plan_regions
from core.task_observability import ProbeSession

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


_WORKERS = _int_setting("PLAN_CHECK_WORKERS", 8, 1, 30)
_QUEUE_LIMIT = _int_setting("PLAN_CHECK_QUEUE_LIMIT", 500, _WORKERS, 5000)
_EXECUTOR = ThreadPoolExecutor(max_workers=_WORKERS, thread_name_prefix="plan-check")
_QUEUE_SLOTS = threading.BoundedSemaphore(_QUEUE_LIMIT)
_RATE_LOCK = threading.Lock()
_NEXT_REQUEST_AT = 0.0
_SCHEDULER_LOCK = threading.Lock()
_SCHEDULER_STARTED = False


def _parse_timestamp(value: object) -> datetime | None:
    text = str(value or "").strip().replace("Z", "+00:00")
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text)
        return parsed.replace(tzinfo=None) if parsed.tzinfo else parsed
    except ValueError:
        return None


def enqueue_due_account_status_checks(now: datetime | None = None) -> dict:
    """Queue stale accounts for a lightweight token/plan health check."""
    try:
        interval = int(getattr(proxy_cfg, "ACCOUNT_STATUS_CHECK_INTERVAL_MINUTES", 360))
    except (TypeError, ValueError):
        interval = 360
    interval = max(0, min(10080, interval))
    batch_size = _int_setting("ACCOUNT_STATUS_CHECK_BATCH_SIZE", 10, 1, 200)
    if interval <= 0:
        return {"enabled": False, "queued": 0}

    reference_now = now or datetime.now()
    cutoff = reference_now - timedelta(minutes=interval)
    queued = 0
    scanned = 0
    for account in db.list_accounts(limit=5000, archived=False):
        scanned += 1
        recovered_orphan = False
        if queued >= batch_size:
            break
        if str(account.get("plan_check_status") or "") in {"queued", "running"}:
            status = str(account.get("plan_check_status") or "")
            stamp = _parse_timestamp(account.get("plan_check_queued_at") if status == "queued" else account.get("plan_check_started_at"))
            age_seconds = (reference_now - stamp).total_seconds() if stamp else 0
            stale_after = 90 if status == "queued" else 180
            if age_seconds < stale_after:
                continue
            logger.warning(
                "[AccountStatus] 发现孤儿套餐任务，自动恢复后重新入队: account_id=%s status=%s age=%.0fs",
                account.get("id"), status, age_seconds,
            )
            db.update_account_plan_check(acc_id=int(account.get("id") or 0), result={
                "ok": False,
                "checked_at": datetime.now().isoformat(timespec="seconds"),
                "error": f"套餐查询任务超过 {stale_after} 秒未推进，已自动恢复",
            })
            recovered_orphan = True
        if str(account.get("live_check_status") or "") in {"queued", "running"}:
            continue
        checked_at = _parse_timestamp(account.get("plan_checked_at"))
        if not recovered_orphan and checked_at is not None and checked_at > cutoff:
            continue
        result = enqueue_account_plan_check(
            account_id=int(account.get("id") or 0),
            email=str(account.get("email") or ""),
            access_token=str(account.get("access_token") or ""),
            trigger="account_status_periodic",
        )
        if result.get("accepted"):
            queued += 1
    return {"enabled": True, "queued": queued, "scanned": scanned, "interval_minutes": interval}


def start_account_status_scheduler() -> bool:
    """Start one daemon scheduler for periodic lightweight account checks."""
    global _SCHEDULER_STARTED
    with _SCHEDULER_LOCK:
        if _SCHEDULER_STARTED:
            return False
        _SCHEDULER_STARTED = True

    def _loop() -> None:
        while True:
            try:
                from core import live_check_service

                live_summary = live_check_service.enqueue_due_account_live_checks()
                if live_summary.get("queued"):
                    logger.info("[AccountStatus] 定时测活已入队 %s 个账号", live_summary["queued"])

                plan_summary = enqueue_due_account_status_checks()
                if plan_summary.get("queued"):
                    logger.info("[AccountStatus] 定时资格刷新已入队 %s 个账号", plan_summary["queued"])
            except Exception:
                logger.exception("[AccountStatus] 定时巡检调度失败")
            time.sleep(60)

    threading.Thread(target=_loop, name="account-status-scheduler", daemon=True).start()
    return True


def _wait_for_rate_slot() -> None:
    """为所有查询线程分配错开的请求启动时间。"""
    global _NEXT_REQUEST_AT
    min_interval = _float_setting("PLAN_CHECK_MIN_INTERVAL", 0.4, 0.0, 30.0)
    jitter = _float_setting("PLAN_CHECK_JITTER", 0.3, 0.0, 30.0)
    with _RATE_LOCK:
        now = time.monotonic()
        scheduled = max(now, _NEXT_REQUEST_AT) + (random.uniform(0.0, jitter) if jitter else 0.0)
        _NEXT_REQUEST_AT = scheduled + min_interval
    wait_seconds = scheduled - now
    if wait_seconds > 0:
        time.sleep(wait_seconds)



def _queue_auth_refresh_if_needed(*, account_id: int, email: str, trigger: str, result: dict) -> dict | None:
    """Queue one AT refresh only for explicit authentication-expiry results."""
    auth_expired = (
        not bool(result.get("ok"))
        and (
            result.get("needs_live_check") is True
            or result.get("token_expired") is True
            or int(result.get("http_status") or 0) == 401
        )
    )
    if not auth_expired or trigger == "live_check_refresh":
        return None
    from core import live_check_service
    return live_check_service.enqueue_account_live_check(
        account_id=account_id,
        email=email,
        trigger="plan_401_auto_refresh",
        proxy=None,
    )

def _registration_recheck_delay() -> float:
    return _float_setting("PLAN_CHECK_REGISTRATION_RECHECK_DELAY", 2.0, 0.0, 30.0)


def _run_plan_check(
    *,
    account_id: int,
    email: str,
    access_token: str,
    trigger: str,
    proxy: str | None,
    timezone_offset_min: str,
    multi_region: bool = False,
) -> dict:
    result: dict = {}
    probe: ProbeSession | None = None
    probe_context = None
    probe_active = False
    try:
        probe = ProbeSession("plan_check", account_id, email=email, trigger=trigger, multi_region=multi_region)
        probe_context = probe.activate()
        probe_context.__enter__()
        probe_active = True
        probe.mark("worker", "started")
        if not db.mark_account_plan_check_running(account_id):
            result = {"ok": False, "error": "账号已删除或套餐查询状态已被重置"}
            probe.mark("claim", "failed", error=result["error"])
            return result
        probe.mark("claim", "ok")

        _wait_for_rate_slot()
        probe.mark("plan_query", "started")
        result = (check_account_plan_regions(access_token) if multi_region else check_account_plan(
            access_token, proxy=proxy, timezone_offset_min=timezone_offset_min,
        ))
        probe.mark(
            "plan_query", "ok" if result.get("ok") else "failed",
            error=None if result.get("ok") else result.get("error"),
            current_plan_type=result.get("current_plan_type"),
            plus_trial_eligible=bool(result.get("plus_trial_eligible")),
        )

        recheck_delay = _registration_recheck_delay()
        should_recheck = (
            trigger == "registration_auto"
            and recheck_delay > 0
            and bool(result.get("ok"))
            and str(result.get("current_plan_type") or "").lower() == "free"
            and not bool(result.get("plus_trial_eligible"))
        )
        if should_recheck:
            logger.info("[Plan] 新账号暂未发现 Plus 试用资格，%.1fs 后复查一次: %s", recheck_delay, email)
            time.sleep(recheck_delay)
            _wait_for_rate_slot()
            probe.mark("registration_recheck", "started")
            recheck_result = check_account_plan(
                access_token,
                proxy=proxy,
                timezone_offset_min=timezone_offset_min,
                max_attempts=1,
            )
            if recheck_result.get("ok"):
                result = recheck_result
                probe.mark("registration_recheck", "ok")
            else:
                probe.mark("registration_recheck", "failed", error=recheck_result.get("error"))
                logger.warning(
                    "[Plan] 新账号资格复查失败，保留首次成功结果: %s, %s",
                    email,
                    recheck_result.get("error") or "未知错误",
                )

        db.update_account_plan_check(acc_id=account_id, result=result)
        probe.mark("persist_result", "ok")

        # A live-check refresh already performs a plan recheck. The helper suppresses
        # refresh -> plan 401 -> refresh loops and ignores ordinary 403/timeouts.
        try:
            refresh = _queue_auth_refresh_if_needed(
                account_id=account_id, email=email, trigger=trigger, result=result,
            )
            if refresh is not None:
                probe.mark(
                    "auto_refresh_token",
                    "queued" if refresh.get("accepted") else "skipped",
                    error=None if refresh.get("accepted") else refresh.get("error"),
                )
                logger.info(
                    "[Plan] AT expired; automatic refresh %s: %s (%s)",
                    "queued" if refresh.get("accepted") else "not queued",
                    email,
                    refresh.get("error") or "ok",
                )
        except Exception as refresh_exc:
            probe.mark("auto_refresh_token", "failed", error=str(refresh_exc))
            logger.exception("[Plan] failed to queue automatic AT refresh: %s", email)

        if result.get("ok"):
            logger.info(
                "[Plan] 后台查询成功: %s, plan=%s, plus_trial=%s, trigger=%s",
                email,
                result.get("current_plan_type") or "unknown",
                bool(result.get("plus_trial_eligible")),
                trigger,
            )
        else:
            logger.warning(
                "[Plan] 后台查询失败: %s, trigger=%s, error=%s",
                email,
                trigger,
                result.get("error") or "未知错误",
            )
        return result
    except Exception as exc:
        result = {
            "ok": False,
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "error": f"{type(exc).__name__}: {str(exc)[:180]}",
        }
        try:
            db.update_account_plan_check(acc_id=account_id, result=result)
        except Exception:
            logger.exception("[Plan] 写入后台查询异常状态失败: account_id=%s", account_id)
        logger.exception("[Plan] 后台查询异常: %s", email)
        return result
    finally:
        try:
            final_ok = bool(result.get("ok"))
            if probe is not None:
                probe.mark(
                    "worker", "ok" if final_ok else "failed",
                    error=None if final_ok else result.get("error"),
                )
                summary = probe.finish(
                    "ok" if final_ok else "failed",
                    error=None if final_ok else result.get("error"),
                    current_plan_type=result.get("current_plan_type"),
                    plus_trial_eligible=bool(result.get("plus_trial_eligible")),
                )
                logger.info(
                    "[Plan][观测] account_id=%s first_failure=%s category=%s requests=%s traffic=%sB",
                    account_id,
                    summary.get("first_failure_stage") or "-",
                    summary.get("first_failure_category") or "-",
                    summary.get("traffic", {}).get("request_count", 0),
                    summary.get("traffic", {}).get("total_bytes", 0),
                )
        except Exception:
            logger.debug("[Plan] 写入结构化观测失败", exc_info=True)
        finally:
            if probe_active and probe_context is not None:
                try:
                    probe_context.__exit__(None, None, None)
                except Exception:
                    logger.debug("[Plan] 关闭结构化观测上下文失败", exc_info=True)
            _QUEUE_SLOTS.release()


def _handle_plan_future_done(account_id: int, email: str, future) -> None:
    """兜底捕获 ThreadPoolExecutor 在 worker 主保护之外的异常，避免状态永久停在 queued。"""
    try:
        if future.cancelled():
            raise RuntimeError("套餐查询 Future 在执行前被取消")
        exc = future.exception()
        if exc is None:
            return
        raise exc
    except Exception as exc:
        logger.exception("[Plan] 后台 Future 异常终止: account_id=%s email=%s", account_id, email)
        try:
            account = db.get_account(account_id) or {}
            if str(account.get("plan_check_status") or "") in {"queued", "running"}:
                db.update_account_plan_check(acc_id=account_id, result={
                    "ok": False,
                    "checked_at": datetime.now().isoformat(timespec="seconds"),
                    "error": f"套餐查询线程异常: {type(exc).__name__}: {str(exc)[:160]}",
                })
        except Exception:
            logger.exception("[Plan] Future 异常状态回写失败: account_id=%s", account_id)


def _submit_plan_check(**kwargs):
    future = _EXECUTOR.submit(_run_plan_check, **kwargs)
    account_id = int(kwargs.get("account_id") or 0)
    email = str(kwargs.get("email") or "")
    future.add_done_callback(lambda done: _handle_plan_future_done(account_id, email, done))
    return future


def enqueue_account_plan_check(
    *,
    account_id: int,
    email: str,
    access_token: str,
    trigger: str,
    proxy: str | None = None,
    timezone_offset_min: str = "-",
    multi_region: bool = False,
) -> dict:
    """把查询放入统一线程池；重复查询或队列满时不提交。"""
    account_id = int(account_id)
    email = str(email or "").strip()
    access_token = str(access_token or "").strip()
    if not access_token:
        return {"accepted": False, "busy": False, "error": "账号缺少 access_token"}
    if not _QUEUE_SLOTS.acquire(blocking=False):
        return {"accepted": False, "busy": False, "queue_full": True, "error": "套餐查询队列已满，请稍后重试"}

    if not db.claim_account_plan_check(acc_id=account_id, trigger=trigger):
        _QUEUE_SLOTS.release()
        return {"accepted": False, "busy": True, "error": "该账号正在查询套餐"}

    try:
        _submit_plan_check(
            account_id=account_id,
            email=email,
            access_token=access_token,
            trigger=str(trigger or "manual"),
            proxy=proxy,
            timezone_offset_min=str(timezone_offset_min or "-"),
            multi_region=bool(multi_region),
        )
    except Exception as exc:
        _QUEUE_SLOTS.release()
        result = {
            "ok": False,
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "error": f"套餐查询入队失败: {type(exc).__name__}: {str(exc)[:160]}",
        }
        db.update_account_plan_check(acc_id=account_id, result=result)
        return {"accepted": False, "busy": False, "error": result["error"]}

    return {
        "accepted": True,
        "busy": False,
        "account_id": account_id,
        "email": email,
        "status": "queued",
        "trigger": str(trigger or "manual"),
    }


def enqueue_account_plan_checks_batch(
    items: list[dict],
    trigger: str,
    proxy: str | None = None,
    timezone_offset_min: str = "-",
    multi_region: bool = False,
) -> tuple[list[dict], list[dict], list[dict]]:
    """批量快速入队，采用统一批处理数据库锁，入队耗时从数十秒骤降至几十毫秒。"""
    valid_items = [acc for acc in items if (acc.get("access_token") or "").strip()]
    acc_ids = [int(acc.get("id")) for acc in valid_items]
    claimed_ids = db.claim_account_plan_checks_batch(acc_ids, trigger=trigger)

    started, busy, failed = [], [], []
    for acc in valid_items:
        aid = int(acc.get("id"))
        if aid not in claimed_ids:
            busy.append({"id": aid, "email": acc.get("email"), "reason": "该账号正在查询套餐"})
            continue
        if not _QUEUE_SLOTS.acquire(blocking=False):
            reason = "套餐查询队列已满"
            db.update_account_plan_check(acc_id=aid, result={
                "ok": False,
                "checked_at": datetime.now().isoformat(timespec="seconds"),
                "error": reason,
            })
            failed.append({"id": aid, "email": acc.get("email"), "reason": reason})
            continue
        try:
            _submit_plan_check(
                account_id=aid,
                email=acc.get("email") or "",
                access_token=acc.get("access_token") or "",
                trigger=str(trigger or "manual"),
                proxy=proxy,
                timezone_offset_min=str(timezone_offset_min or "-"),
                multi_region=bool(multi_region),
            )
            started.append({"id": aid, "email": acc.get("email"), "accepted": True, "status": "queued"})
        except Exception as exc:
            _QUEUE_SLOTS.release()
            # A claimed task must leave the queued state when submission fails.
            from core.task_observability import redact_text
            reason = f"套餐查询入队失败: {type(exc).__name__}: {redact_text(exc)}"
            db.update_account_plan_check(acc_id=aid, result={
                "ok": False,
                "checked_at": datetime.now().isoformat(timespec="seconds"),
                "error": reason,
            })
            failed.append({"id": aid, "email": acc.get("email"), "reason": reason})
    return started, busy, failed


def queue_settings() -> dict:
    return {
        "workers": _WORKERS,
        "queue_limit": _QUEUE_LIMIT,
        "min_interval": _float_setting("PLAN_CHECK_MIN_INTERVAL", 0.4, 0.0, 30.0),
        "jitter": _float_setting("PLAN_CHECK_JITTER", 0.3, 0.0, 30.0),
    }
