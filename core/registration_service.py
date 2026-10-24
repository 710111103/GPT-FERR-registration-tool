# -*- coding: utf-8 -*-
"""
注册任务服务层：
    - 线程池并发执行 run_registration
    - 每个任务在 data/registration_jobs.json 里有一条记录
    - 每个任务的日志写到 data/logs/<job_uuid>.log，便于 Web UI 实时尾巴

使用：
    submit_registration(email_source="outlook", count=5)
    → 创建 5 个任务，丢入线程池，立即返回 [job_dict, ...]
"""
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any

from core import codex_retry_service, db
from core.task_observability import ProbeSession

logger = logging.getLogger(__name__)

# 全局线程池，最大并发数（WebUI 每次提交时可按最新 workers 重建）
_DEFAULT_MAX_WORKERS = 2
_MIN_MAX_WORKERS = 1
_MAX_MAX_WORKERS = 16
_executor: ThreadPoolExecutor | None = None
_executor_workers = _DEFAULT_MAX_WORKERS
_executor_generation = 0
_retired_executors: list[ThreadPoolExecutor] = []
_executor_lock = threading.RLock()

_STOP_EVENTS: dict[int, threading.Event] = {}
_ACTIVE_JOBS: set[int] = set()
_JOB_DRIVERS: dict[int, Any] = {}
_STOP_LOCK = threading.Lock()
_THREAD_CTX = threading.local()


class StopRequested(RuntimeError):
    """用户手动停止注册任务。"""


def register_job_driver(job_id: int, driver: Any) -> None:
    """登记正在运行的任务浏览器驱动，供手动停止时主动关闭。"""
    with _STOP_LOCK:
        job_id = int(job_id)
        existing = _JOB_DRIVERS.get(job_id)
        if existing is not None and existing is not driver:
            raise RuntimeError(f"任务 #{job_id} 已登记浏览器驱动，拒绝重复启动")
        _JOB_DRIVERS[job_id] = driver


def unregister_job_driver(job_id: int) -> None:
    """注销任务浏览器驱动。"""
    with _STOP_LOCK:
        _JOB_DRIVERS.pop(int(job_id), None)


def _activate_job(job_id: int) -> bool:
    """Atomically claim a job for one worker in this WebUI process."""
    job_id = int(job_id)
    with _STOP_LOCK:
        if job_id in _ACTIVE_JOBS:
            return False
        _STOP_EVENTS.setdefault(job_id, threading.Event())
        _ACTIVE_JOBS.add(job_id)
    _THREAD_CTX.job_id = job_id
    return True


def _deactivate_job(job_id: int) -> None:
    with _STOP_LOCK:
        _STOP_EVENTS.pop(int(job_id), None)
        _ACTIVE_JOBS.discard(int(job_id))
        _JOB_DRIVERS.pop(int(job_id), None)
    try:
        delattr(_THREAD_CTX, "job_id")
    except Exception:
        pass


def is_stop_requested(job_id: int | None = None) -> bool:
    if job_id is None:
        job_id = getattr(_THREAD_CTX, "job_id", None)
    if not job_id:
        return False
    with _STOP_LOCK:
        ev = _STOP_EVENTS.get(int(job_id))
        if ev and ev.is_set():
            return True
    job = db.get_job(int(job_id))
    return bool(job and job.get("status") in ("stopping", "stopped", "cancelled"))


def check_stop_requested() -> None:
    job_id = getattr(_THREAD_CTX, "job_id", None)
    if is_stop_requested(job_id):
        raise StopRequested(f"任务 #{job_id} 已被用户手动停止")


def _append_job_log(job_id: int, message: str) -> None:
    try:
        job = db.get_job(job_id)
        log_file = job.get("log_file") if job else None
        if not log_file:
            return
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%H:%M:%S")
        with Path(log_file).open("a", encoding="utf-8") as f:
            f.write(f"{ts} [WARNING] [manual-stop] {message}\n")
    except Exception:
        pass


def _random_display_name() -> str:
    """生成符合 OpenAI 限制的英文字母显示名。"""
    from core.name_samples import random_display_name

    return random_display_name()


def _prepare_registration_args(preset_email: str | None = None) -> tuple[str | None, str, str]:
    """复用 CLI 的默认规则，为旧 Web 任务入口补齐注册参数。"""
    # 用模块属性读，支持 WebUI 热加载
    from config import register as _r, email as _e
    from core.profile_utils import generate_random_birthday

    email = str(preset_email or getattr(_r, "REGISTER_EMAIL", "") or "").strip()
    name = str(getattr(_r, "REGISTER_NAME", "") or "").strip()
    # WebUI/配置里有时会把空值存成 "-"，这不是合法 OpenAI 显示名，按空处理并自动生成
    if name in {"-", "—", "无", "空", "none", "None", "null", "NULL"}:
        name = ""

    if not name:
        # 手动模式也自动生成显示名，减少配置负担
        name = _random_display_name()

    birthday = generate_random_birthday()

    # 自动邮箱不在准备阶段领取：浏览器驱动会等页面找到邮箱输入框后再领取，
    # 协议驱动则在 run_registration 即将开始认证时领取。这样页面打不开/找不到
    # 输入框时不会提前消耗邮箱订单或池中素材。
    if not email and not _e.USE_EMAIL_SERVICE:
        raise RuntimeError(
            "手动模式未配置邮箱。请在 WebUI 配置页设置 REGISTER_EMAIL，"
            "或开启 USE_EMAIL_SERVICE 并从邮箱池领取。"
        )

    return email or None, name, birthday


def _release_unconsumed_job_email(email: str | None, reason: str) -> None:
    """任务失败兜底：只回收尚未生成账号、仍处于 used 的邮箱领取。"""
    if not email:
        return
    try:
        from core.email_provider import release_email_if_unconsumed

        release_email_if_unconsumed(email, note=f"任务未消耗，已自动回收: {reason[:180]}")
    except Exception:
        logger.exception("[Service] 回收未消耗邮箱失败: %s", email)


def _is_final_session_access_token_timeout(error: object) -> bool:
    """
    识别注册最后一步已经返回 /api/auth/session 200 但没有 accessToken 的失败。
    这种邮箱后续继续注册通常会卡在同一状态，按要求直接停用邮箱池条目。
    """
    text = str(error or "")
    if not text:
        return False
    return (
        "等待 /api/auth/session accessToken 超时" in text
        and "WARNING_BANNER" in text
        and "'_http_status': 200" in text
    )


def _should_disable_failed_registration_email(error: object) -> bool:
    """需要直接停用邮箱的注册失败类型。"""
    text = str(error or "")
    if not text:
        return False
    return (
        _is_final_session_access_token_timeout(text)
        or "邮箱提交后进入登录密码页" in text
        or "auth.openai.com/log-in/password" in text
        or "/log-in/password" in text
        or "已在 OpenAI 存在账号" in text
        or "已在OpenAI注册过" in text
        or "已在本地存在注册账号" in text
        or "已注册" in text
    )


def _disable_job_email(email: str | None, reason: str) -> bool:
    """把本次任务邮箱停用，避免后续再次领取。"""
    if not email:
        return False
    try:
        from core.email_provider import release_email

        source = release_email(email, status="disabled", note=f"自动停用: {reason[:180]}")
        logger.warning("[Service] 已自动停用邮箱: source=%s email=%s reason=%s", source, email, reason[:220])
        return True
    except Exception:
        logger.exception("[Service] 自动停用邮箱失败: %s", email)
        return False


def _normalize_workers(max_workers: int | None) -> int:
    if max_workers is None:
        return _DEFAULT_MAX_WORKERS
    try:
        value = int(max_workers)
    except (TypeError, ValueError):
        value = _DEFAULT_MAX_WORKERS
    return max(_MIN_MAX_WORKERS, min(_MAX_MAX_WORKERS, value))


def get_executor(max_workers: int | None = None) -> ThreadPoolExecutor:
    """返回注册线程池。

    旧逻辑只在首次创建线程池时使用 max_workers，后续 WebUI 改线程数再提交仍会复用
    上一次的池。这里改成：每次传入的 max_workers 和当前池不一致时，立即创建新池供
    新提交任务使用；旧池不接收新任务，但会继续把已经排队/运行的任务跑完。
    """
    global _executor, _executor_workers, _executor_generation
    requested_workers = _normalize_workers(max_workers) if max_workers is not None else _executor_workers
    with _executor_lock:
        if _executor is None or requested_workers != _executor_workers:
            old_executor = _executor
            if old_executor is not None:
                # 不取消旧池里已提交的任务，只是不再往旧池追加新任务。
                old_executor.shutdown(wait=False, cancel_futures=False)
                _retired_executors.append(old_executor)
                logger.info(
                    "[Service] 注册线程池 workers 从 %s 切换为 %s；旧池继续处理已排队任务",
                    _executor_workers,
                    requested_workers,
                )
            _executor_workers = requested_workers
            _executor_generation += 1
            _executor = ThreadPoolExecutor(
                max_workers=requested_workers,
                thread_name_prefix=f"reg-worker-{_executor_generation}",
            )
    return _executor


def get_executor_workers() -> int:
    """当前新提交注册任务会使用的线程数。"""
    with _executor_lock:
        return _executor_workers


def shutdown_executor(wait: bool = True) -> None:
    global _executor
    with _executor_lock:
        executors = []
        if _executor is not None:
            executors.append(_executor)
            _executor = None
        executors.extend(_retired_executors)
        _retired_executors.clear()
    for ex in executors:
        ex.shutdown(wait=wait, cancel_futures=False)


# ============================================================
# 单任务执行：日志重定向到任务专属文件
# ============================================================

class _JobLogContext:
    """让本线程的根 logger 多一个 FileHandler，结束后移除。"""

    def __init__(self, log_path: str):
        self.log_path = log_path
        self.handler: logging.FileHandler | None = None

    def __enter__(self):
        Path(self.log_path).parent.mkdir(parents=True, exist_ok=True)
        self.handler = logging.FileHandler(self.log_path, encoding="utf-8")
        self.handler.setLevel(logging.INFO)
        self.handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s",
            datefmt="%H:%M:%S",
        ))
        # Ant/Playwright 在任务专属子线程执行。子线程名继承当前 worker 名，既能
        # 写入本任务日志，也不会把并发任务的日志串进来。
        thread_name = threading.current_thread().name
        child_prefix = f"{thread_name}-ant"
        self.handler.addFilter(
            lambda r: r.threadName == thread_name or r.threadName.startswith(child_prefix)
        )
        logging.getLogger().addHandler(self.handler)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.handler is not None:
            self.handler.close()
            logging.getLogger().removeHandler(self.handler)


def _is_browser_target_closed_error(error: object) -> bool:
    """Return True when the automation browser disappeared underneath a job.

    This is a batch-level stop signal: continuing the queue would only create a
    fresh visible browser for every remaining job after the user closed the
    stuck window or Ant/Chromium crashed.
    """
    text = str(error or "").lower()
    return any(marker in text for marker in (
        "targetclosederror",
        "target page, context or browser has been closed",
        "browser has been closed",
    ))


def _trip_browser_queue_breaker(job_id: int, error: object) -> int:
    if not _is_browser_target_closed_error(error):
        return 0
    from config import register as _register_cfg
    if not bool(getattr(_register_cfg, "ENABLE_QUEUE_BREAKER_ON_TARGET_CLOSED", False)):
        return 0
    reason = f"浏览器窗口已关闭或崩溃，任务 #{job_id} 触发队列断路，阻止继续打开新窗口"
    cancelled = cancel_pending_jobs(reason=reason)
    logger.error("[Service] %s；已取消 %s 个排队任务", reason, cancelled)
    return cancelled


def _run_one_job(job_id: int, log_file: str) -> None:
    """单任务入口（线程池里跑这个）。"""
    log_logger = logging.getLogger(__name__)
    if not _activate_job(job_id):
        log_logger.warning("[Job %s] 已有 worker 正在执行，忽略重复投递", job_id)
        return

    # 取消检查：用户可能在任务排队期间点了"取消排队"，把 status 改成了 cancelled。
    # 因为 Future 已经 submit 进线程池无法撤回，只能在真正执行前自检一下，跳过 cancelled 的。
    current = db.get_job(job_id)
    if not current:
        log_logger.info(f"[Job {job_id}] 任务记录已删除，跳过执行")
        _deactivate_job(job_id)
        return
    if not db.claim_pending_job(job_id):
        log_logger.info(f"[Job {job_id}] 已退出排队状态，跳过执行")
        _deactivate_job(job_id)
        return

    email: str | None = None
    result: dict | None = None
    resume_mode = False
    resume_account_id: int | None = None
    probe = ProbeSession(
        "registration", job_id,
        email_source=str(current.get("email_source") or ""),
    )
    probe_context = probe.activate()
    probe_context.__enter__()
    probe.mark("worker", "started")
    try:
        with _JobLogContext(log_file):
            from main import run_registration
            log_logger.info(f"[Job {job_id}] 开始注册任务")
            resume_account_id = current.get("resume_account_id")
            try:
                resume_account_id = int(resume_account_id) if resume_account_id is not None else None
            except (TypeError, ValueError):
                resume_account_id = None
            resume_mode = resume_account_id is not None
            resume_from = str(current.get("resume_from") or "password_checkpoint_saved").strip() or "password_checkpoint_saved"
            job_preset_email = str(current.get("email") or "").strip() or None
            if resume_mode:
                resume_account = db.get_account(resume_account_id)
                if not resume_account:
                    raise RuntimeError(f"断点续跑账号不存在: {resume_account_id}")
                job_preset_email = str(resume_account.get("email") or job_preset_email or "").strip() or None
                if not db.get_registration_password(resume_account):
                    raise RuntimeError(f"账号 #{resume_account_id} 没有已确认的注册密码，不能断点续跑")
                db.update_job(job_id, email=job_preset_email, account_id=resume_account_id)
                log_logger.info(f"[Job {job_id}] 断点续跑账号 #{resume_account_id}，阶段={resume_from}")
            if job_preset_email and not resume_mode:
                existing_acc = db.get_account_by_email(job_preset_email)
                if existing_acc:
                    msg = f"邮箱 {job_preset_email} 已在注册账号库中存在，快速跳过以节省代理流量"
                    log_logger.warning(f"[Job {job_id}] {msg}")
                    db.update_job(job_id, status="failed", error=msg, completed_at=datetime.now().isoformat(timespec="seconds"))
                    _deactivate_job(job_id)
                    return
                pool_item = db.get_email_pool_item_by_email(job_preset_email)
                if pool_item and str(pool_item.get("status") or "").lower() in {"disabled", "failed"}:
                    msg = f"邮箱 {job_preset_email} 在邮箱池中已被标记为不可用({pool_item.get('status')})，快速跳过"
                    log_logger.warning(f"[Job {job_id}] {msg}")
                    db.update_job(job_id, status="failed", error=msg, completed_at=datetime.now().isoformat(timespec="seconds"))
                    _deactivate_job(job_id)
                    return

            probe.mark("email_acquire", "started", preset=bool(job_preset_email))
            email, name, birthday = _prepare_registration_args(preset_email=job_preset_email)
            probe.mark("email_acquire", "ok", email=email or "deferred")
            if email:
                log_logger.info(f"[Job {job_id}] 使用任务继承/预设邮箱: {email}")
            db.update_job(job_id, email=email)
            check_stop_requested()
            def _on_email_acquired(acquired_email: str) -> None:
                nonlocal email
                email = str(acquired_email or "").strip() or None
                if email:
                    db.update_job(job_id, email=email)
                    log_logger.info(f"[Job {job_id}] 页面已找到邮箱输入框，已分配邮箱: {email}")
                    probe.mark("browser_email_acquire", "ok", email=email)
                    if not resume_mode and db.get_account_by_email(email):
                        msg = f"邮箱 {email} 已在本地注册账号库中存在，自动跳过"
                        log_logger.warning(f"[Job {job_id}] {msg}")
                        raise RuntimeError(f"该邮箱已在本地存在注册账号，自动跳过: {email}")

            probe.mark("registration_core", "started")
            result = run_registration(
                email=email,
                name=name,
                birthday=birthday,
                on_email_acquired=_on_email_acquired,
                resume_account_id=resume_account_id,
                resume_from=resume_from if resume_mode else None,
            )
            if isinstance(result, dict) and result.get("success"):
                probe.mark("registration_core", "ok", account_id=result.get("account_id"))
            else:
                probe.mark(
                    "registration_core", "failed",
                    error=(result or {}).get("error") if isinstance(result, dict) else "unknown",
                )
            if is_stop_requested(job_id):
                _release_unconsumed_job_email(email, "用户手动停止")
                db.update_job(
                    job_id,
                    status="stopped",
                    network_traffic=(result or {}).get("network_traffic") if isinstance(result, dict) else None,
                    registration_stage=(result or {}).get("registration_stage") if isinstance(result, dict) else None,
                    error="用户手动停止",
                    completed_at=datetime.now().isoformat(timespec="seconds"),
                )
                log_logger.warning(f"[Job {job_id}] 已按用户请求停止")
                return
            if isinstance(result, dict) and result.get("success"):
                db.update_job(
                    job_id,
                    status="success",
                    email=result.get("email"),
                    account_id=result.get("account_id"),
                    network_traffic=result.get("network_traffic"),
                    registration_stage=result.get("registration_stage"),
                    completed_at=datetime.now().isoformat(timespec="seconds"),
                )
                log_logger.info(f"[Job {job_id}] 成功: {result.get('email')}")
            else:
                # 注意：失败也可能伴随 account_id（如 Codex 失败但账号已注册成功）
                err = (result or {}).get("error") if isinstance(result, dict) else "unknown"
                result_email = (result or {}).get("email") if isinstance(result, dict) else None
                db.update_job(
                    job_id,
                    status="failed",
                    email=result_email,
                    account_id=(result or {}).get("account_id") if isinstance(result, dict) else None,
                    network_traffic=(result or {}).get("network_traffic") if isinstance(result, dict) else None,
                    registration_stage=(result or {}).get("registration_stage") if isinstance(result, dict) else None,
                    error=str(err)[:500],
                    completed_at=datetime.now().isoformat(timespec="seconds"),
                )
                email_to_handle = str(result_email or email or "").strip()
                if _should_disable_failed_registration_email(err):
                    _disable_job_email(email_to_handle, str(err))
                else:
                    _release_unconsumed_job_email(email_to_handle, str(err))
                log_logger.error(f"[Job {job_id}] 失败: {err}")
                _trip_browser_queue_breaker(job_id, err)
    except StopRequested as exc:
        probe.mark("worker", "cancelled", error=exc)
        _release_unconsumed_job_email(email, str(exc))
        log_logger.warning(f"[Job {job_id}] 已停止: {exc}")
        db.update_job(
            job_id,
            status="stopped",
            error="用户手动停止",
            completed_at=datetime.now().isoformat(timespec="seconds"),
        )
    except Exception as exc:
        probe.mark("worker", "failed", error=exc)
        err_text = f"{type(exc).__name__}: {exc}"
        existing_acc = db.get_account_by_email(email) if email else None
        if existing_acc and existing_acc.get("id") and not resume_mode:
            log_logger.warning(
                f"[Job {job_id}] 注册核心流程已落库(id={existing_acc.get('id')})，但收尾阶段捕获异常: {err_text}"
            )
            db.update_job(
                job_id,
                status="success",
                email=email,
                account_id=existing_acc.get("id"),
                error=None,
                completed_at=datetime.now().isoformat(timespec="seconds"),
            )
            return

        if _should_disable_failed_registration_email(err_text):
            _disable_job_email(email, err_text)
        else:
            _release_unconsumed_job_email(email, err_text)
        if is_stop_requested(job_id):
            log_logger.warning(f"[Job {job_id}] 停止中捕获异常，按停止处理: {type(exc).__name__}: {exc}")
            db.update_job(
                job_id,
                status="stopped",
                error="用户手动停止",
                completed_at=datetime.now().isoformat(timespec="seconds"),
            )
            return
        log_logger.exception(f"[Job {job_id}] 异常")
        db.update_job(
            job_id,
            status="failed",
            error=f"{type(exc).__name__}: {exc}"[:500],
            completed_at=datetime.now().isoformat(timespec="seconds"),
        )
        _trip_browser_queue_breaker(job_id, err_text)
    finally:
        try:
            final_job = db.get_job(job_id) or {}
            final_status = str(final_job.get("status") or "failed")
            final_error = final_job.get("error_message") or final_job.get("error")
            probe_status = "ok" if final_status == "success" else ("cancelled" if final_status in {"stopped", "cancelled"} else "failed")
            probe.mark("worker", probe_status, error=None if probe_status == "ok" else final_error)
            summary = probe.finish(
                probe_status,
                error=None if probe_status == "ok" else final_error,
                email=email,
                account_id=final_job.get("account_id"),
            )
            log_logger.info(
                "[Job %s][观测] first_failure=%s category=%s requests=%s traffic=%sB path=%s",
                job_id,
                summary.get("first_failure_stage") or "-",
                summary.get("first_failure_category") or "-",
                summary.get("traffic", {}).get("request_count", 0),
                summary.get("traffic", {}).get("total_bytes", 0),
                probe.path,
            )
        except Exception:
            log_logger.debug("[Job %s] 写入结构化观测失败", job_id, exc_info=True)
        finally:
            probe_context.__exit__(None, None, None)
        _deactivate_job(job_id)


def _run_codex_retry_job(job_id: int, log_file: str, email: str, account_id: int) -> None:
    """把 Codex 补跑作为标准任务执行，并复用任务状态、日志和停止入口。"""
    if not _activate_job(job_id):
        logger.warning("[Job %s] 已有 worker 正在执行，忽略重复 Codex 投递", job_id)
        return
    current = db.get_job(job_id)
    if not current or not db.claim_pending_job(job_id):
        codex_retry_service.release(email)
        _deactivate_job(job_id)
        return
    try:
        result = codex_retry_service.run_worker(
            email,
            clear_log=False,
            target_log_path=log_file,
        )
        now_iso = datetime.now().isoformat(timespec="seconds")
        if is_stop_requested(job_id) or result.get("status") == "stopped":
            db.update_job(job_id, status="stopped", email=email, account_id=account_id, error=str(result.get("message") or "用户手动停止")[:500], completed_at=now_iso)
        elif result.get("ok"):
            db.update_job(
                job_id,
                status="success",
                email=email,
                account_id=account_id,
                completed_at=now_iso,
            )
        else:
            db.update_job(
                job_id,
                status="failed",
                email=email,
                account_id=account_id,
                error=str(result.get("message") or "Codex 补跑失败")[:500],
                completed_at=now_iso,
            )
    except Exception as exc:
        db.update_job(
            job_id,
            status="failed",
            error=f"{type(exc).__name__}: {exc}"[:500],
            completed_at=datetime.now().isoformat(timespec="seconds"),
        )
        codex_retry_service.release(email)
        logger.exception("[Job %s] Codex 补跑异常", job_id)
    finally:
        _deactivate_job(job_id)


# ============================================================
# 公共接口
# ============================================================

def submit_registration(count: int = 1, email_source: str | None = None, workers: int | None = None) -> list[dict]:
    """
    创建 N 个注册任务并提交到线程池。
    email_source 仅记录到 DB；实际邮箱来源固定为 Outlook 账号池。

    Returns:
        N 个新创建的 job dict
    """
    if email_source is None:
        from config import email as _email_cfg
        email_source = _email_cfg.EMAIL_SOURCE

    # 创建/切换线程池和提交本批任务必须整体串行化：否则另一请求在本批提交中途
    # 切换 workers 并 shutdown 旧池，会导致后续 submit 报 cannot schedule new futures after shutdown。
    with _executor_lock:
        executor = get_executor(max_workers=workers)
        effective_workers = get_executor_workers()
        jobs = []
        for _ in range(count):
            job = db.create_job(email_source=email_source)
            try:
                executor.submit(_run_one_job, job["id"], job["log_file"])
            except Exception as exc:
                db.update_job(
                    int(job["id"]),
                    status="failed",
                    error=f"队列提交失败：{type(exc).__name__}: {exc}"[:500],
                    completed_at=datetime.now().isoformat(timespec="seconds"),
                )
                logger.exception("[Service] 注册任务 #%s 提交线程池失败", job["id"])
            jobs.append(db.get_job(int(job["id"])) or job)
    logger.info(f"[Service] 已提交 {count} 个注册任务，源={email_source}，workers={effective_workers}")
    return jobs



def submit_registration_resume(
    account_ids: list[int] | None,
    workers: int | None = 1,
) -> dict:
    """为已保存注册密码、但注册流程中断的账号创建断点续跑任务。"""
    raw_ids = account_ids or []
    if not isinstance(raw_ids, list):
        raw_ids = list(raw_ids) if isinstance(raw_ids, (tuple, set)) else []
    normalized: list[int] = []
    seen: set[int] = set()
    skipped: list[dict] = []
    for raw in raw_ids:
        try:
            acc_id = int(raw)
        except (TypeError, ValueError):
            skipped.append({"id": raw, "reason": "ID 非法"})
            continue
        if acc_id <= 0 or acc_id in seen:
            if acc_id in seen:
                continue
            skipped.append({"id": acc_id, "reason": "ID 非法"})
            continue
        seen.add(acc_id)
        normalized.append(acc_id)

    if not normalized:
        return {"ok": True, "started_count": 0, "skipped_count": len(skipped), "jobs": [], "skipped": skipped}

    from config import email as _email_cfg
    email_source = str(getattr(_email_cfg, "EMAIL_SOURCE", "outlook") or "outlook")
    active_resume_ids: set[int] = set()
    for job in db.list_jobs(limit=100000):
        if str(job.get("status") or "").lower() not in {"pending", "running", "stopping"}:
            continue
        try:
            resume_id = int(job.get("resume_account_id"))
        except (TypeError, ValueError):
            continue
        active_resume_ids.add(resume_id)

    prepared: list[tuple[dict, int]] = []
    for acc_id in normalized:
        account = db.get_account(acc_id)
        if not account:
            skipped.append({"id": acc_id, "reason": "账号不存在"})
            continue
        status = str(account.get("status") or "").strip().lower()
        if status not in {"registering", "interrupted"}:
            skipped.append({"id": acc_id, "email": account.get("email"), "status": status, "reason": "状态不需要续跑"})
            continue
        if not db.get_registration_password(account):
            skipped.append({"id": acc_id, "email": account.get("email"), "reason": "没有已确认注册密码"})
            continue
        if acc_id in active_resume_ids:
            skipped.append({"id": acc_id, "email": account.get("email"), "reason": "已有续跑任务"})
            continue
        prepared.append((account, acc_id))

    started: list[dict] = []
    with _executor_lock:
        executor = get_executor(max_workers=max(1, min(4, int(workers or 1))))
        for account, acc_id in prepared:
            job = db.create_job(email_source=email_source)
            db.update_job(
                int(job["id"]),
                email=str(account.get("email") or "").strip() or None,
                account_id=acc_id,
                resume_account_id=acc_id,
                resume_from="password_checkpoint_saved",
            )
            try:
                executor.submit(_run_one_job, int(job["id"]), job["log_file"])
            except Exception as exc:
                db.update_job(
                    int(job["id"]),
                    status="failed",
                    error=f"续跑任务提交失败：{type(exc).__name__}: {exc}"[:500],
                    completed_at=datetime.now().isoformat(timespec="seconds"),
                )
                skipped.append({"id": acc_id, "email": account.get("email"), "reason": "排队失败"})
                logger.exception("[Service] 续跑任务 #%s 提交线程池失败", job.get("id"))
                continue
            started.append(db.get_job(int(job["id"])) or job)
    return {
        "ok": True,
        "started_count": len(started),
        "skipped_count": len(skipped),
        "jobs": started,
        "skipped": skipped,
    }


def _account_for_job(job: dict) -> dict | None:
    account_id = job.get("account_id")
    if account_id is not None:
        try:
            account = db.get_account(int(account_id))
            if account is not None:
                return account
        except (TypeError, ValueError):
            pass
    email = str(job.get("email") or "").strip()
    return db.get_account_by_email(email) if email else None


def _build_retry_info(
    job: dict,
    *,
    successful_retry: dict | None,
    account: dict | None,
) -> dict:
    """使用已解析的任务链和账号构造重试信息。"""
    status = str(job.get("status") or "")
    info = {
        "retryable": False,
        "retry_action": None,
        "retry_label": None,
        "retry_reason": None,
        "display_status": status,
    }
    if status not in ("failed", "stopped", "cancelled"):
        return info

    if successful_retry is not None:
        info["retry_reason"] = f"后续重试任务 #{successful_retry.get('id')} 已成功"
        info["successful_retry_job_id"] = successful_retry.get("id")
        return info

    if account and job.get("account_id") is not None and status in ("failed", "stopped"):
        info["display_status"] = "success" if (account.get("codex_status") or "") == "success" else "partial_success"

    if account:
        codex_status = str(account.get("codex_status") or "")
        if codex_status == "deactivated":
            info["retry_reason"] = "账号已废号，不能补跑 Codex"
            return info
        if codex_status == "success":
            info["retry_reason"] = "账号和 Codex 授权均已完成"
            return info
        info.update({
            "retryable": True,
            "retry_action": "codex",
            "retry_label": "补跑 Codex",
        })
        return info

    info.update({
        "retryable": True,
        "retry_action": "registration",
        "retry_label": "重试",
    })
    return info


def get_retry_info(job: dict) -> dict:
    """返回给 API/UI 的重试能力描述，不依赖前端猜测错误阶段。"""
    status = str(job.get("status") or "")
    if status not in ("failed", "stopped", "cancelled"):
        return _build_retry_info(job, successful_retry=None, account=None)
    return _build_retry_info(
        job,
        successful_retry=db.get_successful_retry_for_job(int(job.get("id") or 0)),
        account=_account_for_job(job),
    )


def get_retry_info_bulk(jobs: list[dict]) -> dict[int, dict]:
    """批量生成任务重试信息，避免列表接口逐行重复加载全部任务和账号。"""
    rows = [dict(job) for job in (jobs or [])]
    if not rows:
        return {}

    retryable_rows = [
        job for job in rows
        if str(job.get("status") or "") in ("failed", "stopped", "cancelled")
    ]
    if not retryable_rows:
        return {
            int(job.get("id") or 0): _build_retry_info(
                job, successful_retry=None, account=None
            )
            for job in rows
        }

    all_jobs = db.list_jobs(limit=1_000_000)
    successful_by_root: dict[int, dict] = {}
    for candidate in all_jobs:
        if str(candidate.get("status") or "") != "success":
            continue
        root_id = int(candidate.get("root_job_id") or 0)
        if root_id <= 0:
            continue
        previous = successful_by_root.get(root_id)
        if previous is None or int(candidate.get("id") or 0) > int(previous.get("id") or 0):
            successful_by_root[root_id] = candidate

    accounts = db.list_accounts(limit=1_000_000)
    accounts_by_id = {
        int(account.get("id") or 0): account
        for account in accounts
        if int(account.get("id") or 0) > 0
    }
    accounts_by_email = {
        str(account.get("email") or "").strip().lower(): account
        for account in accounts
        if str(account.get("email") or "").strip()
    }

    result: dict[int, dict] = {}
    for job in rows:
        job_id = int(job.get("id") or 0)
        root_id = int(job.get("root_job_id") or job_id or 0)
        successful_retry = successful_by_root.get(root_id)
        if successful_retry is not None and int(successful_retry.get("id") or 0) == job_id:
            successful_retry = None

        account = None
        account_id = int(job.get("account_id") or 0)
        if account_id > 0:
            account = accounts_by_id.get(account_id)
        if account is None:
            account = accounts_by_email.get(str(job.get("email") or "").strip().lower())

        result[job_id] = _build_retry_info(
            job,
            successful_retry=successful_retry,
            account=account,
        )
    return result


def retry_job(job_id: int, workers: int | None = None) -> dict:
    """智能重试终态任务：未生成账号则重新注册，已有账号则仅补跑 Codex。"""
    source = db.get_job(job_id)
    if source is None:
        return {"ok": False, "error": "任务不存在", "status": 404}

    retry_info = get_retry_info(source)
    if not retry_info["retryable"]:
        reason = retry_info.get("retry_reason") or f"当前状态不支持重试：{source.get('status')}"
        return {"ok": False, "error": reason, "status": 409}

    action = str(retry_info["retry_action"])
    account = _account_for_job(source)
    email = str((account or {}).get("email") or source.get("email") or "").strip()
    account_id = int(account["id"]) if account and account.get("id") is not None else None
    reserved_codex = False
    if action == "codex":
        if not email or account_id is None:
            return {"ok": False, "error": "已注册账号信息不完整，无法补跑 Codex", "status": 409}
        if not codex_retry_service.reserve(email):
            return {"ok": False, "error": "该账号正在补跑 Codex，请稍候", "status": 409}
        reserved_codex = True

    # 注册重试时：如果原任务已分配过邮箱，且该邮箱尚未在 OpenAI 完成最终注册落库，优先复用该邮箱继续注册
    retry_email = None
    if action == "codex":
        retry_email = email
    elif email:
        existing_acc = db.get_account_by_email(email)
        disabled_pool_email = False
        if str(source.get("email_source") or "").strip().lower() == "remail":
            pool_row = db.get_remail_email_by_email(email)
            disabled_pool_email = str((pool_row or {}).get("status") or "").lower() == "disabled"
        else:
            pool_item = db.get_email_pool_item_by_email(email)
            pool_status = str((pool_item or {}).get("status") or "").lower()
            disabled_pool_email = pool_status in {"disabled", "failed"}
        source_error = str(source.get("error_message") or source.get("error") or "")
        if _should_disable_failed_registration_email(source_error):
            disabled_pool_email = True
        if not existing_acc and not disabled_pool_email:
            retry_email = email

    try:
        job, created = db.create_retry_job(
            int(job_id),
            job_type="codex_retry" if action == "codex" else "registration",
            email_source=str(source.get("email_source") or "outlook"),
            email=retry_email,
            account_id=account_id if action == "codex" else None,
        )
    except LookupError as exc:
        if reserved_codex:
            codex_retry_service.release(email)
        return {"ok": False, "error": str(exc), "status": 404}
    except ValueError as exc:
        if reserved_codex:
            codex_retry_service.release(email)
        return {"ok": False, "error": str(exc), "status": 409}

    if not created:
        job_id_int = int(job["id"])
        with _STOP_LOCK:
            is_active = job_id_int in _ACTIVE_JOBS
        if not is_active:
            # 该任务在数据库中处于 pending 或其它等待状态，但线程池中没有活跃 worker 在执行它，必须补投进线程池
            logger.info("[Service] 重试任务 #%s 当前未在线程池中，现补投执行", job_id_int)
            try:
                if action == "codex":
                    db.update_account_codex_status(email, "retrying", None)
                with _executor_lock:
                    executor = get_executor(max_workers=workers)
                    if action == "codex":
                        executor.submit(_run_codex_retry_job, job["id"], job["log_file"], email, int(account_id))
                    else:
                        executor.submit(_run_one_job, job["id"], job["log_file"])
                return {
                    "ok": True,
                    "created": False,
                    "reused": True,
                    "message": f"排队任务 #{job['id']} 已提交线程池开始执行",
                    "source_job_id": int(job_id),
                    "retry_action": action,
                    "job": job,
                }
            except Exception as exc:
                if reserved_codex:
                    codex_retry_service.release(email)
                    db.update_account_codex_status(email, "failed", f"队列提交失败：{type(exc).__name__}: {exc}"[:500])
                logger.exception("[Service] 补投重试任务 #%s 失败", job["id"])
                return {"ok": False, "error": f"任务调度失败：{exc}", "status": 500}

        if reserved_codex:
            codex_retry_service.release(email)
        return {
            "ok": True,
            "created": False,
            "reused": True,
            "message": f"已有重试任务 #{job['id']} 正在运行中",
            "source_job_id": int(job_id),
            "retry_action": action,
            "job": job,
        }

    try:
        if action == "codex":
            db.update_account_codex_status(email, "retrying", None)
        with _executor_lock:
            executor = get_executor(max_workers=workers)
            if action == "codex":
                executor.submit(_run_codex_retry_job, job["id"], job["log_file"], email, int(account_id))
            else:
                executor.submit(_run_one_job, job["id"], job["log_file"])
    except Exception as exc:
        if reserved_codex:
            codex_retry_service.release(email)
            db.update_account_codex_status(email, "failed", f"队列提交失败：{type(exc).__name__}: {exc}"[:500])
        db.update_job(
            int(job["id"]),
            status="failed",
            error=f"队列提交失败：{type(exc).__name__}: {exc}"[:500],
            completed_at=datetime.now().isoformat(timespec="seconds"),
        )
        logger.exception("[Service] 重试任务 #%s 提交线程池失败", job["id"])
        return {"ok": False, "error": "重试任务创建成功，但提交执行失败", "status": 500, "job": db.get_job(int(job["id"]))}

    return {
        "ok": True,
        "created": True,
        "reused": False,
        "message": f"已创建重试任务 #{job['id']}（{'Codex 补跑' if action == 'codex' else '完整注册'}）",
        "source_job_id": int(job_id),
        "retry_action": action,
        "job": job,
    }


def cancel_pending_jobs(reason: str = "用户手动取消") -> int:
    """
    把所有 status=pending 的任务批量改成 cancelled，避免它们被执行。
    已经在 running 的任务不动（线程池中无法中途打断）。
    返回成功取消的数量。

    实际"不执行"的保证在 _run_one_job 开头——它真要跑起来时会先看 status 决定是否跳过。
    """
    cancelled = db.cancel_pending_jobs(reason=reason)
    logger.info(f"[Service] 已取消 {cancelled} 个排队任务")
    return cancelled


def cleanup_stale_jobs_on_init() -> int:
    """清理因进程重启导致的孤立假死状态（running/stopping）。"""
    try:
        now_iso = datetime.now().isoformat(timespec="seconds")
        rows = db.list_jobs(limit=2000)
        reset_count = 0
        for r in rows:
            if r.get("status") in ("running", "stopping"):
                db.update_job(
                    int(r["id"]),
                    status="failed",
                    error="服务重启，历史运行状态已重置",
                    completed_at=now_iso,
                )
                reset_count += 1
        if reset_count:
            logger.warning("[Service] 已清理 %d 个上一进程遗留的 running/stopping 假死任务", reset_count)
        return reset_count
    except Exception as exc:
        logger.exception("[Service] 清理遗留假死任务失败: %s", exc)
        return 0


def request_stop_job(job_id: int, force: bool = False) -> dict:
    """手动停止单个注册任务。pending 直接取消；running 设置停止标记并尝试关闭驱动；stopping 或 force 直接强制停止。"""
    job = db.get_job(job_id)
    if not job:
        return {"ok": False, "error": "任务不存在", "status": 404}
    status = job.get("status")
    now_iso = datetime.now().isoformat(timespec="seconds")
    if status == "pending":
        if db.cancel_pending_job(job_id):
            _append_job_log(job_id, "用户手动停止：任务尚未运行，已取消排队。")
            return {"ok": True, "message": "排队任务已取消", "job_id": job_id, "state": "cancelled"}
        # worker 可能刚好抢先领取；按最新状态继续停止，避免返回过期结果。
        job = db.get_job(job_id) or job
        status = job.get("status")
    if status in ("success", "failed", "cancelled", "stopped"):
        return {"ok": True, "message": f"任务已结束：{status}", "job_id": job_id, "state": status}
    if status in ("running", "stopping"):
        # 如果已经处于 stopping 状态再次点击，或显式要求 force，则视为强制停止
        is_force = force or (status == "stopping")

        with _STOP_LOCK:
            active = int(job_id) in _ACTIVE_JOBS
            ev = _STOP_EVENTS.get(int(job_id)) if active else None
            drv = _JOB_DRIVERS.pop(int(job_id), None)
            if ev is not None:
                ev.set()

        # 尝试主动关闭运行中的浏览器驱动，打断阻塞调用
        if drv is not None:
            def _close_driver_async(d):
                try:
                    if hasattr(d, "quit"):
                        d.quit()
                    elif hasattr(d, "close"):
                        d.close()
                except Exception:
                    pass
            threading.Thread(target=_close_driver_async, args=(drv,), daemon=True).start()

        if is_force or not active or ev is None:
            # 强制停止，或 Web 服务重启/实例丢失等情况：直接落为 stopped，彻底解决永远卡在“停止中”
            with _STOP_LOCK:
                _STOP_EVENTS.pop(int(job_id), None)
                _ACTIVE_JOBS.discard(int(job_id))
            db.update_job(
                job_id,
                status="stopped",
                completed_at=now_iso,
                error="用户手动停止（已强制终止）" if is_force else "用户手动停止（任务实例不存在）",
            )
            _release_unconsumed_job_email(
                str(job.get("email") or "").strip() or None,
                "任务强制终止，确认未继续执行",
            )
            msg = "用户手动停止：已强制终止任务并释放资源。" if is_force else "用户手动停止：未找到运行中的任务实例，已直接标记为已停止。"
            _append_job_log(job_id, msg)
            logger.warning("[Service] 用户停止任务 #%s：%s，已直接标记 stopped", job_id, "强制终止" if is_force else "无实例")
            return {"ok": True, "message": "已强制停止任务并释放资源", "job_id": job_id, "state": "stopped"}

        db.update_job(job_id, status="stopping", error="用户手动停止中")
        _append_job_log(job_id, "用户手动停止：已发送停止信号并打断驱动，任务正在退出。")
        logger.warning("[Service] 用户请求停止任务 #%s", job_id)
        return {"ok": True, "message": "已发送停止信号", "job_id": job_id, "state": "stopping"}
    return {"ok": False, "error": f"当前状态不支持停止：{status}", "status": 409}


def read_job_log(job_id: int, max_bytes: int = 50_000) -> str:
    """读取任务日志文件最后 max_bytes 字节，给 Web UI 显示。"""
    job = db.get_job(job_id)
    if not job or not job.get("log_file"):
        return ""
    p = Path(job["log_file"])
    if not p.exists():
        return ""
    size = p.stat().st_size
    with p.open("rb") as f:
        if size > max_bytes:
            f.seek(size - max_bytes)
        data = f.read()
    return data.decode("utf-8", errors="replace")
