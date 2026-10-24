# -*- coding: utf-8 -*-
"""通过 antbrowser + Playwright 适配层执行 ChatGPT 注册。"""
from __future__ import annotations

import logging
import os
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from config import antbrowser as _cfg
from config import twofa as _twofa_cfg
from core.account_export import save_account_data, post_register_dwell
from core.db import save_registration_password_checkpoint, mark_account_registration_interrupted
from core.browser_data_saver import BrowserDataSaver
from core.browser_traffic import PlaywrightTrafficTracker
from core.antbrowser_driver import build_ant_driver, cleanup_ant_profile
from core.email_provider import acquire_email_after_input, wait_for_otp, resolve_email_source, reject_remail_after_otp_timeout
from core.humanize import delay as human_delay

# 复用 Roxy 注册流程里已维护好的页面操作函数。
from core.roxy_registration import (  # noqa: F401
    _safe_get, _maybe_accept, _submit_email_and_wait_next, _fill_password_page_if_present,
    _clear_otp_inputs, _type_otp, _click_continue, _wait_after_email_otp_submit,
    _click_resend_email_otp, _recover_email_otp_http_500, _complete_profile_page, _click_final_confirmation_if_present,
    _fetch_chatgpt_session, _check_manual_stop, _is_email_verification_page,
)

logger = logging.getLogger(__name__)


def _capture_password_request(context) -> dict:
    """记录密码提交请求的结构与结果，并返回仅含元数据的确认状态。"""
    state = {"request_seen": False, "response_seen": False, "response_status": None, "path": None}

    def is_target(request) -> bool:
        parsed = urlsplit(str(request.url or ""))
        return (
            request.method.upper() == "POST"
            and parsed.hostname == "auth.openai.com"
            and ("register" in parsed.path or "password" in parsed.path)
        )

    def on_request(request) -> None:
        try:
            if not is_target(request):
                return
            body = request.post_data or ""
            try:
                parsed_body = json.loads(body)
                body_keys = sorted(parsed_body) if isinstance(parsed_body, dict) else [type(parsed_body).__name__]
            except (TypeError, ValueError):
                body_keys = ["<non-json>"] if body else []
            headers = request.headers
            state["request_seen"] = True
            state["path"] = urlsplit(request.url).path
            logger.info(
                "[密码请求抓包] request method=%s path=%s body_keys=%s header_keys=%s sentinel_present=%s",
                request.method,
                urlsplit(request.url).path,
                body_keys,
                sorted(headers),
                bool(headers.get("openai-sentinel-token")),
            )
        except Exception as exc:
            logger.warning("[密码请求抓包] request 元数据读取失败：%s", type(exc).__name__)

    def on_response(response) -> None:
        try:
            request = response.request
            if is_target(request):
                state["response_seen"] = True
                state["response_status"] = int(response.status)
                state["path"] = urlsplit(request.url).path
                logger.info(
                    "[密码请求抓包] response method=%s path=%s status=%s",
                    request.method,
                    urlsplit(request.url).path,
                    response.status,
                )
        except Exception as exc:
            logger.warning("[密码请求抓包] response 元数据读取失败：%s", type(exc).__name__)

    context.on("request", on_request)
    context.on("response", on_response)
    return state


def _password_submit_verified(state: dict | None) -> bool:
    if not isinstance(state, dict):
        return False
    return bool(state.get("request_seen") and state.get("response_seen") and int(state.get("response_status") or 0) in {200, 201, 204})


def _ensure_registration_password(
    driver,
    email: str,
    current_password: str | None,
    timeout: int = 15,
    capture_state: dict | None = None,
) -> str | None:
    """仅在捕获到成功的远端密码提交响应后返回密码；OTP 直通流不伪造密码。"""
    if current_password:
        if capture_state is None:
            return current_password
        deadline = time.monotonic() + min(max(0, timeout), 5)
        while not capture_state.get("response_seen") and time.monotonic() < deadline:
            time.sleep(0.1)
        if _password_submit_verified(capture_state):
            return current_password
        logger.warning("[Ant Browser注册][密码] 候选密码缺少成功远端响应，丢弃：%s status=%s", email, capture_state.get("response_status"))
        return None

    deadline = time.monotonic() + max(0, timeout)
    attempt = 0
    while True:
        attempt += 1
        password = _fill_password_page_if_present(driver, email, timeout=6)
        if password:
            if capture_state is None or _password_submit_verified(capture_state):
                logger.info("[Ant Browser注册][密码] 远端密码提交已确认：%s（第 %s 次检查）", email, attempt)
                return password
            logger.warning("[Ant Browser注册][密码] 页面已跳转但未捕获成功密码响应，丢弃候选密码：%s", email)
            return None
        if _is_email_verification_page(driver):
            logger.info("[Ant Browser注册][密码] OTP 直通流未设置密码：%s", email)
            return None
        if time.monotonic() >= deadline:
            logger.warning("[Ant Browser注册][密码] 密码入口超时，账号密码保持未验证：%s", email)
            return None
        logger.info(
            "[Ant Browser注册][密码] 正在等待密码设置入口：%s（第 %s 次检查）",
            email,
            attempt,
        )
        time.sleep(1.0)


def _wait_registration_otp(driver, email: str, after_ts: float) -> str:
    """在 35s 内等待 Remail/API 验证码，未收到时点击重发后再等待 30s。"""
    if resolve_email_source(email) != "remail":
        return wait_for_otp(email, after_ts=after_ts, max_wait=35)

    try:
        return wait_for_otp(email, after_ts=after_ts, max_wait=35)
    except Exception as first_exc:
        message = str(first_exc or "")
        if "超时" not in message.lower() and "timeout" not in message.lower():
            raise
        logger.warning(
            "[Ant Browser注册][OTP] 35 秒未取到验证码，点击重新发送后再等待 30 秒：%s",
            email,
        )
        _click_resend_email_otp(driver, timeout=20)
        resend_after_ts = time.time()
        human_delay("api")
        try:
            return wait_for_otp(email, after_ts=resend_after_ts, max_wait=30)
        except Exception as second_exc:
            reject_remail_after_otp_timeout(email, second_exc)
            raise


def _is_recoverable_registration_error(error: object) -> bool:
    """判断是否值得重建浏览器后重试一次注册。

    这些错误表示浏览器/网络瞬态故障，而不是验证码错误、账号已存在等业务拒绝。
    """
    text = str(error or "").lower()
    return any(marker in text for marker in (
        "targetclosederror",
        "target page, context or browser has been closed",
        "browser has been closed",
        "antbrowser 页面上下文已关闭",
        "等待 /api/auth/session accesstoken 超时",
        "找不到 otp 输入框",
        "[navigation_error]",
        "chrome-error://chromewebdata/",
        "browser_navigation_failed",
    ))


def _registration_recovery_retries() -> int:
    try:
        value = int(os.getenv("ANT_REGISTRATION_RECOVERY_RETRIES", "1") or "1")
    except (TypeError, ValueError):
        value = 1
    return max(0, min(value, 2))


def _run_ant_registration_once(*args, **kwargs) -> dict:
    """在任务专属线程运行 Playwright Sync API，并恢复瞬态浏览器故障。

    WebUI 调用栈可能带有 asyncio loop，Sync API 需要隔离；每个任务独立线程还可
    确保 Playwright greenlet 和事件循环随任务一并销毁，不跨任务复用状态。
    页面上下文被 Ant/Chromium 瞬时关闭时，旧 driver 已不可恢复，因此销毁本次
    worker 后重建一个全新的 browser/profile，再从注册入口重跑；业务错误不重试。
    """
    from core import registration_service as svc
    parent_job_id = getattr(svc._THREAD_CTX, "job_id", None)

    def _sync_worker():
        if parent_job_id is not None:
            svc._THREAD_CTX.job_id = parent_job_id
        return _run_ant_registration_sync(*args, **kwargs)

    parent_name = threading.current_thread().name
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix=f"{parent_name}-ant")
    try:
        future = executor.submit(_sync_worker)
        start_time = time.monotonic()
        try:
            timeout = max(240, min(int(os.getenv("ANT_REGISTRATION_TASK_TIMEOUT", "480") or "480"), 900))
        except (TypeError, ValueError):
            timeout = 480
        while not future.done():
            if parent_job_id is not None and svc.is_stop_requested(parent_job_id):
                with svc._STOP_LOCK:
                    drv = svc._JOB_DRIVERS.get(int(parent_job_id))
                if drv is not None:
                    try:
                        drv.quit()
                    except Exception:
                        pass
                raise svc.StopRequested(f"任务 #{parent_job_id} 已按用户请求停止")
            try:
                return future.result(timeout=0.5)
            except (TimeoutError, FuturesTimeoutError):
                if time.monotonic() - start_time > timeout:
                    if parent_job_id is not None:
                        with svc._STOP_LOCK:
                            stop_event = svc._STOP_EVENTS.get(int(parent_job_id))
                            if stop_event is not None:
                                stop_event.set()
                    with svc._STOP_LOCK:
                        drv = svc._JOB_DRIVERS.get(int(parent_job_id)) if parent_job_id is not None else None
                    if drv is not None:
                        try:
                            drv.quit()
                        except Exception:
                            pass
                    future.cancel()
                    # Playwright sync calls cannot be force-cancelled. Closing the registered
                    # driver makes the worker unwind; wait briefly so its profile cleanup
                    # finishes before the serial executor starts another registration.
                    try:
                        future.result(timeout=20)
                    except Exception:
                        pass
                    raise TimeoutError(f"注册任务超过 {timeout} 秒超时")
        return future.result()
    finally:
        # shutdown(wait=True) would make the caller wait forever when a Playwright
        # call is wedged. The worker owns its browser and is closed above on timeout.
        executor.shutdown(wait=False, cancel_futures=True)
def run_ant_registration(*args, **kwargs) -> dict:
    """运行 Ant 注册；瞬态浏览器故障时重建 worker 并有限重试。"""
    retries = _registration_recovery_retries()
    for attempt in range(retries + 1):
        try:
            return _run_ant_registration_once(*args, **kwargs)
        except Exception as exc:
            if attempt >= retries or not _is_recoverable_registration_error(exc):
                raise
            delay = min(8.0, 2.0 ** attempt)
            logger.warning(
                "[Ant Browser注册][恢复] 瞬态故障，第 %s/%s 次恢复；%s 秒后重建浏览器：%s: %s",
                attempt + 1,
                retries,
                delay,
                type(exc).__name__,
                str(exc)[:220],
            )
            time.sleep(delay)
    raise RuntimeError("Ant Browser 注册恢复流程异常结束")


def _open_registration_browser(proxy: str | None, *, force_headless: bool | None = None):
    """Apply the configured Ant mode to each registration worker."""
    return build_ant_driver(proxy=proxy, force_headless=bool(_cfg.ANT_HEADLESS) if force_headless is None else force_headless)


def _run_ant_registration_sync(
    email: str | None,
    name: str,
    birthday: str,
    proxy: str = None,
    otp_code: str = None,
    batch_dir: Path | None = None,
    on_email_acquired: Callable[[str], None] | None = None,
    resume_account_id: int | None = None,
    resume_from: str | None = None,
    force_headless: bool | None = None,
) -> dict:
    """antbrowser 自动化注册入口。"""
    import importlib
    import core.roxy_registration
    import core.antbrowser_driver
    import core.account_export
    try:
        importlib.reload(core.roxy_registration)
        importlib.reload(core.antbrowser_driver)
        importlib.reload(core.account_export)
    except Exception:
        pass

    driver = None
    opened = None
    create_acknowledged = False
    openai_password: str | None = None
    traffic_tracker: PlaywrightTrafficTracker | None = None
    data_saver: BrowserDataSaver | None = None
    network_traffic: dict | None = None
    resume_mode = bool(resume_account_id)
    resume_password: str | None = None
    if resume_mode:
        try:
            from core import db as _db
            resume_account = _db.get_account(int(resume_account_id))
            resume_password = _db.get_registration_password(resume_account)
            if not resume_password:
                raise RuntimeError("断点续跑账号缺少已确认的注册密码")
            email = email or str((resume_account or {}).get("email") or "").strip() or None
            if not email:
                raise RuntimeError("断点续跑账号缺少邮箱")
            logger.info("[Ant Browser注册][断点续跑] account_id=%s from=%s，跳过邮箱密码设置阶段", resume_account_id, resume_from or "password_checkpoint_saved")
        except Exception:
            raise
    try:
        # ANT_HEADLESS controls the registration worker's browser mode.  A headless
        # worker always creates an isolated Ant profile; it never reuses a visible one.
        driver, opened = _open_registration_browser(proxy, force_headless=force_headless)
        from core import registration_service as svc
        current_job_id = getattr(svc._THREAD_CTX, "job_id", None)
        if current_job_id is not None:
            svc.register_job_driver(current_job_id, driver)
        try:
            traffic_tracker = PlaywrightTrafficTracker(driver.context, label="Ant")
        except Exception as exc:
            logger.warning("[Ant Browser注册] 初始化浏览器流量统计失败，继续注册：%s: %s", type(exc).__name__, str(exc)[:180])
        password_capture = _capture_password_request(driver.context)
        data_saver = None
        logger.info("[Ant Browser注册] 开始：%s，profile=%s", email, opened.profile_id)

        otp_after_ts = time.time()
        logger.info("[Ant Browser注册] 打开登录页：https://chatgpt.com/auth/login")
        _safe_get(
            driver,
            "https://chatgpt.com/auth/login",
            timeout=50,
            attempts=2,
            accept_hosts=("chatgpt.com", "auth.openai.com"),
        )
        human_delay("navigate")
        _maybe_accept(driver)
        _check_manual_stop()

        def _email_supplier_after_input() -> str:
            nonlocal email
            _check_manual_stop()
            email = acquire_email_after_input(email)
            if on_email_acquired:
                on_email_acquired(email)
            return email

        next_state = _submit_email_and_wait_next(
            driver,
            email,
            attempts=3,
            email_supplier=_email_supplier_after_input,
        )
        _check_manual_stop()

        # 如果邮箱提交后直接进入验证码页，也尝试点击“使用密码继续”进入密码创建页；
        # _fill_password_page_if_present 会在设置成功后返回本次 OpenAI 注册密码。
        if resume_mode:
            openai_password = resume_password
            logger.info("[Ant Browser注册][断点续跑] 已跳过密码设置，直接进入 OTP：%s", email)
        else:
            openai_password = _fill_password_page_if_present(driver, email, timeout=25)
        _check_manual_stop()

        current_otp = otp_code
        max_otp_attempts = 3
        for otp_attempt in range(1, max_otp_attempts + 1):
            _check_manual_stop()
            if current_otp is None:
                logger.info("[Ant Browser注册][OTP] 等待验证码：%s（第 %s/%s 次）", email, otp_attempt, max_otp_attempts)
                try:
                    current_otp = _wait_registration_otp(driver, email, otp_after_ts)
                except Exception as exc:
                    reject_remail_after_otp_timeout(email, exc)
                    _check_manual_stop()
                    if otp_attempt >= max_otp_attempts:
                        raise
                    logger.warning(
                        "[Ant Browser注册][OTP] 一直未收到验证码，点击“重新发送电子邮件”后继续等待（下一轮 %s/%s）：%s: %s",
                        otp_attempt + 1,
                        max_otp_attempts,
                        type(exc).__name__,
                        str(exc)[:180],
                    )
                    otp_after_ts = time.time()
                    _click_resend_email_otp(driver, timeout=25)
                    human_delay("api")
                    current_otp = None
                    continue
            _check_manual_stop()
            # 强制确认密码分支已完成并成功设置密码，确保导出的账号具备密码凭证。
            if not resume_mode:
                openai_password = _ensure_registration_password(
                    driver,
                    email,
                    openai_password,
                    timeout=25,
                    capture_state=password_capture,
                )
            if openai_password and _password_submit_verified(password_capture):
                try:
                    save_registration_password_checkpoint(
                        email=email,
                        password=openai_password,
                        verified=True,
                        stage="antbrowser_password_submitted",
                        proxy_used=((opened.raw or {}).get("proxy") if opened else None) or proxy or None,
                        email_source=resolve_email_source(email),
                        extra_context={
                            "antbrowser": {
                                "profile_id": getattr(opened, "profile_id", None),
                            },
                        },
                    )
                except Exception as ck_exc:
                    logger.warning("[Ant Browser注册][密码预存] Stage-1 密码原子预存异常：%s", ck_exc)
            logger.info("[Ant Browser注册][OTP] 收到验证码：%s", current_otp)
            if _recover_email_otp_http_500(driver, email):
                otp_after_ts = time.time()
                current_otp = None
                continue

            # 确保页面已稳定进入邮箱验证码页面（避免刚从密码页跳转导致找不到输入框）
            for _wait_page in range(12):
                if _is_email_verification_page(driver):
                    break
                time.sleep(0.5)

            _clear_otp_inputs(driver)
            _type_otp(driver, current_otp)
            human_delay("otp_input")

            # 等待验证码自动流转（Remix / React 在 6 位填满后会自动发起请求校验）
            outcome = _wait_after_email_otp_submit(driver, timeout=12)
            if outcome != "accepted":
                _check_manual_stop()
                try:
                    _click_continue(driver)
                except Exception as exc:
                    logger.info("[Ant Browser注册][OTP] 未找到显式提交按钮，继续等待页面状态：%s", str(exc)[:120])
                outcome = _wait_after_email_otp_submit(driver, timeout=20)

            _check_manual_stop()
            if outcome == "accepted":
                break
            if otp_attempt >= max_otp_attempts:
                raise RuntimeError("邮箱验证码连续错误/过期，已达到最大重试次数")

            # 住宅代理延迟较高时，如果 outcome 并非 invalid（页面并无错误码提示），
            # 避免过早点击“重新发送”，否则刚收到的有效验证码立刻被作废，且易触发风控 500
            if outcome != "invalid":
                logger.info("[Ant Browser注册][OTP] 页面流转中（outcome=%s），追加缓冲等待 15s...", outcome)
                for _ in range(15):
                    time.sleep(1.0)
                    if not _is_email_verification_page(driver):
                        outcome = "accepted"
                        break
                if outcome == "accepted":
                    break

            otp_after_ts = time.time()
            _click_resend_email_otp(driver, timeout=25)
            human_delay("api")
            current_otp = None

        _check_manual_stop()
        if not openai_password:
            logger.info("[Ant Browser注册] 注册完成但未确认远端密码提交，账号保持无密码/待补设：%s", email)
        if data_saver is not None:
            # about-you 仍在 auth.openai.com，不受此阶段影响；OAuth 回跳到
            # chatgpt.com 后只需同源读取 /api/auth/session，无需加载聊天 SPA。
            data_saver.session_only()
        profile_submitted = _complete_profile_page(driver, name, birthday, timeout=60)
        _check_manual_stop()
        if profile_submitted:
            create_acknowledged = True
            human_delay("post_auth")

        session_info = _fetch_chatgpt_session(driver, timeout=120)
        _check_manual_stop()
        access_token = session_info["accessToken"]
        logger.info("[Ant Browser注册] 已拿到 accessToken：%s", email)

        codex_auto = False
        try:
            from config import codex as _codex_cfg
            codex_auto = bool(getattr(_codex_cfg, "ENABLE_CODEX_AUTO", False))
        except Exception:
            codex_auto = False

        if not codex_auto:
            # 注册凭证已完整获取，跳过 Codex 时立即切往空白页并开启全局拦截，
            # 彻底阻断 ChatGPT 首页在后台下载数十个 SPA chunk / KaTeX / 媒体 / 统计（节约 8~12MB 流量）
            try:
                driver.execute_script("window.stop();")
                driver.get("about:blank")
            except Exception:
                pass
            if data_saver is not None:
                data_saver.block_all()
        else:
            # 开启自动 Codex 时，也无需加载 ChatGPT 首页 SPA（Codex 会重新打开 auth_url 并清理 chatgpt.com 存储）
            try:
                driver.execute_script("window.stop();")
            except Exception:
                pass
            final_confirmation = _click_final_confirmation_if_present(driver)
            if final_confirmation.get("ok"):
                logger.info(
                    "[Ant Browser注册] 已点击注册完成页继续按钮：%s",
                    final_confirmation.get("reason"),
                )
                human_delay("navigate")

        totp_secret = None
        if _twofa_cfg.ENABLE_2FA:
            logger.info("[Ant Browser注册] 2FA 已启用，账号落库后由统一 2FA 服务在后台异步自动入队")

        codex_result = {
            "status": "skipped",
            "ok": True,
            "message": "ENABLE_CODEX_AUTO=False，跳过 Codex",
        }
        try:
            from config import codex as _codex_cfg
            cpa_key = str(getattr(_codex_cfg, "CPA_MANAGEMENT_KEY", "") or "").strip()
            uses_cpa = str(getattr(_codex_cfg, "CODEX_AUTH_URL_SOURCE", "cpa") or "cpa").strip().lower() == "cpa"
            if codex_auto and uses_cpa and not cpa_key:
                codex_result = {
                    "status": "skipped",
                    "ok": True,
                    "message": "未配置 CPA_MANAGEMENT_KEY，已跳过 Codex 自动授权",
                }
                logger.info("[Ant Browser注册][Codex] 未配置 CPA_MANAGEMENT_KEY，直接跳过自动授权")
            elif codex_auto:
                from core.roxy_codex_oauth import run_roxy_codex_oauth
                logger.info("[Ant Browser注册][Codex] ENABLE_CODEX_AUTO=True，复用当前 antbrowser 窗口执行 Codex 授权")
                _check_manual_stop()
                codex_result = run_roxy_codex_oauth(
                    email,
                    reuse_existing_profile=True,
                    existing_driver=driver,
                    existing_opened=opened,
                    force=True,
                    clear_existing_state=True,
                )
            else:
                logger.info("[Ant Browser注册][Codex] ENABLE_CODEX_AUTO=False，注册后跳过 Codex OAuth")
        except Exception as exc:
            codex_result = {"status": "failed", "ok": False, "message": f"{type(exc).__name__}: {str(exc)[:180]}"}

        if codex_auto:
            try:
                driver.execute_script("window.stop();")
                driver.get("about:blank")
            except Exception:
                pass
            if data_saver is not None:
                data_saver.block_all()

        # 拿到 accessToken 后立即优先落库，绝不等流量统计或延迟关闭，确保凭证不因后续步骤丢单
        password_verified = resume_mode or _password_submit_verified(password_capture)
        account_id = save_account_data(
            email=email,
            access_token=access_token,
            totp_secret=totp_secret,
            email_source=resolve_email_source(email),
            proxy_used=((opened.raw or {}).get("proxy") if opened else None) or proxy or None,
            batch_dir=batch_dir,
            extra={
                "user": session_info.get("user"),
                "account": session_info.get("account"),
                "expires": session_info.get("expires"),
                "antbrowser": {
                    "profile_id": opened.profile_id,
                    "open_result": {k: v for k, v in (opened.raw or {}).items() if k != "static_asset_proxy"},
                },
                "registration_password": openai_password if password_verified else None,
                "registration_password_verified": password_verified,
                "registration_password_submit_status": password_capture.get("response_status"),
                "codex": codex_result,
                "network_traffic": network_traffic,
            },
        )
        logger.info("[Ant Browser注册] 账号已优先落库：%s account_id=%s", email, account_id)

        # 账号落库后立即结束流程，快速回收浏览器实例并启动下一个任务
        if traffic_tracker is not None:
            try:
                network_traffic = traffic_tracker.stop_local()
            except Exception as tracker_exc:
                logger.warning("[Ant Browser注册] 统计流量异常：%s", tracker_exc)
        cache_proxy = (opened.raw or {}).get("static_asset_proxy") if opened else None
        if cache_proxy is not None:
            cache_stats = cache_proxy.snapshot()
            if isinstance(network_traffic, dict):
                network_traffic["static_asset_cache"] = cache_stats
            logger.info(
                "[静态缓存] 命中=%s 未命中=%s 并发复用=%s 等待超时=%s 节省下载=%sB",
                cache_stats.get("hits", 0), cache_stats.get("misses", 0),
                cache_stats.get("waiter_hits", 0), cache_stats.get("waiter_timeouts", 0),
                cache_stats.get("bytes_saved", 0),
            )
        if data_saver is not None:
            try:
                data_saver.stop()
            except Exception:
                pass
        codex_ok = codex_result.get("ok") or codex_result.get("status") == "skipped"
        return {
            "success": bool(codex_ok),
            "email": email,
            "account_id": account_id,
            "access_token": access_token,
            "totp_secret": totp_secret,
            "codex": codex_result,
            "network_traffic": network_traffic,
            "error": None if codex_ok else f"Codex 未完成: {codex_result.get('message')}",
        }
    except Exception as exc:
        if driver is not None:
            try:
                driver.execute_script("window.stop();")
                driver.get("about:blank")
            except Exception:
                pass
        if data_saver is not None:
            try:
                data_saver.block_all()
            except Exception:
                pass
        if traffic_tracker is not None:
            try:
                network_traffic = traffic_tracker.stop_local()
            except Exception:
                pass
        cache_proxy = (opened.raw or {}).get("static_asset_proxy") if opened else None
        if cache_proxy is not None and isinstance(network_traffic, dict):
            network_traffic["static_asset_cache"] = cache_proxy.snapshot()
        if data_saver is not None:
            try:
                data_saver.stop()
            except Exception:
                pass
        logger.error("[Ant Browser注册] 失败：%s: %s", type(exc).__name__, exc)
        logger.debug("[Ant Browser注册] 失败详情", exc_info=True)
        try:
            if email and openai_password and (resume_mode or _password_submit_verified(password_capture)):
                try:
                    mark_account_registration_interrupted(
                        email,
                        stage="antbrowser_registration_interrupted",
                        error=f"{type(exc).__name__}: {str(exc)[:180]}",
                        password=openai_password,
                    )
                except Exception as int_exc:
                    logger.warning("[Ant Browser注册][中断保全] 标记中断异常：%s", int_exc)
        except Exception:
            pass
        try:
            if email:
                from core.email_provider import release_email
                is_timeout = isinstance(exc, (TimeoutError, FuturesTimeoutError)) or "超时" in str(exc) or "timeout" in str(exc).lower()
                is_disabled_error = (
                    "进入登录密码页" in str(exc)
                    or "已注册" in str(exc)
                    or "/log-in/password" in str(exc)
                    or "存在账号" in str(exc)
                )
                if openai_password and (resume_mode or _password_submit_verified(password_capture)):
                    release_status = "registered"
                elif is_disabled_error:
                    release_status = "disabled"
                elif create_acknowledged or is_timeout:
                    release_status = "failed"
                else:
                    release_status = getattr(exc, "email_release_status", "available")
                release_email(email, status=release_status, note=f"Ant注册失败: {str(exc)[:180]}")
        except Exception:
            pass
        return {
            "success": False,
            "email": email,
            "network_traffic": network_traffic,
            "error": f"{type(exc).__name__}: {str(exc)[:300]}",
        }
    finally:
        if traffic_tracker is not None:
            try:
                traffic_tracker.stop_local()
            except Exception:
                pass
        if data_saver is not None:
            try:
                data_saver.stop()
            except Exception:
                pass
        # Ant owns the browser process. Stop/delete the profile before disconnecting
        if driver and (bool(force_headless) or bool(_cfg.ANT_HEADLESS) or not bool(_cfg.ANT_KEEP_BROWSER_OPEN)):
            try:
                driver.quit()
            except Exception:
                pass
            driver = None
        if opened is not None:
            try:
                cleanup_ant_profile(opened)
                opened = None
            except Exception as exc:
                logger.warning("[Ant Browser注册] 清理临时实例失败：%s", exc)
        try:
            from core import registration_service as svc
            current_job_id = getattr(svc._THREAD_CTX, "job_id", None)
            if current_job_id is not None:
                svc.unregister_job_driver(current_job_id)
        except Exception:
            pass
        if opened is not None:
            try:
                cleanup_ant_profile(opened)
            except Exception as exc:
                logger.warning("[Ant Browser注册] 二次清理临时实例失败：%s", exc)



