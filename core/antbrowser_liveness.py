# -*- coding: utf-8 -*-
"""Refresh an account login through the real AntBrowser Chromium network stack."""
from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any

from core.antbrowser_driver import build_ant_driver, cleanup_ant_profile
from core.email_provider import wait_for_otp
from core.roxy_codex_oauth import _fill_email_and_otp, _is_mfa_challenge_page, _fill_mfa_challenge_if_present
from core.roxy_registration import _fetch_chatgpt_session

logger = logging.getLogger(__name__)


def _browser_refresh_limit() -> int:
    try:
        return max(1, min(4, int(os.environ.get("ANT_REFRESH_BROWSER_WORKERS", "2"))))
    except (TypeError, ValueError):
        return 2


def _login_attempt_timeout() -> int:
    """Hard ceiling for one isolated browser/profile attempt.

    Closing the driver from a watchdog is intentional: Playwright/Selenium calls can
    block inside a navigation or locator wait, so checking elapsed time only between
    calls does not release a live-check worker reliably.
    """
    try:
        return max(45, min(240, int(os.environ.get("ANT_LOGIN_ATTEMPT_TIMEOUT", "120"))))
    except (TypeError, ValueError):
        return 120


def _rotate_retry_proxy(proxy: str | None, attempt: int) -> str | None:
    """Use a fresh sticky-session id for the second browser attempt when supported."""
    if attempt <= 1:
        return proxy
    try:
        from core.chatgpt_plan import rotate_proxy_session
        rotated, _session_id = rotate_proxy_session(str(proxy or "").strip())
        return rotated or proxy
    except Exception:
        logger.debug("Ant browser retry proxy rotation failed", exc_info=True)
        return proxy


_BROWSER_REFRESH_SLOTS = threading.BoundedSemaphore(_browser_refresh_limit())


def refresh_recent_login_browser(
    email: str,
    *,
    email_source: str | None = None,
    proxy: str | None = None,
    force_headless: bool = True,
    ant_headless: bool = True,
    progress_callback=None,
) -> dict[str, Any]:
    """Queue browser logins; never share an authenticated profile across accounts."""
    with _BROWSER_REFRESH_SLOTS:
        return _refresh_recent_login_browser_impl(
            email,
            email_source=email_source,
            proxy=proxy,
            force_headless=force_headless,
            ant_headless=ant_headless,
            progress_callback=progress_callback,
        )


def _refresh_recent_login_browser_impl(
    email: str,
    *,
    email_source: str | None = None,
    proxy: str | None = None,
    force_headless: bool = True,
    ant_headless: bool = True,
    progress_callback=None,
) -> dict[str, Any]:
    """Log in in AntBrowser or Standalone Playwright Headless and return a fresh ChatGPT session payload."""
    for attempt in range(1, 3):
        driver = None
        opened = None
        watchdog = None
        attempt_finished = threading.Event()
        attempt_timed_out = threading.Event()
        profile_cleaned = threading.Event()
        watchdog_wakeup = threading.Event()
        activity_lock = threading.Lock()
        last_activity = [time.monotonic()]
        activity_stage = ["browser_start"]
        attempt_proxy = _rotate_retry_proxy(proxy, attempt)
        try:
            build_kwargs = {"ant_headless": True} if ant_headless else {}
            driver, opened = build_ant_driver(proxy=attempt_proxy, force_headless=force_headless, **build_kwargs)
            driver._registration_log_prefix = "[无头浏览器登录]" if force_headless else "[有头浏览器登录]"
            timeout_seconds = _login_attempt_timeout()
            driver._auth_open_attempts = 1
            driver._email_submit_attempts = 2
            driver._email_input_wait_timeout = min(30, max(15, timeout_seconds // 4))
            try:
                driver.set_page_load_timeout(min(40, max(20, timeout_seconds // 3)))
                if getattr(driver, "page", None) is not None:
                    driver.page.set_default_timeout(10000)
                    driver.page.set_default_navigation_timeout(min(40000, max(20000, timeout_seconds * 300)))
            except Exception:
                logger.debug("Ant bounded timeout configuration failed", exc_info=True)

            def _touch_activity(stage: str) -> None:
                # The auth flow can legitimately spend more than one original hard
                # ceiling in total (Cloudflare -> email -> password/MFA -> session).
                # Only terminate when one stage makes no observable progress.
                with activity_lock:
                    last_activity[0] = time.monotonic()
                    activity_stage[0] = stage
                watchdog_wakeup.set()

            def _expire_attempt() -> None:
                while not attempt_finished.is_set():
                    with activity_lock:
                        idle_for = time.monotonic() - last_activity[0]
                        stalled_stage = activity_stage[0]
                    remaining = timeout_seconds - idle_for
                    if remaining > 0:
                        watchdog_wakeup.wait(min(1.0, remaining))
                        watchdog_wakeup.clear()
                        continue
                    if attempt_finished.is_set():
                        return
                    attempt_timed_out.set()
                    message = (
                        f"Ant 登录阶段 {stalled_stage} 连续 {timeout_seconds} 秒无进展，"
                        "已强制关闭当前实例并准备轮换代理"
                    )
                    logger.warning("%s %s: %s", driver._registration_log_prefix, message, email)
                    if callable(progress_callback):
                        try:
                            progress_callback(message)
                        except Exception:
                            logger.debug("Ant timeout progress callback failed", exc_info=True)
                    # Do not call Playwright's synchronous driver from this watchdog
                    # thread: its greenlet belongs to the worker thread and a cross-thread
                    # quit can deadlock the whole Flask process. Deleting the ephemeral Ant
                    # profile through the local API closes Chromium externally, which makes
                    # the blocked worker call unwind with TargetClosed.
                    try:
                        if opened is not None:
                            cleanup_ant_profile(opened)
                            profile_cleaned.set()
                    except Exception:
                        logger.debug("Ant watchdog profile cleanup failed", exc_info=True)
                    return

            watchdog = threading.Thread(
                target=_expire_attempt,
                name=f"ant-login-watchdog-{attempt}",
                daemon=True,
            )
            watchdog.start()
            if not force_headless:
                # Visible browser, automatic flow: do not park for five minutes
                # waiting for an operator to complete a challenge.
                driver._manual_challenge_wait = False
                driver._challenge_progress = progress_callback
            logger.info(
                "%s 开始 Recent Login：email=%s profile=%s attempt=%s/2",
                driver._registration_log_prefix, email, opened.profile_id, attempt,
            )

            def otp_provider(target_email: str, *, after_ts: float, exclude_codes=None):
                # Keep each mailbox poll short. The browser can advance from the
                # email branch to MFA/already-authenticated state while the mail
                # API is still waiting; a long blocking poll previously hid that
                # transition for several minutes and falsely failed the refresh.
                return wait_for_otp(
                    target_email,
                    after_ts=after_ts,
                    max_wait=8,
                    poll_interval=2,
                    settle_seconds=0,
                    email_source=email_source,
                    exclude_codes=exclude_codes,
                )

            def login_progress(_stage: str, message: str, _extra: dict | None = None) -> None:
                _touch_activity(_stage or "auth_progress")
                if callable(progress_callback):
                    progress_callback(message)

            fill_kwargs = {"progress_callback": login_progress} if callable(progress_callback) else {}
            _fill_email_and_otp(
                driver,
                email,
                otp_provider,
                "https://chatgpt.com/auth/login",
                **fill_kwargs,
            )
            if attempt_timed_out.is_set():
                raise RuntimeError(
                    f"ant_login_timeout: 邮箱提交/Cloudflare 页面超过单轮总时限 {timeout_seconds}s"
                )
            if not force_headless:
                # MFA may render after the password/email step has already returned.
                # Keep the visible browser open while the operator enters the app code.
                deadline = time.monotonic() + 180
                next_notice = 0.0
                first_check = time.monotonic()
                saw_mfa = False
                while time.monotonic() < deadline:
                    if _is_mfa_challenge_page(driver):
                        saw_mfa = True
                        if _fill_mfa_challenge_if_present(driver, email, timeout=2) and not _is_mfa_challenge_page(driver):
                            break
                        now = time.monotonic()
                        if now >= next_notice:
                            message = "等待认证器验证码：请在有头窗口输入当前验证码并点击继续"
                            logger.info("%s", message)
                            if callable(progress_callback):
                                progress_callback(message)
                            next_notice = now + 30
                        time.sleep(1)
                        continue
                    if saw_mfa or time.monotonic() - first_check >= 5:
                        break
                    time.sleep(1)
                else:
                    raise RuntimeError("认证器验证码等待超时；未取得新 AT，旧 AT 保持不变")
            session_timeout = min(90, max(30, timeout_seconds // 2))
            _touch_activity("session_fetch")
            if callable(progress_callback):
                progress_callback("登录步骤已完成，正在读取新会话与 AT")
            session_info = _fetch_chatgpt_session(
                driver,
                timeout=session_timeout,
                auto_jump_wait=min(30, max(10, timeout_seconds // 4)),
            )
            _touch_activity("session_received")
            if attempt_timed_out.is_set():
                raise RuntimeError(
                    f"ant_login_timeout: 登录后获取会话超过单轮总时限 {timeout_seconds}s"
                )
            token = str((session_info or {}).get("accessToken") or "").strip()
            if not token:
                raise RuntimeError("AntBrowser 登录完成，但 /api/auth/session 未返回 accessToken")
            session_info = dict(session_info)
            # Persist the authenticated browser session for a later protocol-only
            # AT renewal. Keep this secret out of logs and HTTP responses.
            try:
                cookies = driver.page.context.cookies("https://chatgpt.com/")
                cookie_names = ("__Secure-next-auth.session-token", "next-auth.session-token")
                for base in cookie_names:
                    direct = next((str(c.get("value") or "") for c in cookies if c.get("name") == base), "")
                    chunks = sorted(
                        (int(str(c.get("name"))[len(base) + 1:]), str(c.get("value") or ""))
                        for c in cookies
                        if str(c.get("name") or "").startswith(base + ".")
                        and str(c.get("name"))[len(base) + 1:].isdigit()
                    )
                    value = direct or "".join(chunk for _, chunk in chunks)
                    if value:
                        session_info["_session_token"] = value
                        break
            except Exception as cookie_exc:
                logger.debug("[Ant Browser换绑] 会话 Cookie 提取失败: %s", type(cookie_exc).__name__)
            session_info["_network_proxy"] = str((opened.raw or {}).get("proxy") or proxy or "")
            logger.info("[Ant Browser换绑] Recent Login 完成：%s", email)
            return session_info
        except Exception as exc:
            message = str(exc).lower()
            timed_out = attempt_timed_out.is_set() or "ant_login_timeout" in message
            target_closed = "页面上下文已关闭" in str(exc) or "targetclosed" in message or "target page, context or browser has been closed" in message
            navigation_failed = any(token in message for token in (
                "[navigation_error]", "chrome-error://", "browser_navigation_failed",
                "邮箱提交未确认页面迁移", "email_submit_not_confirmed", "email_submit_stalled",
                "邮箱登录入口未就绪", "尚未提交邮箱",
                "cloudflare 验证页等待超时",
            ))
            if timed_out:
                exc = RuntimeError(
                    f"ant_login_timeout: 邮箱提交/Cloudflare 页面超过单轮总时限 {_login_attempt_timeout()}s"
                )
            if not (timed_out or target_closed or navigation_failed) or attempt >= 2:
                raise exc
            if timed_out:
                reason = "单轮登录超时"
            elif navigation_failed:
                reason = "浏览器/代理导航失败"
            else:
                reason = "浏览器上下文意外关闭"
            logger.warning("[Ant Browser换绑] %s，轮换代理会话并创建新实例重试：%s", reason, email)
        finally:
            attempt_finished.set()
            watchdog_wakeup.set()
            if watchdog is not None and watchdog.is_alive():
                watchdog.join(timeout=1.0)
            if driver is not None:
                try:
                    driver.quit()
                except Exception:
                    pass
            if opened is not None and not profile_cleaned.is_set():
                try:
                    cleanup_ant_profile(opened)
                except Exception as exc:
                    logger.warning("[Ant Browser换绑] 清理临时实例失败：%s", exc)
    raise RuntimeError("AntBrowser Recent Login 未完成")
