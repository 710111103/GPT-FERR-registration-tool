# -*- coding: utf-8 -*-
"""账号查活后台队列：协议 BrowserSession 指纹环境 + 独立日志。"""
from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path

from config import proxy as proxy_cfg
from core import db
from core.account_liveness import check_account_liveness, log_path
from core.chatgpt_plan import resolve_plan_check_route, rotate_proxy_session
from core.task_observability import ProbeSession, redact_text

logger = logging.getLogger(__name__)


def _is_explicit_http_403_challenge(value: object) -> bool:
    """Do not turn generic browser/page failures into a fabricated HTTP 403."""
    text = str(value or "").strip().lower()
    return any(marker in text for marker in (
        "http 403", "http error 403", "status=403", "status_code=403",
        "response 403", "cf-mitigated", "cloudflare challenge", "cloudflare 验证页",
    ))


def _worker_failure_result(exc: BaseException) -> dict:
    raw = f"{type(exc).__name__}: {redact_text(exc)[:500]}"
    if _is_explicit_http_403_challenge(exc):
        return {
            "ok": False,
            "status": "blocked",
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "error": "登录被验证页/HTTP 403 阻断，待重试；旧 AT 保持不变",
        }
    if "email_submit_stalled" in str(exc).lower() or "邮箱提交未确认页面迁移" in str(exc):
        return {
            "ok": False,
            "status": "failed",
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "error": f"邮箱提交停滞，未进入密码/验证码步骤；旧 AT 保持不变（{raw}）",
        }
    return {
        "ok": False,
        "status": "failed",
        "checked_at": datetime.now().isoformat(timespec="seconds"),
        "error": raw,
    }

def _fallback_failure_result(previous: dict, exc: BaseException) -> dict:
    """Report the final failure, without inferring password/account validity."""
    result = _worker_failure_result(exc)
    result["failure_stage"] = "browser_fallback"
    result["previous_error"] = redact_text(previous.get("error"))
    # Keep an explicit old-token observation, but never carry credentials forward.
    if isinstance(previous.get("token_expired"), bool):
        result["token_expired"] = previous["token_expired"]
    return result


def _int_setting(name: str, default: int, lower: int, upper: int) -> int:
    try:
        value = int(getattr(proxy_cfg, name, default) or default)
    except (TypeError, ValueError):
        value = default
    return max(lower, min(upper, value))


_WORKERS = _int_setting("LIVE_CHECK_WORKERS", 6, 1, 30)
_QUEUE_LIMIT = 500
_EXECUTOR = ThreadPoolExecutor(max_workers=_WORKERS, thread_name_prefix="live-check")
_QUEUE_SLOTS = threading.BoundedSemaphore(_QUEUE_LIMIT)
_RUNNING: set[int] = set()
_LOCK = threading.Lock()


def _parse_timestamp(value: object) -> datetime | None:
    text = str(value or "").strip().replace("Z", "+00:00")
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text)
        return parsed.replace(tzinfo=None) if parsed.tzinfo else parsed
    except ValueError:
        return None


def enqueue_due_account_live_checks(now: datetime | None = None) -> dict:
    """Queue expired AT first, then ordinary stale account checks (if enabled)."""
    from datetime import timezone
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    marked = db.mark_expired_access_tokens(now=current)
    try:
        interval = int(getattr(proxy_cfg, "ACCOUNT_LIVE_CHECK_INTERVAL_MINUTES", 360))
    except (TypeError, ValueError):
        interval = 360
    interval = max(0, min(10080, interval))
    batch_size = _int_setting("ACCOUNT_LIVE_CHECK_BATCH_SIZE", 3, 1, 100)
    auto_expired = bool(getattr(proxy_cfg, "AUTO_REFRESH_EXPIRED_AT", True))
    if interval <= 0 and not auto_expired:
        return {"enabled": False, "queued": 0, "marked_expired": marked}

    wall_now = now if now is not None and now.tzinfo is None else current.astimezone().replace(tzinfo=None)
    cutoff = wall_now - timedelta(minutes=interval)
    # Failed auto refreshes must not retry every scheduler minute.
    retry_cutoff = wall_now - timedelta(minutes=60)
    queued = 0
    scanned = 0
    accounts = db.list_accounts(limit=5000, archived=False)
    # Limit concurrent in-flight jobs across scheduler ticks, not only new jobs per tick.
    in_flight = sum(str(account.get("live_check_status") or "") in {"queued", "running"} for account in accounts)
    available = max(0, batch_size - in_flight)
    accounts.sort(key=lambda account: not bool(account.get("token_expired")))
    for account in accounts:
        scanned += 1
        if queued >= available:
            break
        if str(account.get("live_check_status") or "") in {"queued", "running", "deactivated", "dead"}:
            continue
        if not str(account.get("email") or "").strip():
            continue
        checked_at = _parse_timestamp(account.get("live_checked_at"))
        expired = bool(account.get("token_expired")) and bool(account.get("token_expires_at"))
        if expired and auto_expired:
            if checked_at is not None and checked_at > retry_cutoff:
                continue
            trigger = "expired_at_auto_refresh"
        elif interval > 0:
            if checked_at is not None and checked_at > cutoff:
                continue
            trigger = "account_live_periodic"
        else:
            continue
        result = enqueue_account_live_check(
            account_id=int(account.get("id") or 0),
            email=str(account.get("email") or ""),
            trigger=trigger,
            proxy=None,
        )
        if result.get("accepted"):
            queued += 1
    return {"enabled": True, "queued": queued, "scanned": scanned,
            "interval_minutes": interval, "marked_expired": marked}


def is_checking(email: str) -> bool:
    acc = db.get_account_by_email(email)
    if not acc:
        return False
    return str(acc.get("live_check_status") or "") in {"queued", "running"}


def _append_log(email: str, line: str, *, clear: bool = False) -> None:
    p = log_path(email)
    p.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%H:%M:%S")
    mode = "w" if clear else "a"
    with p.open(mode, encoding="utf-8") as f:
        f.write(f"{stamp} [INFO] {redact_text(line)}\n")


def _verify_browser_token(token: str, session_info: dict, account: dict, email: str, proxy: str) -> dict:
    """Independently verify a browser login before allowing an AT replacement."""
    from core.account_liveness import probe_access_token_liveness
    from core.session import BrowserSession

    user = (session_info or {}).get("user") or {}
    actual_email = str(user.get("email") or "").strip().casefold()
    if not actual_email or actual_email != str(email or "").strip().casefold():
        raise RuntimeError("新会话身份未确认：邮箱缺失或不匹配，旧 AT 保持不变")
    check_session = BrowserSession(proxy=proxy, detect_exit_geo=False)
    try:
        probe = probe_access_token_liveness(check_session, token)
    finally:
        check_session.session.close()
    if probe.get("valid") is not True or int(probe.get("status_code") or 0) != 200:
        raise RuntimeError("新 AT 独立鉴权未通过，旧 AT 保持不变：%s" % (probe.get("error") or probe.get("status_code")))
    expected_id = str(account.get("user_id") or user.get("id") or "").strip()
    probed_id = str(probe.get("user_id") or "").strip()
    if expected_id and probed_id and expected_id != probed_id:
        raise RuntimeError("新 AT 账号 ID 不匹配，旧 AT 保持不变")
    return probe


def _run_live_check(*, account_id: int, email: str, proxy: str | None, trigger: str) -> dict:
    result: dict = {}
    probe = ProbeSession("live_check", account_id, email=email, trigger=trigger)
    probe_context = probe.activate()
    probe_context.__enter__()
    probe.mark("worker", "started")
    try:
        with _LOCK:
            _RUNNING.add(int(account_id))
        if not db.mark_account_live_check_running(account_id):
            _append_log(email, "[查活] 账号已删除或查活状态已被重置，取消执行")
            result = {"ok": False, "status": "failed", "error": "账号已删除或查活状态已被重置"}
            probe.mark("claim", "failed", error=result["error"])
            return result
        probe.mark("claim", "ok")
        try:
            account = db.get_account(account_id) or {}
        except Exception:
            account = {}
        # 优先使用显式传入的 proxy 或当前全局配置中的代理池/套餐代理
        route = resolve_plan_check_route(explicit_proxy=proxy if proxy else None)
        selected_proxy = route.get("proxy")
        if not selected_proxy:
            raise RuntimeError("查活需要代理：当前没有可用代理，请检查代理池和套餐查询代理配置；不会直连")
        if selected_proxy:
            # 无论来自配置还是历史，均强制轮换生成全新动态会话 sid，确保出口 IP 新鲜且未过期
            selected_proxy, _ = rotate_proxy_session(selected_proxy)
        email_source = str(account.get("email_source") or "").strip() or None
        if email_source:
            _append_log(email, f"[查活] 使用注册时保存的邮箱来源：{email_source}")
        _append_log(
            email,
            "[查活] 开始后台执行 "
            f"trigger={trigger} network_route={route.get('network_route')} "
            f"proxy_mode={route.get('proxy_mode')} proxy_used={route.get('proxy_used') or '-'} "
            f"fallback_reason={route.get('proxy_fallback_reason') or '-'}"
        )

        ant_headless_refresh = trigger in ("manual_ant_headless_refresh", "manual_headed_refresh")
        if ant_headless_refresh:
            _append_log(email, "[Ant 无头刷新AT] 开始无头浏览器重新登录；本次不复用旧 AT 探测结果")
            from core.antbrowser_liveness import refresh_recent_login_browser
            session_info = refresh_recent_login_browser(
                email, email_source=email_source, proxy=selected_proxy, force_headless=True,
                progress_callback=lambda message: _append_log(email, f"[Ant 无头刷新AT] {message}"),
            )
            fresh_token = str((session_info or {}).get("accessToken") or "").strip()
            if not fresh_token:
                raise RuntimeError("Ant 无头登录未取得 accessToken，旧 AT 保持不变")
            _verify_browser_token(fresh_token, session_info, account, email, session_info.get("_network_proxy") or selected_proxy)
            result = {
                "ok": True, "status": "live", "access_token": fresh_token,
                "token_expired": False, "error": None,
                "checked_at": datetime.now().isoformat(timespec="seconds"),
                "proxy_used": session_info.get("_network_proxy") or selected_proxy,
                "session_token": session_info.get("_session_token") or "",
            }
            _append_log(email, "[Ant 无头刷新AT] 登录返回新 AT，准备写入数据库")

        # 换绑后或普通查活均执行纯协议静默流程（支持密码/邮箱OTP/TOTP-MFA）。
        # 可重试的网络/代理错误会创建全新认证会话；每轮优先重新从代理池
        # 选择代理，再为动态代理生成新的 sid，避免继续使用已变更/失效的出口。
        configured_retries = _int_setting("ACCOUNT_LIVE_CHECK_NETWORK_RETRIES", 2, 1, 4)
        attempts = max(
            3 if str(trigger or "").startswith("email_change") else 1,
            configured_retries,
        )
        explicit_proxy = proxy is not None and bool(str(proxy).strip())
        for network_attempt in range(1, attempts + 1):
            if ant_headless_refresh:
                break
            attempt_proxy = selected_proxy
            proxy_session_id = None
            route_changed = False
            if network_attempt > 1 and not explicit_proxy and str(route.get("network_route") or "") == "proxy":
                # 重新解析 route：代理池发生切换时，不复用上一轮的 endpoint。
                refreshed_route = resolve_plan_check_route(explicit_proxy=None)
                refreshed_proxy = str(refreshed_route.get("proxy") or "").strip()
                if not refreshed_proxy:
                    _append_log(email, "[查活] 代理池刷新后无可用代理，保留上一条代理；不会直连")
                else:
                    route = refreshed_route
                    selected_proxy = refreshed_proxy
                    route_changed = selected_proxy != attempt_proxy
            if selected_proxy and network_attempt > 1:
                attempt_proxy, proxy_session_id = rotate_proxy_session(selected_proxy)
            if network_attempt > 1:
                _append_log(
                    email,
                    f"[查活] 风控/网络失败后创建全新认证会话 {network_attempt}/{attempts}，"
                    f"proxy_sid_rotated={'yes' if proxy_session_id else 'no'} "
                    f"proxy_endpoint_changed={'yes' if route_changed else 'no'}",
                )
            stage = f"authentication_attempt_{network_attempt}"
            probe.mark(stage, "started", network_route=route.get("network_route"))
            result = check_account_liveness(
                email, proxy=attempt_proxy, clear_log=False,
                email_source=email_source, fingerprint_state={},
            )
            if result.get("ok"):
                probe.mark(stage, "ok")
            else:
                probe.mark(stage, "failed", error=result.get("error") or result.get("status"))
            if result.get("ok") or result.get("status") == "deactivated":
                break
            err_text = str(result.get("error") or "").lower()
            retryable_network = any(marker in err_text for marker in (
                "403", "429", "tls", "ssl", "proxy", "timeout", "timed out",
                "connection", "connect", "reset", "eof",
            ))
            # 403 非连接错误不重复提交认证请求；后续浏览器兜底沿用代理。
            if "403" in err_text and "connection" not in err_text and "connect" not in err_text:
                break
            if not retryable_network or network_attempt >= attempts:
                break
            if "403" in err_text:
                try:
                    from core.chatgpt_plan import configured_country_proxies, _mask_proxy
                    c_proxies = configured_country_proxies()
                    if c_proxies:
                        jp_or_us = [p for c, p in c_proxies if c.upper() in {"JP", "US"}]
                        candidate = jp_or_us[0] if jp_or_us else c_proxies[0][1]
                        if candidate and candidate != selected_proxy:
                            _append_log(email, f"[查活] 收到 403，切换国家候选代理重试：{_mask_proxy(candidate)}")
                            selected_proxy = candidate
                except Exception:
                    pass
            time.sleep(float(network_attempt))
        # 纯协议受阻时，后台查活使用隔离的 Ant 无头实例；手动有头入口保持独立。
        # token_expired 只描述旧 AT，不代表账号失效，不能阻止重新登录。
        if (
            not ant_headless_refresh
            and not result.get("ok")
            and result.get("status") != "deactivated"
            and "403" in str(result.get("error") or "")
            and not any(kw in str(result.get("error") or "") for kw in ("超时", "timeout", "未找到注册密码", "验证码"))
        ):
            _append_log(
                email,
                f"[查活] 纯协议登录受阻（{result.get('error') or '未知'}），调用 Ant 无头浏览器尝试登录获取最新 AT...",
            )
            try:
                from core.antbrowser_liveness import refresh_recent_login_browser
                session_info = refresh_recent_login_browser(
                    email,
                    email_source=email_source,
                    proxy=selected_proxy,
                    force_headless=True,
                    progress_callback=lambda message: _append_log(email, f"[自动无头刷新AT] {message}"),
                )
                fresh_token = str((session_info or {}).get("accessToken") or "").strip()
                if fresh_token:
                    _verify_browser_token(fresh_token, session_info, account, email, session_info.get("_network_proxy") or selected_proxy)
                    result = {
                        "ok": True,
                        "status": "live",
                        "access_token": fresh_token,
                        "token_expired": False,
                        "error": None,
                        "checked_at": datetime.now().isoformat(timespec="seconds"),
                        "session_token": session_info.get("_session_token") or "",
                    }
                    _append_log(email, "[查活] Ant 无头浏览器登录成功，已刷新最新 AT/accessToken")
                else:
                    result = _fallback_failure_result(
                        result, RuntimeError("浏览器流程结束但未返回 accessToken；账号与密码状态未判定")
                    )
                    _append_log(email, f"[查活] {result['error']}")
            except Exception as b_exc:
                result = _fallback_failure_result(result, b_exc)
                logger.warning("[查活] 浏览器兜底失败: %s", result["error"])
                _append_log(email, f"[查活] 浏览器兜底失败：{result['error']}")

        if not result.get("ok") and _is_explicit_http_403_challenge(result.get("error")) and result.get("status") != "deactivated":
            result["status"] = "blocked"
            _append_log(email, "[查活] 登录被验证页/403 阻断，待重试；账号与密码状态未判定")
        persisted = db.update_account_liveness(account_id, result)
        if not persisted:
            raise RuntimeError("查活结果未写入数据库：账号可能已删除")
        probe.mark("persist_result", "ok", live_status=result.get("status"))
        if result.get("ok"):
            _append_log(email, "[查活] 完成：账号正常，已刷新最新 AT/accessToken")
            fresh_token = str(result.get("access_token") or "").strip()
            if fresh_token and bool(getattr(proxy_cfg, "AUTO_PLAN_CHECK_AFTER_LIVE_REFRESH", False)):
                try:
                    from core import plan_check_service
                    queued = plan_check_service.enqueue_account_plan_check(
                        account_id=account_id,
                        email=email,
                        access_token=fresh_token,
                        trigger="live_check_refresh",
                    )
                    _append_log(
                        email,
                        "[查活] 新 AT 套餐复查已入队" if queued.get("accepted")
                        else f"[查活] 新 AT 套餐复查未入队：{queued.get('error') or '任务繁忙'}",
                    )
                except Exception as plan_exc:
                    logger.warning("[查活] 新 AT 套餐复查入队失败: %s", plan_exc)
                    _append_log(email, f"[查活] 新 AT 套餐复查入队失败：{plan_exc}")
            elif fresh_token:
                _append_log(email, "[查活] 已按配置跳过套餐/试用资格自动刷新")
        elif result.get("status") == "deactivated":
            _append_log(email, f"[查活] 完成：账号已废 {result.get('error') or ''}")
        else:
            _append_log(email, f"[查活] 完成：失败 {result.get('error') or ''}")
        return result
    except Exception as exc:
        result = _worker_failure_result(exc)
        try:
            db.update_account_liveness(account_id, result)
        except Exception:
            logger.exception("[查活] 写入异常状态失败: account_id=%s", account_id)
        logger.exception("[查活] 后台异常: %s", email)
        try:
            _append_log(email, f"[查活] 后台异常：{result['error']}")
        except Exception:
            pass
        return result
    finally:
        try:
            final_ok = bool(result.get("ok"))
            final_error = result.get("error")
            probe.mark("worker", "ok" if final_ok else "failed", error=None if final_ok else final_error)
            summary = probe.finish("ok" if final_ok else "failed", error=None if final_ok else final_error)
            _append_log(
                email,
                "[观测] first_failure=%s category=%s requests=%s traffic=%sB"
                % (
                    summary.get("first_failure_stage") or "-",
                    summary.get("first_failure_category") or "-",
                    summary.get("traffic", {}).get("request_count", 0),
                    summary.get("traffic", {}).get("total_bytes", 0),
                ),
            )
        except Exception:
            logger.debug("[查活] 写入结构化观测失败", exc_info=True)
        finally:
            probe_context.__exit__(None, None, None)
        with _LOCK:
            _RUNNING.discard(int(account_id))
        try:
            _QUEUE_SLOTS.release()
        except ValueError:
            pass


def enqueue_account_live_check(*, account_id: int, email: str, trigger: str = "manual", proxy: str | None = None) -> dict:
    account_id = int(account_id)
    email = str(email or "").strip()
    if not email:
        return {"accepted": False, "busy": False, "error": "email 为空"}
    if not _QUEUE_SLOTS.acquire(blocking=False):
        return {"accepted": False, "busy": False, "queue_full": True, "error": "查活队列已满，请稍后重试"}
    if not db.claim_account_live_check(acc_id=account_id, trigger=trigger):
        _QUEUE_SLOTS.release()
        return {"accepted": False, "busy": True, "error": "该账号正在查活"}

    _append_log(email, f"[查活] 已入队 account_id={account_id} trigger={trigger}", clear=True)
    try:
        _EXECUTOR.submit(
            _run_live_check,
            account_id=account_id,
            email=email,
            proxy=proxy,
            trigger=str(trigger or "manual"),
        )
    except Exception as exc:
        _QUEUE_SLOTS.release()
        result = {
            "ok": False,
            "status": "failed",
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "error": f"查活入队失败: {type(exc).__name__}: {str(exc)[:160]}",
        }
        db.update_account_liveness(account_id, result)
        _append_log(email, result["error"])
        return {"accepted": False, "busy": False, "error": result["error"]}

    return {
        "accepted": True,
        "busy": False,
        "account_id": account_id,
        "email": email,
        "status": "queued",
        "trigger": str(trigger or "manual"),
    }


def enqueue_account_live_checks_batch(
    accounts: list[dict],
    trigger: str = "manual",
    proxy: str | None = None,
) -> tuple[list[dict], list[dict], list[dict]]:
    """批量查活快速入队：批量单次锁定数据库，入队延迟降低 99% 以上。"""
    valid_accs = [acc for acc in accounts if (acc.get("email") or "").strip()]
    acc_ids = [int(acc.get("id")) for acc in valid_accs]
    claimed_ids = db.claim_account_live_checks_batch(acc_ids, trigger=trigger)

    started, busy, failed = [], [], []
    for acc in valid_accs:
        aid = int(acc.get("id"))
        email = str(acc.get("email") or "")
        if aid not in claimed_ids:
            busy.append({"id": aid, "email": email, "reason": "该账号正在查活"})
            continue
        if not _QUEUE_SLOTS.acquire(blocking=False):
            failed.append({"id": aid, "email": email, "reason": "查活队列已满"})
            continue
        _append_log(email, f"[查活] 已入队 account_id={aid} trigger={trigger}", clear=True)
        try:
            _EXECUTOR.submit(
                _run_live_check,
                account_id=aid,
                email=email,
                proxy=proxy,
                trigger=str(trigger or "manual"),
            )
            started.append({"id": aid, "email": email, "accepted": True, "status": "queued"})
        except Exception as exc:
            _QUEUE_SLOTS.release()
            failed.append({"id": aid, "email": email, "reason": str(exc)})
    return started, busy, failed


def queue_progress(email: str) -> dict:
    """Read-only snapshot for a queued account; no worker or network request is started."""
    account = db.get_account_by_email(email) or {}
    status = str(account.get("live_check_status") or "")
    queued_at = _parse_timestamp(account.get("live_check_queued_at"))
    started_at = _parse_timestamp(account.get("live_check_started_at"))
    now = datetime.now()
    age = max(0, int((now - queued_at).total_seconds())) if queued_at else None
    progress = {"status": status, "queued_at": account.get("live_check_queued_at"),
                "started_at": account.get("live_check_started_at"), "wait_seconds": age,
                "workers": _WORKERS}
    if status == "queued":
        queued = [row for row in db.list_accounts(limit=5000, archived="all")
                  if row.get("live_check_status") == "queued"]
        queued.sort(key=lambda row: (str(row.get("live_check_queued_at") or ""), int(row.get("id") or 0)))
        position = next((index for index, row in enumerate(queued, 1)
                         if int(row.get("id") or 0) == int(account.get("id") or 0)), None)
        progress.update({"position": position, "queued_total": len(queued)})
    elif status == "running" and started_at:
        progress["running_seconds"] = max(0, int((now - started_at).total_seconds()))
    elif status == "failed":
        progress["error"] = str(account.get("live_check_error") or "")[:500]
    return progress


def queue_settings() -> dict:
    return {"workers": _WORKERS, "queue_limit": _QUEUE_LIMIT}

