"""Separate, opt-in OSS protocol registration page and job API."""
from concurrent.futures import ThreadPoolExecutor
from threading import Lock, BoundedSemaphore
from uuid import uuid4
from flask import jsonify, render_template, request
from urllib.parse import urlparse
from datetime import datetime
from pathlib import Path
import re
import time


def _append_main_job_log(log_file, message):
    """Write a redacted OSS lifecycle line to the common registration job log."""
    if not log_file:
        return
    try:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
        with path.open("a", encoding="utf-8") as handle:
            handle.write(f"[{stamp}] {_safe_log(message)}\n")
    except OSError:
        pass

_POOL = ThreadPoolExecutor(max_workers=10, thread_name_prefix="oss-protocol")
_LOCK = Lock()
_JOBS = {}
_PROTOCOL_LOG_DIR = Path(__file__).resolve().parents[1] / "vendor" / "gpt-register-tool" / "协议" / "webui" / "logs"


def _now_text():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _safe_log(value):
    message = str(value or "")
    message = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+", "[邮箱已隐藏]", message)
    message = re.sub(r"https?://[^\s]+", "[链接已隐藏]", message)
    message = re.sub(r"(?i)(access_token|session_token|cookie|password|otp|authorization)\s*[:=]\s*\S+", r"\1=[已隐藏]", message)
    return message[:260]


def _protocol_log_snapshot(job):
    started_epoch = float(job.get("started_epoch") or 0)
    if not started_epoch or not _PROTOCOL_LOG_DIR.exists():
        return [], job.get("phase") or "等待启动"
    candidates = [p for p in _PROTOCOL_LOG_DIR.glob("*.log") if p.stat().st_mtime >= started_epoch - 3]
    if not candidates:
        return list(job.get("logs") or []), job.get("phase") or "协议引擎启动中"
    log_file = max(candidates, key=lambda item: item.stat().st_mtime)
    try:
        lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()[-120:]
    except OSError:
        return list(job.get("logs") or []), job.get("phase") or "读取协议日志"
    markers = ("OAuth", "密码注册", "OTP", "验证码", "创建账户", "账户创建", "重定向", "callback", "session:", "注册流程完成", "失败")
    visible = [_safe_log(line) for line in lines if any(marker.lower() in line.lower() for marker in markers)]
    visible = visible[-12:]
    joined = "\n".join(lines[-80:])
    phase = job.get("phase") or "协议注册运行中"
    for marker, label in (("注册流程完成", "注册完成"), ("session: st=", "获取 Session/AT"),
                          ("重定向链", "OAuth 回调收尾"), ("账户创建成功", "账户创建完成"),
                          ("创建账户", "创建账户"), ("OTP 验证成功", "验证码验证完成"),
                          ("验证 OTP", "验证邮箱验证码"), ("OTP 已发送", "等待邮箱验证码"),
                          ("密码注册成功", "密码注册完成"), ("OAuth 初始化", "OAuth 初始化")):
        if marker in joined:
            phase = label
            break
    return visible or list(job.get("logs") or []), phase


def _safe_error(value, *secrets):
    message = str(value or "")
    for secret in secrets:
        if secret:
            message = message.replace(str(secret), "[redacted]")
    message = re.sub(r"https?://[^\s]+", "[redacted-url]", message)
    return message[:300]


def register_oss_protocol_page(app):
    @app.get("/oss-protocol-register")
    def oss_protocol_register_page():
        from core.email_provider import parse_email_sources
        return render_template("oss_protocol_register.html", default_email_source=parse_email_sources()[0])

    @app.post("/api/oss-protocol/register")
    def oss_protocol_register_start():
        data = request.get_json(silent=True) or {}
        email = str(data.get("email") or "").strip()
        relay = str(data.get("relay_url") or "").strip()
        proxy = str(data.get("proxy") or "").strip()
        try:
            count = max(1, min(100, int(data.get("count", 1))))
            workers = max(1, min(10, int(data.get("workers", min(3, count)))))
        except (TypeError, ValueError):
            return jsonify(ok=False, error="注册数量和并发线程数必须是整数"), 400
        from core.email_provider import _VALID_SOURCES
        source = str(data.get("email_source") or "").strip().lower()
        if source not in (*_VALID_SOURCES, "icloud_relay"):
            return jsonify(ok=False, error="不支持的邮箱来源"), 400
        relay_parts = urlparse(relay)
        if count > 1 and email:
            return jsonify(ok=False, error="批量注册时邮箱必须留空，由邮箱池为每个任务分配独立邮箱"), 400
        if count > 1 and source == "icloud_relay":
            return jsonify(ok=False, error="iCloud HTTPS 中转目前只支持单任务；批量请使用邮箱池来源"), 400
        if source == "icloud_relay":
            if "@" not in email or relay_parts.scheme != "https" or not relay_parts.hostname or relay_parts.username:
                return jsonify(ok=False, error="中转模式需填写邮箱及 HTTPS 取件链接"), 400
        elif relay or (email and "@" not in email):
            return jsonify(ok=False, error="本地接码来源不接受中转链接，邮箱地址须有效"), 400
        if not proxy:
            from config import proxy as proxy_cfg
            if not (getattr(proxy_cfg, "PROXY_POOL", None) or []):
                return jsonify(ok=False, error="没有可用代理；请填写代理或配置代理池"), 400
        from core import db
        jobs = []
        now = _now_text()
        with _LOCK:
            for index in range(count):
                main_job = db.create_job(email_source=source)
                main_job_id = int(main_job["id"])
                job_id = uuid4().hex
                db.update_job(main_job_id, registration_stage={
                    "driver": "oss_protocol", "oss_job_id": job_id, "phase": "queued"
                })
                job = {"job_id": job_id, "main_job_id": main_job_id,
                       "batch_id": None, "batch_index": index + 1, "batch_total": count,
                       "state": "queued", "phase": "等待执行", "account_id": None,
                       "error": "", "created_at": now, "started_at": None,
                       "finished_at": None, "updated_at": now, "started_epoch": 0,
                       "logs": ["任务已进入 OSS 协议注册队列"]}
                _JOBS[job_id] = job
                jobs.append((job_id, main_job_id, main_job.get("log_file")))
            batch_id = uuid4().hex
            for job_id, _, _ in jobs:
                _JOBS[job_id]["batch_id"] = batch_id
        # 协议注册的邮箱准备可以高并发，但 OpenAI OAuth/Callback 并发过高时
        # 实测会集中出现 OTP 403/409 和一次性 callback code 过期。保留用户请求的任务数，
        # 将真实认证并发限制为稳定基线 2，后排任务自动排队。
        auth_workers = min(workers, 2)
        batch_gate = BoundedSemaphore(auth_workers)
        def make_worker(job_id, main_job_id, main_log_file):
            def sync_email(acquired_email):
                acquired_email = str(acquired_email or "").strip()
                if acquired_email:
                    db.update_job(main_job_id, email=acquired_email)
                    _append_main_job_log(main_log_file, "OSS 协议引擎已取得注册邮箱")
            def run_worker():
                started_at = _now_text()
                db.update_job(main_job_id, status="running", email=email or None, started_at=started_at,
                              registration_stage={"driver": "oss_protocol", "oss_job_id": job_id, "phase": "running"})
                _append_main_job_log(main_log_file, "OSS 协议注册任务开始执行")
                with _LOCK:
                    _JOBS[job_id].update(state="running", phase="准备邮箱和代理", started_at=started_at,
                                         updated_at=started_at, started_epoch=time.time(),
                                         logs=["任务开始执行", "正在准备邮箱来源与代理出口"])
                try:
                    from core.oss_protocol_registration import run_oss_protocol_registration
                    result = run_oss_protocol_registration(email=email, name="", birthday=None,
                        proxy=proxy, relay_url=relay or None,
                        email_source=source if source != "icloud_relay" else None,
                        batch_dir=None, on_email_acquired=sync_email)
                    state = "success" if result.get("success") else "failed"
                    done = _now_text()
                    result_email = str(result.get("email") or email or "").strip() or None
                    safe_error = _safe_error(result.get("error"), relay, proxy)
                    db.update_job(main_job_id, status=state, email=result_email,
                                  account_id=result.get("account_id"), error=safe_error,
                                  network_traffic=result.get("network_traffic"), completed_at=done,
                                  registration_stage={"driver": "oss_protocol", "oss_job_id": job_id,
                                                      "phase": "success" if state == "success" else "failed"})
                    _append_main_job_log(main_log_file,
                        "OSS 协议注册成功" if state == "success" else f"OSS 协议注册失败：{safe_error}")
                    with _LOCK:
                        _JOBS[job_id].update(state=state, phase="注册完成" if state == "success" else "注册失败",
                            account_id=result.get("account_id"), error=safe_error,
                            finished_at=done, updated_at=done)
                except Exception as exc:
                    done = _now_text()
                    safe_error = _safe_error(f"{type(exc).__name__}: {exc}", relay, proxy)
                    db.update_job(main_job_id, status="failed", email=email or None, error=safe_error, completed_at=done,
                                  registration_stage={"driver": "oss_protocol", "oss_job_id": job_id, "phase": "failed"})
                    _append_main_job_log(main_log_file, f"OSS 协议注册异常：{safe_error}")
                    with _LOCK:
                        _JOBS[job_id].update(state="failed", phase="运行异常", finished_at=done, updated_at=done,
                                             error=safe_error)
            def worker():
                with batch_gate:
                    run_worker()
            return worker
        submitted = []
        try:
            for job_id, main_job_id, log_file in jobs:
                _append_main_job_log(log_file, f"OSS 协议注册任务已进入队列（请求并发 {workers}，认证并发 {auth_workers}）")
                _POOL.submit(make_worker(job_id, main_job_id, log_file))
                submitted.append(job_id)
        except Exception as exc:
            safe_error = _safe_error(f"队列提交失败：{type(exc).__name__}: {exc}", relay, proxy)
            for job_id, main_job_id, log_file in jobs:
                if job_id not in submitted:
                    done = _now_text()
                    db.update_job(main_job_id, status="failed", error=safe_error, completed_at=done)
                    _append_main_job_log(log_file, safe_error)
                    with _LOCK:
                        _JOBS[job_id].update(state="failed", phase="队列提交失败", error=safe_error,
                                             finished_at=done, updated_at=done)
            return jsonify(ok=False, error=safe_error, job_ids=submitted), 500
        response = {"ok": True, "batch_id": batch_id, "job_ids": [x[0] for x in jobs],
                    "main_job_ids": [x[1] for x in jobs], "submitted": len(jobs),
                    "workers": workers, "auth_workers": auth_workers}
        if len(jobs) == 1:
            response.update(job_id=jobs[0][0], main_job_id=jobs[0][1])
        return jsonify(**response), 202

    @app.get("/api/oss-protocol/batches/<batch_id>")
    def oss_protocol_batch_status(batch_id):
        with _LOCK:
            payload = [dict(job) for job in _JOBS.values() if job.get("batch_id") == batch_id]
        if not payload:
            return jsonify(ok=False, error="批次不存在或服务已重启"), 404
        return jsonify(ok=True, batch_id=batch_id, jobs=payload,
                       total=len(payload), counts={state: sum(1 for job in payload if job.get("state") == state)
                                                   for state in ("queued", "running", "success", "failed")})

    @app.get("/api/oss-protocol/jobs/<job_id>")
    def oss_protocol_register_status(job_id):
        with _LOCK:
            job = _JOBS.get(job_id)
            payload = dict(job) if job is not None else None
        if payload is None:
            # OSS 的细节状态主要在内存，但服务重启后仍可从通用任务表恢复终态。
            from core import db
            for row in db.list_jobs(limit=5000):
                stage = row.get("registration_stage") or {}
                if isinstance(stage, dict) and str(stage.get("oss_job_id") or "") == str(job_id):
                    status = str(row.get("status") or "unknown")
                    state = "success" if status == "success" else ("failed" if status in {"failed", "stopped", "cancelled"} else status)
                    payload = {
                        "job_id": str(job_id), "main_job_id": row.get("id"), "state": state,
                        "phase": stage.get("phase") or state, "account_id": row.get("account_id"),
                        "error": row.get("error_message") or "", "created_at": row.get("created_at"),
                        "started_at": row.get("started_at"), "finished_at": row.get("completed_at"),
                        "updated_at": row.get("completed_at") or row.get("started_at") or row.get("created_at"),
                        "started_epoch": 0, "logs": ["服务重启后已从通用任务列表恢复状态"],
                    }
                    break
        if payload is None:
            return jsonify(ok=False, error="任务不存在或服务已重启"), 404
        logs, phase = _protocol_log_snapshot(payload)
        payload["logs"] = logs
        payload["phase"] = phase if payload.get("state") in ("queued", "running") else payload.get("phase")
        started_epoch = float(payload.pop("started_epoch", 0) or 0)
        payload["elapsed_seconds"] = max(0, int(time.time() - started_epoch)) if started_epoch else 0
        return jsonify(ok=True, **payload)
