# -*- coding: utf-8 -*-
"""后台任务的结构化阶段探针与协议流量归因。

事件按任务写入 JSONL。当前探针通过 ContextVar 隔离，因此多个线程并发时，
BrowserSession 上报的请求只会计入创建它的注册/查活/套餐任务。
"""
from __future__ import annotations

import contextvars
import hashlib
import json
import os
import re
import threading
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlparse


_ROOT = Path(os.getenv("TASK_PROBE_DIR", "注册日志/structured-probes"))
_CURRENT: contextvars.ContextVar["ProbeSession | None"] = contextvars.ContextVar(
    "task_observability_probe", default=None,
)
_WRITE_LOCK = threading.Lock()
_SAFE_NAME = re.compile(r"[^0-9A-Za-z@._-]+")
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]+=*")
_PROXY_AUTH = re.compile(r"(?i)((?:https?|socks4a?|socks5h?)://)([^/@:\s]+):([^/@\s]+)@")
_SECRET_PAIR = re.compile(
    r"(?i)(password|passwd|access[_-]?token|refresh[_-]?token|authorization|cookie|otp|totp|secret)"
    r"(\s*[:=]\s*)([^,;\s]+)"
)
_QUOTED_SECRET = re.compile(
    r"(?i)([\"'](?:password|passwd|access[_-]?token|refresh[_-]?token|session[_-]?token|authorization|cookie|otp|totp|secret)[\"']\s*:\s*)"
    r"(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')"
)
_FINGERPRINT_KEYS = (
    "browser_family", "browser_os", "user_agent", "accept_language",
    "navigator_language", "navigator_languages", "timezone_iana",
    "timezone_offset_minutes", "screen_width", "screen_height",
    "device_pixel_ratio", "hardware_concurrency", "device_memory",
    "sec_ch_ua", "sec_ch_ua_platform", "sec_ch_ua_platform_version",
)


def _safe(value: object, fallback: str = "task") -> str:
    text = _SAFE_NAME.sub("_", str(value or "").strip()).strip("._-")
    return (text or fallback)[:120]


def redact_text(value: object) -> str:
    text = str(value or "")
    text = _QUOTED_SECRET.sub(lambda m: m.group(1) + '"<REDACTED>"', text)
    text = _BEARER.sub("Bearer <REDACTED>", text)
    text = _PROXY_AUTH.sub(r"\1***:***@", text)
    text = _SECRET_PAIR.sub(r"\1\2<REDACTED>", text)
    return text[:1000]


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            normalized = str(key).lower().replace("-", "_")
            if any(mark in normalized for mark in (
                "password", "token", "secret", "authorization", "cookie", "otp", "totp",
            )):
                out[str(key)] = "<REDACTED>"
            else:
                out[str(key)] = _redact(item)
        return out
    if isinstance(value, (list, tuple, set)):
        return [_redact(item) for item in value]
    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"<bytes:{len(value)}>"
    if isinstance(value, str):
        return redact_text(value)
    return value


def classify_error(value: object) -> str:
    text = str(value or "").lower()
    if any(x in text for x in ("account_deactivated", "account deleted", "account suspended")):
        return "account_deactivated"
    if "email_submit_stalled" in text or "邮箱提交停滞" in text or "email_submit_not_confirmed" in text:
        return "email_submit_stalled"
    if "403" in text or "cloudflare" in text or "cf-mitigated" in text:
        return "http_403_challenge"
    if "429" in text or "rate limit" in text:
        return "rate_limited"
    if "otp" in text or "验证码" in text:
        return "otp"
    if "timeout" in text or "timed out" in text or "超时" in text:
        return "timeout"
    if any(x in text for x in ("proxy", "connection", "connect", "ssl", "tls", "eof", "reset")):
        return "network"
    if "cancel" in text or "stopped" in text or "停止" in text or "取消" in text:
        return "cancelled"
    return "unknown"


def fingerprint_signature(summary: dict[str, Any]) -> str:
    """生成不包含任务随机 ID 的语义指纹签名。"""
    payload = {key: summary.get(key) for key in _FINGERPRINT_KEYS}
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def environment_snapshot(summary: dict[str, Any]) -> dict[str, Any]:
    """从 BrowserSession 摘要提取适合冻结和对账的环境字段。"""
    return {
        "device_id": str(summary.get("device_id") or ""),
        "proxy": redact_text(summary.get("proxy") or "direct"),
        "proxy_mode": str(summary.get("proxy_mode") or ""),
        "geo_ip": str(summary.get("geo_ip") or ""),
        "geo_country": str(summary.get("geo_country") or "").upper(),
        "geo_region": str(summary.get("geo_region") or ""),
        "browser_family": str(summary.get("browser_family") or ""),
        "browser_os": str(summary.get("browser_os") or ""),
        "navigator_language": str(summary.get("navigator_language") or ""),
        "timezone_iana": str(summary.get("timezone_iana") or ""),
        "timezone_offset_minutes": summary.get("timezone_offset_minutes"),
        "screen": [summary.get("screen_width"), summary.get("screen_height"), summary.get("device_pixel_ratio")],
        "fingerprint_signature": fingerprint_signature(summary),
    }


class ProbeSession:
    """一个后台任务的阶段与流量账本。"""

    def __init__(self, operation: str, subject: object, **base_details: Any):
        self.operation = _safe(operation, "operation")
        self.subject = _safe(subject)
        self.base_details = _redact(base_details)
        self.started_at = time.perf_counter()
        self._stage_started: dict[str, float] = {}
        self._events: list[dict[str, Any]] = []
        self._first_failure: dict[str, Any] | None = None
        self._frozen_environment: dict[str, Any] | None = None
        self._traffic = {
            "upload_bytes": 0,
            "download_bytes": 0,
            "request_count": 0,
            "by_host": {},
        }
        self._lock = threading.RLock()
        self.path = _ROOT / self.operation / f"{self.subject}.jsonl"

    @contextmanager
    def activate(self) -> Iterator["ProbeSession"]:
        token = _CURRENT.set(self)
        try:
            yield self
        finally:
            _CURRENT.reset(token)

    def mark(
        self,
        stage: str,
        status: str,
        *,
        error: object | None = None,
        duration_ms: int | None = None,
        **details: Any,
    ) -> dict[str, Any]:
        stage = _safe(stage, "stage")
        status = str(status or "info").strip().lower()
        now = time.perf_counter()
        with self._lock:
            if status == "started":
                self._stage_started[stage] = now
            elif duration_ms is None and stage in self._stage_started:
                duration_ms = int((now - self._stage_started[stage]) * 1000)
                self._stage_started.pop(stage, None)
            event: dict[str, Any] = {
                "timestamp": datetime.now().isoformat(timespec="milliseconds"),
                "operation": self.operation,
                "subject": self.subject,
                "stage": stage,
                "status": status,
            }
            if duration_ms is not None:
                event["duration_ms"] = max(0, int(duration_ms))
            merged = dict(self.base_details)
            merged.update(_redact(details))
            if merged:
                event["details"] = merged
            if error is not None:
                event["error"] = redact_text(error)
                event["error_category"] = classify_error(error)
            if status == "failed" and self._first_failure is None:
                self._first_failure = dict(event)
            self._events.append(event)
            self._append(event)
            return dict(event)

    @contextmanager
    def step(self, stage: str, **details: Any) -> Iterator[None]:
        self.mark(stage, "started", **details)
        try:
            yield
        except Exception as exc:
            self.mark(stage, "failed", error=exc, **details)
            raise
        else:
            self.mark(stage, "ok", **details)

    def record_http(self, url: str, upload_bytes: int, download_bytes: int, status_code: int = 0) -> None:
        host = (urlparse(str(url or "")).hostname or "unknown").lower()
        up = max(0, int(upload_bytes or 0))
        down = max(0, int(download_bytes or 0))
        with self._lock:
            self._traffic["upload_bytes"] += up
            self._traffic["download_bytes"] += down
            self._traffic["request_count"] += 1
            bucket = self._traffic["by_host"].setdefault(host, {
                "upload_bytes": 0, "download_bytes": 0, "request_count": 0, "statuses": {},
            })
            bucket["upload_bytes"] += up
            bucket["download_bytes"] += down
            bucket["request_count"] += 1
            code = str(int(status_code or 0))
            bucket["statuses"][code] = int(bucket["statuses"].get(code, 0)) + 1

    def observe_environment(self, summary: dict[str, Any]) -> dict[str, Any]:
        """冻结首个环境；后续 BrowserSession 重建时报告具体变化。"""
        observed = environment_snapshot(summary)
        with self._lock:
            if self._frozen_environment is None:
                self._frozen_environment = dict(observed)
                self.mark("environment_freeze", "ok", environment=observed)
                return {"frozen": True, "changed": False, "differences": {}}

            expected = self._frozen_environment
            differences: dict[str, dict[str, Any]] = {}
            for key in (
                "device_id", "proxy_mode", "geo_ip", "geo_country", "browser_family",
                "browser_os", "navigator_language", "timezone_iana",
                "timezone_offset_minutes", "screen", "fingerprint_signature",
            ):
                before = expected.get(key)
                after = observed.get(key)
                if before not in (None, "", []) and after not in (None, "", []) and before != after:
                    differences[key] = {"expected": before, "observed": after}
            self.mark(
                "environment_consistency", "changed" if differences else "ok",
                differences=differences, environment=observed,
            )
            return {"frozen": False, "changed": bool(differences), "differences": differences}

    def observe_runtime(self, profile: dict[str, Any], runtime: dict[str, Any]) -> dict[str, Any]:
        expected_screen = [profile.get("screen_width"), profile.get("screen_height"), profile.get("device_pixel_ratio")]
        checks = {
            "language_matches": not runtime.get("language") or runtime.get("language") == profile.get("navigator_language"),
            "timezone_matches": not runtime.get("timezone") or runtime.get("timezone") == profile.get("timezone_iana"),
            "screen_matches": not runtime.get("screen") or runtime.get("screen") == expected_screen,
            "webdriver_hidden": runtime.get("webdriver") in (False, None),
        }
        self.mark(
            "runtime_environment_check", "ok" if all(checks.values()) else "changed",
            checks=checks,
            runtime={
                "language": runtime.get("language"), "timezone": runtime.get("timezone"),
                "screen": runtime.get("screen"), "webdriver": runtime.get("webdriver"),
            },
        )
        return {"all_passed": all(checks.values()), "checks": checks}

    def traffic(self) -> dict[str, Any]:
        with self._lock:
            out = json.loads(json.dumps(self._traffic))
        out["total_bytes"] = int(out["upload_bytes"]) + int(out["download_bytes"])
        return out

    def finish(self, status: str, *, error: object | None = None, **details: Any) -> dict[str, Any]:
        for stage in list(self._stage_started):
            self.mark(stage, "failed", error=error or "task ended before stage completion")
        summary = {
            "elapsed_ms": int((time.perf_counter() - self.started_at) * 1000),
            "traffic": self.traffic(),
            "first_failure_stage": (self._first_failure or {}).get("stage"),
            "first_failure_category": (self._first_failure or {}).get("error_category"),
        }
        summary.update(details)
        self.mark("task", status, error=error, **summary)
        return summary

    def summary(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "subject": self.subject,
            "path": str(self.path),
            "events": len(self._events),
            "first_failure": dict(self._first_failure) if self._first_failure else None,
            "traffic": self.traffic(),
        }

    def _append(self, event: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(event, ensure_ascii=False, default=str)
        with _WRITE_LOCK:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")


def record_http_traffic(url: str, upload_bytes: int, download_bytes: int, status_code: int = 0) -> None:
    probe = _CURRENT.get()
    if probe is not None:
        probe.record_http(url, upload_bytes, download_bytes, status_code)


def observe_environment(summary: dict[str, Any]) -> dict[str, Any] | None:
    probe = _CURRENT.get()
    return probe.observe_environment(summary) if probe is not None else None


def observe_runtime_environment(profile: dict[str, Any], runtime: dict[str, Any]) -> dict[str, Any] | None:
    probe = _CURRENT.get()
    return probe.observe_runtime(profile, runtime) if probe is not None else None


def read_events(operation: str, subject: object, limit: int = 200) -> list[dict[str, Any]]:
    path = _ROOT / _safe(operation, "operation") / f"{_safe(subject)}.jsonl"
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    items: list[dict[str, Any]] = []
    for line in lines[-max(1, min(int(limit or 200), 2000)):]:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            items.append(item)
    return items


__all__ = [
    "ProbeSession", "classify_error", "environment_snapshot", "fingerprint_signature",
    "observe_environment", "observe_runtime_environment", "read_events",
    "record_http_traffic", "redact_text",
]
