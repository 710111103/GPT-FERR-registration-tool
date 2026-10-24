# -*- coding: utf-8 -*-
"""Registration checkpoint health classification for the local workbench.

This module is deliberately read-only: it classifies persisted account state and
never starts a browser, sends mail, or changes remote account state.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

_PENDING = {"registering", "interrupted"}

def _parse_time(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)

def classify_registration_health(account: dict[str, Any], *, now: datetime | None = None, stale_after_minutes: int = 15) -> dict[str, Any]:
    status = str(account.get("status") or "").strip().lower()
    password_ok = bool(account.get("password_setup_ok")) or bool(account.get("password_setup_remote_password_present"))
    updated = _parse_time(account.get("updated_at"))
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    age_seconds = max(0, int((current.astimezone(timezone.utc) - updated).total_seconds())) if updated else None
    stale = status == "registering" and age_seconds is not None and age_seconds >= max(1, int(stale_after_minutes)) * 60
    if status == "interrupted":
        reason = "任务已中断，检查记录中的最后错误"
        action = "review_or_resume"
    elif stale:
        reason = f"超过 {max(1, int(stale_after_minutes))} 分钟没有状态更新"
        action = "inspect_stale_task"
    elif status == "registering" and password_ok:
        reason = "密码检查点已保存，等待后续注册阶段"
        action = "wait_or_resume"
    elif status == "registering":
        reason = "注册流程仍在处理中，尚未保存密码检查点"
        action = "wait"
    else:
        reason = "不属于注册待完成状态"
        action = "none"
    return {
        "status": status,
        "pending": status in _PENDING,
        "password_checkpoint_saved": password_ok,
        "updated_at": account.get("updated_at"),
        "age_seconds": age_seconds,
        "stale": stale,
        "reason": reason,
        "recommended_action": action,
    }

def summarize_registration_health(accounts: list[dict[str, Any]], *, now: datetime | None = None, stale_after_minutes: int = 15) -> dict[str, Any]:
    items = []
    for account in accounts:
        health = classify_registration_health(account, now=now, stale_after_minutes=stale_after_minutes)
        if health["pending"]:
            item = {"id": account.get("id"), "email": account.get("email"), **health}
            items.append(item)
    counts = {"pending": len(items), "registering": 0, "interrupted": 0, "stale": 0, "password_checkpoint_saved": 0}
    for item in items:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
        for key in ("stale", "password_checkpoint_saved"):
            if item[key]:
                counts[key] += 1
    return {"counts": counts, "items": items}
