# -*- coding: utf-8 -*-
"""注册流程事实状态：区分账号创建、发码、验码、凭证与密码状态。

该对象只保存布尔事实和阶段，不保存验证码、密码、token 或 TOTP 原文。
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any

@dataclass
class RegistrationStage:
    account_created: bool = False
    password_set: bool = False
    otp_sent: bool = False
    otp_verified: bool = False
    credential_acquired: bool = False
    existing_account: bool = False
    flow: str = "unknown"
    failure_stage: str = ""
    error_code: str = ""

    def mark(self, stage: str, value: bool = True) -> None:
        if hasattr(self, stage):
            setattr(self, stage, bool(value))

    def fail(self, stage: str, error_code: str = "unknown") -> None:
        self.failure_stage = str(stage or "unknown")
        self.error_code = str(error_code or "unknown")

    def snapshot(self) -> dict[str, Any]:
        return asdict(self)


def classify_stage_error(exc: BaseException) -> str:
    text = str(exc or "").lower()
    if "otp" in text or "验证码" in text:
        return "otp"
    if "password" in text or "密码" in text:
        return "password"
    if "token" in text or "session" in text or "oauth" in text:
        return "credential"
    if "403" in text or "cloudflare" in text or "challenge" in text:
        return "challenge"
    if "timeout" in text or "timed out" in text or "超时" in text:
        return "timeout"
    if "proxy" in text or "connect" in text or "network" in text:
        return "network"
    return "unknown"


def from_protocol_bridge(payload: dict[str, Any]) -> RegistrationStage:
    """将上游桥接结果映射为保守的事实快照。

    registered 表的行、password 字段及 partial 标记均不代表远端已确认
    密码或创建账号；只采信显式的阶段证据。输出不含任何凭证。
    """
    if not isinstance(payload, dict):
        raise TypeError("payload must be a dictionary")
    row = payload.get("result") if isinstance(payload.get("result"), dict) else {}
    facts = payload.get("registration_stage")
    if not isinstance(facts, dict):
        facts = row.get("registration_stage")
    if not isinstance(facts, dict):
        facts = {}
    have = payload.get("have") if isinstance(payload.get("have"), dict) else {}
    stage = RegistrationStage(flow="protocol_bridge")
    for name in ("account_created", "password_set", "otp_sent", "otp_verified", "existing_account"):
        stage.mark(name, facts.get(name) is True)
    stage.credential_acquired = bool(row.get("access_token") or have.get("access_token") is True)
    if not payload.get("ok"):
        stage.fail(str(facts.get("failure_stage") or "unknown"),
                   str(facts.get("error_code") or "bridge_failed"))
    return stage
