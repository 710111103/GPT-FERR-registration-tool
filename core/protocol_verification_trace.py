"""Credential-free evidence log for one protocol password-login attempt."""
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

TRACE_DIR = Path(__file__).resolve().parent.parent / "verification" / "protocol-login"
_ALLOWED = {"code", "http_status", "valid", "identity_match", "password_accepted", "new_token_present", "outcome"}


class ProtocolVerificationTrace:
    def __init__(self, account_id: int, attempt: int):
        self.run_id = uuid4().hex
        self.account_id = int(account_id)
        self.attempt = int(attempt)
        TRACE_DIR.mkdir(parents=True, exist_ok=True)
        self.path = TRACE_DIR / f"account-{self.account_id}-{self.run_id}.jsonl"

    def __call__(self, event: str, fields: dict) -> None:
        record = {
            "run_id": self.run_id,
            "account_id": self.account_id,
            "attempt": self.attempt,
            "time_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "event": str(event),
            **{key: fields[key] for key in _ALLOWED if key in fields and type(fields[key]) in (str, bool, int)},
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
