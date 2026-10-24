# -*- coding: utf-8 -*-
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from core import db


def _patches(root: Path) -> dict:
    missing = root / "missing.json"
    return {
        "_ACCOUNTS_JSON": root / "accounts.json", "_OUTLOOK_JSON": missing,
        "_GENERIC_API_EMAIL_JSON": missing, "_DOMAIN_EMAIL_JSON": missing,
        "_JOBS_JSON": missing, "_LEGACY_ACCOUNTS_JSON": missing,
        "_LEGACY_OUTLOOK_JSON": missing, "_LEGACY_JOBS_JSON": missing,
        "_LEGACY_SQLITE": root / "legacy.db", "_CODEX_DIR": root / "codex",
        "_CODEX_AGENT_DIR": root / "agents", "_LEGACY_CODEX_EXPORT_STATE": missing,
        "_SQLITE_READY": False, "_SQLITE_READY_PATH": None,
        "_VIEWER_HTML": root / "viewer.html", "_ACCOUNTS_TXT": root / "accounts.txt",
        "_TOKENS_TXT": root / "tokens.txt",
    }


def test_protocol_registration_password_is_persisted_as_official_password():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "accounts.json").write_text("[]", encoding="utf-8")
        with patch.multiple(db, **_patches(root)):
            account_id = db.insert_account(
                email="protocol@example.test",
                access_token="at-value",
                email_source="cloudflare_domain",
                extra={
                    "engine": "oss_protocol",
                    "registration_password": "Real-Password-123!",
                    "registration_password_verified": True,
                },
            )
            account = db.get_account(account_id)
            assert account["password"] == "Real-Password-123!"
            assert account["registration_password"] == "Real-Password-123!"
            assert account["password_setup_status"] == "success"
            assert account["password_setup_login_verified"] is True
            assert account["password_setup_remote_password_present"] is True
            extra = json.loads(account["extra_json"])
            assert extra["registration_password_verified"] is True
