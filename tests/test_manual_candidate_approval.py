import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from core import db


def test_manual_approval_is_visible_without_forging_login_verification():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "accounts.json").write_text(json.dumps([
            {"id": 1, "email": "a@example.test", "password_setup_candidate": "Candidate-123!",
             "password_setup_status": "verification_pending", "password_setup_login_verified": False,
             "extra_json": "{}"},
            {"id": 2, "email": "b@example.test", "password_setup_candidate": "Bad-123!",
             "password_setup_status": "verification_failed", "extra_json": "{}"},
        ]), encoding="utf-8")
        missing = root / "missing.json"
        patches = {"_ACCOUNTS_JSON": root / "accounts.json", "_OUTLOOK_JSON": missing,
                   "_JOBS_JSON": missing, "_LEGACY_SQLITE": root / "legacy.db",
                   "_SQLITE_READY": False, "_SQLITE_READY_PATH": None}
        with patch.multiple(db, **patches):
            assert db.approve_candidate_passwords_manually([1, 2]) == [1, 2]
            first, second = db.get_account(1), db.get_account(2)
            assert db.get_registration_password(first) == "Candidate-123!"
            assert not db.account_password_login_verified(first)
            assert first["password_setup_status"] == "manual_approved"
            assert second["password_setup_status"] == "manual_approved"
            assert db._password_extra(second)["registration_password_before_manual_status"] == "verification_failed"
            assert not db.account_password_login_verified(second)
