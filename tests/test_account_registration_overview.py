# -*- coding: utf-8 -*-
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import db


class AccountRegistrationOverviewTests(unittest.TestCase):
    def test_completed_credentials_override_stale_registration_status(self):
        base = {
            "status": "interrupted",
            "password_setup_remote_password_present": True,
            "password_setup_login_verified": True,
            "access_token": "AT",
            "token_expired": False,
            "plan_check_http_status": 200,
            "live_check_status": "live",
            "totp_secret": "SECRET",
            "totp_setup_ok": True,
            "totp_setup_status": "success",
        }
        self.assertTrue(db._account_registration_is_effectively_complete(base))
        self.assertEqual(db._decorate_account(base)["registration_display_status"], "complete")

        missing_totp = dict(base, totp_secret="", totp_setup_ok=False, totp_setup_status="failed")
        self.assertFalse(db._account_registration_is_effectively_complete(missing_totp))
        expired = dict(base, token_expired="true")
        self.assertFalse(db._account_registration_is_effectively_complete(expired))
        missing_password = dict(base, password_setup_login_verified=False)
        self.assertFalse(db._account_registration_is_effectively_complete(missing_password))

    def test_registration_checkpoint_counts_and_filters_are_sql_backed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            accounts_path = root / "accounts.json"
            accounts_path.write_text(json.dumps([
                {"id": 1, "email": "done@example.com", "access_token": "AT"},
                {"id": 2, "email": "running@example.com", "status": "registering", "password_setup_remote_password_present": True},
                {"id": 3, "email": "stopped@example.com", "status": "interrupted", "password_setup_remote_password_present": True},
                {"id": 4, "email": "legacy@example.com", "status": "interrupted"},
                {"id": 5, "email": "recovered@example.com", "status": "interrupted",
                 "password_setup_remote_password_present": True, "password_setup_login_verified": True, "access_token": "AT",
                 "token_expired": False, "plan_check_http_status": 200, "live_check_status": "live",
                 "totp_secret": "SECRET", "totp_setup_ok": True, "totp_setup_status": "success"},
            ], ensure_ascii=False), encoding="utf-8")
            missing = root / "missing.json"
            with patch.multiple(
                db,
                _ACCOUNTS_JSON=accounts_path,
                _LEGACY_ACCOUNTS_JSON=missing,
                _OUTLOOK_JSON=missing,
                _GENERIC_API_EMAIL_JSON=missing,
                _JOBS_JSON=missing,
                _DOMAIN_EMAIL_JSON=missing,
            ), patch.object(db, "_SQLITE_READY", False), patch.object(db, "_SQLITE_READY_PATH", None):
                summary = db.get_account_overview_summary(False)
                self.assertEqual(summary["total"], 5)
                self.assertEqual(summary["registering"], 1)
                self.assertEqual(summary["interrupted"], 2)
                self.assertEqual(summary["registration_incomplete"], 3)
                self.assertEqual(summary["registration_recovered"], 1)
                self.assertEqual(summary["password_saved"], 1)
                self.assertEqual(db.list_accounts_page(limit=20, overview_filter="registering")["total"], 1)
                self.assertEqual(db.list_accounts_page(limit=20, overview_filter="interrupted")["total"], 2)
                self.assertEqual(db.list_accounts_page(limit=20, overview_filter="registration_incomplete")["total"], 3)
                self.assertEqual(db.list_accounts_page(limit=20, overview_filter="registration_recovered")["total"], 1)
                self.assertEqual(db.list_accounts_page(limit=20, overview_filter="password_saved")["total"], 1)


if __name__ == "__main__":
    unittest.main()
