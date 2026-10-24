# -*- coding: utf-8 -*-
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import db


class AccountPlanFilterTests(unittest.TestCase):
    def test_plus_trial_and_no_trial_filters_use_sql(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            accounts_path = root / "accounts.json"
            accounts_path.write_text(json.dumps([
                {"id": 1, "email": "eligible@example.com", "current_plan_type": "free", "plus_trial_eligible": True},
                {"id": 2, "email": "not-eligible@example.com", "current_plan_type": "free", "plus_trial_eligible": False},
                {"id": 3, "email": "paid@example.com", "current_plan_type": "plus", "plus_trial_eligible": True},
                {"id": 4, "email": "missing-plan@example.com", "plus_trial_eligible": True},
                {"id": 5, "email": "unknown-eligibility@example.com", "current_plan_type": "free"},
                {"id": 6, "email": "discount@example.com", "current_plan_type": "free",
                 "plus_trial_eligible": True, "plus_trial_campaign_id": "go-2-months-50-pct-off",
                 "plus_trial_title": "Get a 50% discount on Go for 2 months",
                 "plus_trial_discount_percentage": 50},
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
                for filter_name in ("plus_trial", "plus_trial_eligible", "trial"):
                    result = db.list_accounts_page(limit=20, plan_filter=filter_name)
                    self.assertEqual([item["id"] for item in result["items"]], [1])

                free_result = db.list_accounts_page(limit=20, plan_filter="free")
                self.assertEqual([item["id"] for item in free_result["items"]], [6, 5, 2, 1])

                no_trial_result = db.list_accounts_page(limit=20, plan_filter="free_no_trial")
                self.assertEqual([item["id"] for item in no_trial_result["items"]], [6, 2])

                discount_result = db.list_accounts_page(limit=20, plan_filter="discount")
                self.assertEqual([item["id"] for item in discount_result["items"]], [6])
                discount_row = discount_result["items"][0]
                self.assertFalse(discount_row["plus_trial_eligible"])
                self.assertTrue(discount_row["discount_offer_eligible"])
                self.assertEqual(discount_row["discount_offer_percentage"], 50)

                snapshot = db.list_account_plan_check_statuses(limit=20, plan_filter="plus_trial")
                self.assertEqual([item["id"] for item in snapshot["items"]], [1])

                free_snapshot = db.list_account_plan_check_statuses(limit=20, plan_filter="free")
                self.assertEqual([item["id"] for item in free_snapshot["items"]], [6, 5, 2, 1])

                no_trial_snapshot = db.list_account_plan_check_statuses(limit=20, plan_filter="free_no_trial")
                self.assertEqual([item["id"] for item in no_trial_snapshot["items"]], [6, 2])


    def test_liveness_changes_appear_in_lightweight_snapshot_and_revision(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            accounts_path = root / "accounts.json"
            accounts_path.write_text(json.dumps([{
                "id": 1, "email": "snapshot@example.com", "access_token": "placeholder",
                "token_expired": True, "live_check_status": "queued",
                "live_check_queued_at": "2026-01-01T00:00:00",
                "updated_at": "2026-01-01T00:00:00",
            }]), encoding="utf-8")
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
                queued = db.list_account_plan_check_statuses(limit=20)
                self.assertEqual(queued["items"][0]["live_check_status"], "queued")
                self.assertTrue(queued["items"][0]["token_expired"])
                db.update_account_liveness(1, {"status": "failed", "error": "验证页", "token_expired": True})
                failed = db.list_account_plan_check_statuses(limit=20)
                self.assertEqual(failed["items"][0]["live_check_status"], "failed")
                self.assertEqual(failed["items"][0]["live_check_error"], "验证页")
                self.assertNotEqual(queued["revision"], failed["revision"])


    def test_single_liveness_claim_enters_queue(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            accounts_path = root / "accounts.json"
            accounts_path.write_text(json.dumps([{"id": 1, "email": "claim@example.com", "live_check_status": "failed"}]), encoding="utf-8")
            missing = root / "missing.json"
            with patch.multiple(db, _ACCOUNTS_JSON=accounts_path, _LEGACY_ACCOUNTS_JSON=missing,
                                _OUTLOOK_JSON=missing, _GENERIC_API_EMAIL_JSON=missing,
                                _JOBS_JSON=missing, _DOMAIN_EMAIL_JSON=missing), \
                 patch.object(db, "_SQLITE_READY", False), patch.object(db, "_SQLITE_READY_PATH", None):
                self.assertTrue(db.claim_account_live_check(1, trigger="manual_headed_refresh"))
                row = db.get_account(1)
                self.assertEqual(row["live_check_status"], "queued")
                self.assertEqual(row["live_check_trigger"], "manual_headed_refresh")
                self.assertTrue(db.mark_account_live_check_running(1))
                self.assertEqual(db.get_account(1)["live_check_status"], "running")


if __name__ == "__main__":
    unittest.main()
