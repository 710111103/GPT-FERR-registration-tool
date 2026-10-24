# -*- coding: utf-8 -*-
import json
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from core import db, registration_service


class RegistrationCancelPendingTests(unittest.TestCase):
    def test_bulk_cancel_is_unlimited_and_running_job_is_untouched(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            missing = root / "missing.json"
            with patch.multiple(
                db,
                _ACCOUNTS_JSON=missing,
                _OUTLOOK_JSON=missing,
                _GENERIC_API_EMAIL_JSON=missing,
                _JOBS_JSON=missing,
                _DOMAIN_EMAIL_JSON=missing,
                _LEGACY_SQLITE=root / "missing.db",
                _LEGACY_ACCOUNTS_JSON=missing,
                _LEGACY_OUTLOOK_JSON=missing,
                _LEGACY_JOBS_JSON=missing,
                _SQLITE_READY=False,
                _SQLITE_READY_PATH=None,
            ):
                db._ensure_sqlite()
                with closing(db._sqlite_conn()) as conn, conn:
                    rows = []
                    for job_id in range(1, 1004):
                        status = "running" if job_id == 1003 else "pending"
                        payload = {"id": job_id, "status": status, "completed_at": None}
                        rows.append((job_id, "", status, 0, "", "", json.dumps(payload)))
                    conn.executemany(
                        "INSERT INTO registration_jobs"
                        "(id,email,status,archived,created_at,updated_at,payload) "
                        "VALUES(?,?,?,?,?,?,?)",
                        rows,
                    )

                cancelled = registration_service.cancel_pending_jobs("bulk test")

                self.assertEqual(cancelled, 1002)
                self.assertEqual(db.job_status_counts()["cancelled"], 1002)
                self.assertEqual(db.get_job(1)["error_message"], "bulk test")
                self.assertTrue(db.get_job(1)["completed_at"])
                self.assertEqual(db.get_job(1003)["status"], "running")
                self.assertFalse(db.claim_pending_job(1))

    def test_single_cancel_and_worker_claim_are_mutually_exclusive(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            missing = root / "missing.json"
            with patch.multiple(
                db,
                _ACCOUNTS_JSON=missing,
                _OUTLOOK_JSON=missing,
                _GENERIC_API_EMAIL_JSON=missing,
                _JOBS_JSON=missing,
                _DOMAIN_EMAIL_JSON=missing,
                _LEGACY_SQLITE=root / "missing.db",
                _LEGACY_ACCOUNTS_JSON=missing,
                _LEGACY_OUTLOOK_JSON=missing,
                _LEGACY_JOBS_JSON=missing,
                _SQLITE_READY=False,
                _SQLITE_READY_PATH=None,
            ):
                first = db.create_job("generic_api")
                second = db.create_job("generic_api")
                self.assertTrue(db.cancel_pending_job(first["id"]))
                self.assertFalse(db.claim_pending_job(first["id"]))
                self.assertTrue(db.claim_pending_job(second["id"]))
                self.assertFalse(db.cancel_pending_job(second["id"]))
                self.assertEqual(db.get_job(first["id"])["status"], "cancelled")
                self.assertEqual(db.get_job(second["id"])["status"], "running")


if __name__ == "__main__":
    unittest.main()
