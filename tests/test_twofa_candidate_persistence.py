# -*- coding: utf-8 -*-
import unittest
from unittest.mock import patch

from core import db


class TotpCandidatePersistenceTests(unittest.TestCase):
    def setUp(self):
        self.rows = [{"id": 1, "email": "fixture@example.test", "totp_setup_status": "running"}]
        self.load = patch.object(db, "_load_accounts", side_effect=lambda: [dict(r) for r in self.rows])
        self.save = patch.object(db, "_save_accounts", side_effect=self._save)
        self.load.start()
        self.save.start()

    def tearDown(self):
        self.save.stop()
        self.load.stop()

    def _save(self, rows):
        self.rows[:] = [dict(r) for r in rows]

    def test_candidate_survives_unknown_activation_and_blocks_reenroll(self):
        self.assertTrue(db.update_account_totp_secret(1, {
            "status": "prepared", "totp_secret": "LOCAL-CANDIDATE", "message": "pending"
        }))
        self.assertEqual(self.rows[0]["totp_setup_candidate_secret"], "LOCAL-CANDIDATE")
        self.assertIsNone(self.rows[0].get("totp_secret"))
        self.assertTrue(db.update_account_totp_secret(1, {
            "status": "activation_unknown", "error": "proxy aborted"
        }))
        self.assertFalse(db.claim_account_totp_setup(1, trigger="manual"))
        self.assertEqual(self.rows[0]["totp_setup_candidate_secret"], "LOCAL-CANDIDATE")

    def test_confirmed_activation_promotes_candidate(self):
        db.update_account_totp_secret(1, {"status": "prepared", "totp_secret": "LOCAL-CANDIDATE"})
        db.update_account_totp_secret(1, {
            "status": "success", "ok": True, "totp_secret": "LOCAL-CANDIDATE"
        })
        self.assertEqual(self.rows[0]["totp_secret"], "LOCAL-CANDIDATE")
        self.assertIsNone(self.rows[0]["totp_setup_candidate_secret"])

    def test_interrupted_setup_keeps_candidate_unconfirmed(self):
        db.update_account_totp_secret(1, {"status": "prepared", "totp_secret": "LOCAL-CANDIDATE"})
        self.assertEqual(db.recover_interrupted_totp_setups(), 1)
        self.assertEqual(self.rows[0]["totp_setup_status"], "activation_unknown")
        self.assertEqual(self.rows[0]["totp_setup_candidate_secret"], "LOCAL-CANDIDATE")
        self.assertIsNone(self.rows[0].get("totp_secret"))


if __name__ == "__main__":
    unittest.main()
