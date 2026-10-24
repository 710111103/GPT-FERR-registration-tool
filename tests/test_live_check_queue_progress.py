# -*- coding: utf-8 -*-
import unittest
from unittest.mock import patch

from core import live_check_service as service


class QueueProgressTests(unittest.TestCase):
    def test_position_and_elapsed_are_reported_without_starting_worker(self):
        target = {"id": 339, "email": "person@example.com", "live_check_status": "queued",
                  "live_check_queued_at": "2026-10-18T00:40:00"}
        prior = {"id": 111, "live_check_status": "queued", "live_check_queued_at": "2026-10-18T00:39:00"}
        with patch.object(service.db, "get_account_by_email", return_value=target), \
             patch.object(service.db, "list_accounts", return_value=[target, prior]) as listing:
            progress = service.queue_progress(target["email"])
        self.assertEqual(progress["position"], 2)
        self.assertEqual(progress["queued_total"], 2)
        self.assertGreaterEqual(progress["wait_seconds"], 0)
        listing.assert_called_once_with(limit=5000, archived="all")

    def test_running_does_not_scan_queue(self):
        account = {"id": 339, "live_check_status": "running", "live_check_started_at": "2026-10-18T00:48:21"}
        with patch.object(service.db, "get_account_by_email", return_value=account), \
             patch.object(service.db, "list_accounts") as listing:
            progress = service.queue_progress("person@example.com")
        self.assertEqual(progress["status"], "running")
        self.assertGreaterEqual(progress["running_seconds"], 0)
        listing.assert_not_called()
