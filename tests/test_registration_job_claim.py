# -*- coding: utf-8 -*-
import unittest
from unittest.mock import MagicMock, patch

from core import registration_service as service


class RegistrationJobClaimTests(unittest.TestCase):
    def tearDown(self):
        service._deactivate_job(987654)

    def test_only_one_worker_can_claim_same_job(self):
        self.assertTrue(service._activate_job(987654))
        self.assertFalse(service._activate_job(987654))

    def test_second_driver_cannot_replace_registered_driver(self):
        self.assertTrue(service._activate_job(987654))
        first = object()
        service.register_job_driver(987654, first)
        service.register_job_driver(987654, first)

        with self.assertRaisesRegex(RuntimeError, "拒绝重复启动"):
            service.register_job_driver(987654, object())

        self.assertIs(service._JOB_DRIVERS[987654], first)

    def test_retry_does_not_reuse_disabled_remail_address(self):
        source = {
            "id": 42, "status": "failed", "email_source": "remail",
            "email": "disabled@icloud.com", "account_id": None,
        }
        retry = {"id": 43, "status": "pending", "log_file": "retry.log"}
        executor = MagicMock()
        with patch.object(service.db, "get_job", return_value=source), patch.object(
            service.db, "get_successful_retry_for_job", return_value=None
        ), patch.object(service.db, "get_account_by_email", return_value=None), patch.object(
            service.db, "get_remail_email_by_email", return_value={"status": "disabled"}
        ), patch.object(service.db, "create_retry_job", return_value=(retry, True)) as create, patch.object(
            service, "get_executor", return_value=executor
        ):
            result = service.retry_job(42, workers=1)

        self.assertTrue(result["ok"])
        self.assertIsNone(create.call_args.kwargs["email"])


if __name__ == "__main__":
    unittest.main()
