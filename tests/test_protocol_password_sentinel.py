import json
import unittest
from unittest.mock import MagicMock, patch

from core.openai_auth import build_sentinel_header


class ProtocolPasswordSentinelTests(unittest.TestCase):
    def test_password_registration_token_does_not_require_so_header(self):
        session = MagicMock()
        session.device_id = "device-test-id"
        session.browser_profile = {}
        token = json.dumps({
            "p": "proof",
            "t": "turnstile",
            "c": "challenge",
            "id": session.device_id,
            "flow": "username_password_create",
        })

        with patch("core.openai_auth.generate_sentinel_token", return_value=token):
            header, so_header = build_sentinel_header(
                session, {"token": "challenge"}, "username_password_create"
            )

        self.assertEqual(header, token)
        self.assertIsNone(so_header)


if __name__ == "__main__":
    unittest.main()
