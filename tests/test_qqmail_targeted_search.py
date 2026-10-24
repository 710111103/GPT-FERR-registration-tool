from datetime import datetime, timezone

from core.qqmail_client import _search_messages


class _Inbox:
    def __init__(self):
        self.criteria = None

    def search(self, charset, *criteria):
        assert charset is None
        self.criteria = criteria
        return "OK", [b"21"]

    def fetch(self, msg_id, query):
        assert msg_id == b"21"
        assert query == "(RFC822)"
        raw = (
            b"From: OpenAI <noreply@openai.com>\r\n"
            b"To: target@example.com\r\n"
            b"Date: Mon, 12 Oct 2026 04:40:38 +0000\r\n"
            b"Subject: Your code is 123456\r\n\r\n"
            b"Your verification code is 123456\r\n"
        )
        return "OK", [(b"21 (RFC822 {0})", raw)]


def test_qqmail_search_filters_recipient_before_recent_message_limit():
    inbox = _Inbox()
    after = datetime(2026, 10, 12, 4, 40, tzinfo=timezone.utc)

    messages = _search_messages(inbox, after_dt=after, target_email="target@example.com")

    assert inbox.criteria == ("SINCE", "12-Oct-2026", "TO", '"target@example.com"')
    assert len(messages) == 1
    assert messages[0]["to"] == "target@example.com"
