"""``Reply.generated_locally``: siphon-made response versus one received."""

from siphon_sdk.reply import Reply


def test_defaults_to_false():
    assert Reply(status_code=408, reason="Request Timeout").generated_locally is False


def test_settable_for_a_test():
    reply = Reply(status_code=408, reason="Request Timeout", generated_locally=True)
    assert reply.generated_locally is True
