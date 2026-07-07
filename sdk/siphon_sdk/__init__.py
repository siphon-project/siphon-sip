"""
siphon_sdk — Mock library for testing and authoring SIPhon scripts.

This package provides mock implementations of the ``siphon`` Python module
that SIPhon exposes to user scripts at runtime. It has two purposes:

1. **Unit/integration testing** — Write pytest tests for your SIPhon scripts
   without running the Rust binary.  The test harness simulates incoming SIP
   messages, captures actions (reply, relay, fork, reject, etc.), and lets you
   assert on the results.

2. **LLM context** — Every class, method, and property carries rich docstrings
   and type annotations so that language models can generate correct SIPhon
   scripts from ``pip install siphon-sdk`` alone.

Quick start::

    from siphon_sdk.testing import SipTestHarness

    harness = SipTestHarness()
    harness.load_script("scripts/proxy_default.py")

    result = harness.send_request("REGISTER", "sip:alice@example.com",
                                  from_uri="sip:alice@example.com")
    assert result.action == "reply"
    assert result.status_code == 401   # digest challenge
"""

__version__ = "0.1.0"

from siphon_sdk.mock_module import install
from siphon_sdk.testing import SipTestHarness
from siphon_sdk.smpp_testing import SmppTestHarness
from siphon_sdk.http_testing import HttpTestHarness

__all__ = ["install", "SipTestHarness", "SmppTestHarness", "HttpTestHarness"]
