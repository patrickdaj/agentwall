import shutil

import pytest

from agentwall.detect.tier1_gitleaks import GitleaksScanner
from agentwall.events import new_event

pytestmark = pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks not installed")


def _evt():
    return new_event(event_type="network_upload", session_id="s", source="egress", ts=1.0)


def test_detects_aws_key():
    scanner = GitleaksScanner()
    payload = b"github_token = ghp_1234567890abcdefghij1234567890abcdef\n"
    out = scanner.inspect(_evt(), payload)
    assert any(d.classification.startswith("secret:") for d in out)


def test_clean_payload_is_silent():
    scanner = GitleaksScanner()
    assert scanner.inspect(_evt(), b"just some normal text\n") == []


def test_missing_binary_is_fail_safe():
    scanner = GitleaksScanner(binary="definitely-not-a-real-binary-xyz")
    assert scanner.inspect(_evt(), b"AKIAIOSFODNN7EXAMPLE") == []
    assert scanner.degraded is True
