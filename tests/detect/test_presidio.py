import pytest

from agentwall.detect.tier1_presidio import PresidioScanner
from agentwall.events import new_event

analyzer_available = True
try:
    from presidio_analyzer import AnalyzerEngine  # noqa: F401
except Exception:
    analyzer_available = False

pytestmark = pytest.mark.skipif(not analyzer_available, reason="presidio not installed")


def _evt():
    return new_event(event_type="network_upload", session_id="s", source="egress", ts=1.0)


def test_detects_email_and_ssn():
    scanner = PresidioScanner()
    out = scanner.inspect(_evt(), b"contact john@example.com, SSN 123-45-6789")
    cls = {d.classification for d in out}
    assert any(c.startswith("pii:") for c in cls)


def test_clean_text_silent():
    scanner = PresidioScanner()
    assert scanner.inspect(_evt(), b"the quick brown fox") == []


def test_none_payload():
    assert PresidioScanner().inspect(_evt(), None) == []
