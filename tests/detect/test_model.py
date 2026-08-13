from agentwall.detect.model import Detection, NullClassifier, Verdict
from agentwall.events import new_event


def test_verdict_severity_ordering():
    assert Verdict.ALLOW < Verdict.WARN < Verdict.BLOCK < Verdict.QUARANTINE
    assert max(Verdict.WARN, Verdict.QUARANTINE) is Verdict.QUARANTINE


def test_detection_fields():
    d = Detection(tier=0, classification="secret", confidence=0.9, evidence=["aws key"])
    assert d.tier == 0 and d.evidence == ["aws key"]


async def test_null_classifier_returns_none():
    e = new_event(event_type="x", session_id="s", source="workspace", ts=1.0)
    assert await NullClassifier().classify(e, None) is None
