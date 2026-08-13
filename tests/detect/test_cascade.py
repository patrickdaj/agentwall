from agentwall.detect.cascade import Cascade, escalate_on_any
from agentwall.detect.model import Detection, NullClassifier
from agentwall.events import new_event


class FakeDetector:
    def __init__(self, dets):
        self._dets = dets

    def inspect(self, event, payload):
        return list(self._dets)


class RecordingClassifier:
    def __init__(self):
        self.calls = 0

    async def classify(self, event, payload):
        self.calls += 1
        return Detection(tier=2, classification="semantic", confidence=0.5)


def _evt():
    return new_event(event_type="x", session_id="s", source="workspace", ts=1.0)


async def test_runs_all_tiers_and_collects():
    t0 = FakeDetector([Detection(tier=0, classification="a", confidence=1.0)])
    t1 = FakeDetector([Detection(tier=1, classification="b", confidence=1.0)])
    c = Cascade([t0], [t1], NullClassifier(), escalate_on_any)
    res = await c.run(_evt(), None)
    assert {d.classification for d in res.detections} >= {"a", "b"}


async def test_escalation_invokes_classifier_and_counts():
    t0 = FakeDetector([Detection(tier=0, classification="a", confidence=1.0)])
    rc = RecordingClassifier()
    c = Cascade([t0], [], rc, escalate_on_any)
    res = await c.run(_evt(), None)
    assert rc.calls == 1 and res.escalated
    assert c.stats.tier2_invocations == 1 and c.stats.total == 1


async def test_no_detection_no_escalation():
    c = Cascade([FakeDetector([])], [], NullClassifier(), escalate_on_any)
    res = await c.run(_evt(), None)
    assert res.escalated is False and c.stats.tier2_rate == 0.0
