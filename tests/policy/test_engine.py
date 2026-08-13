from pathlib import Path

from agentwall.detect.model import Detection, Verdict
from agentwall.events import new_event
from agentwall.policy.engine import PolicyEngine

POLICY = Path("src/agentwall/policy/default_policy.yaml")


def _egress():
    return new_event(event_type="network_upload", session_id="s", source="egress", ts=1.0)


def test_secret_egress_blocks_when_capable():
    pe = PolicyEngine.from_yaml(POLICY, capabilities={"block", "quarantine"})
    d = pe.evaluate(_egress(), [Detection(tier=1, classification="secret:aws", confidence=0.9)], in_chain=False)
    assert d.verdict is Verdict.BLOCK and d.matched_rule == "block-secret-egress"


def test_block_downgrades_without_capability():
    pe = PolicyEngine.from_yaml(POLICY, capabilities=set())
    d = pe.evaluate(_egress(), [Detection(tier=1, classification="secret:aws", confidence=0.9)], in_chain=False)
    assert d.verdict is Verdict.WARN and d.downgraded is True


def test_chain_quarantines():
    pe = PolicyEngine.from_yaml(POLICY, capabilities={"quarantine"})
    d = pe.evaluate(_egress(), [], in_chain=True)
    assert d.verdict is Verdict.QUARANTINE


def test_no_match_allows():
    pe = PolicyEngine.from_yaml(POLICY, capabilities={"block"})
    d = pe.evaluate(_egress(), [], in_chain=False)
    assert d.verdict is Verdict.ALLOW and d.matched_rule is None
