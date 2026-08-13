from agentwall.eval.driver import ObservedOutcome
from agentwall.eval.schema import Scenario, Provenance, ExpectedOutcome
from agentwall.eval.scorer import score, ScenarioScore

_PROV = Provenance(source="https://example.com", kind="research", date="2025-01-01")


def _scn(**kw):
    base = dict(id="s", title="t", family="f", provenance=_PROV, actions=[],
                expected=ExpectedOutcome(min_verdict="QUARANTINE", expect_chain=True),
                status="caught", sensors_required=[])
    base.update(kw); return Scenario(**base)


def _obs(verdicts, chains=None, warned=0):
    return ObservedOutcome(verdicts=verdicts, chains=chains or [], warned_or_worse=warned)


def test_caught_when_verdict_meets_expected_with_chain():
    r = score(_scn(), _obs(["ALLOW", "QUARANTINE"], chains=[["untrusted-source: x", "secret-egress: y"]], warned=1))
    assert r.outcome == "caught" and r.is_regression is False


def test_caught_status_missed_is_regression():
    r = score(_scn(status="caught"), _obs(["WARN"], warned=1))  # expected QUARANTINE+chain, got WARN/no chain
    assert r.outcome == "missed" and r.is_regression is True


def test_blind_spot_miss_is_not_regression():
    r = score(_scn(status="blind-spot"), _obs(["ALLOW"]))
    assert r.outcome == "missed" and r.is_regression is False


def test_benign_false_positive_is_regression():
    benign = _scn(benign=True, expected=ExpectedOutcome(min_verdict="ALLOW", expect_chain=False), status="caught")
    r = score(benign, _obs(["WARN"], warned=1))
    assert r.is_false_positive is True and r.is_regression is True


def test_benign_silent_is_clean():
    benign = _scn(benign=True, expected=ExpectedOutcome(min_verdict="ALLOW", expect_chain=False), status="caught")
    r = score(benign, _obs(["ALLOW"], warned=0))
    assert r.is_false_positive is False and r.outcome == "caught" and r.is_regression is False
