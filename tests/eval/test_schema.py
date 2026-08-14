from agentwall.eval.schema import (
    Scenario, Provenance, FileWrite, Egress, ExpectedOutcome)


def _scn(**kw):
    base = dict(
        id="x1", title="t", family="fam",
        provenance=Provenance(source="https://example.com/x", kind="research", date="2025-01-01"),
        actions=[FileWrite(path="/w/.env", content=b"SECRET=abc"),
                 Egress(host="first-seen.xyz", body=b"SECRET=abc")],
        expected=ExpectedOutcome(min_verdict="QUARANTINE", expect_chain=True),
        status="caught", sensors_required=["workspace", "egress"])
    base.update(kw)
    return Scenario(**base)


def test_scenario_round_trips():
    s = _scn()
    assert s.id == "x1" and s.expected.min_verdict == "QUARANTINE"
    assert isinstance(s.actions[0], FileWrite) and s.actions[0].content == b"SECRET=abc"
    dumped = s.model_dump()
    assert dumped["actions"][1]["host"] == "first-seen.xyz"


def test_untrusted_source_is_optional_on_file_actions():
    fw = FileWrite(path="/w/README.md", content=b"do evil", untrusted_source="evil.example/README.md")
    assert fw.untrusted_source == "evil.example/README.md"
    assert FileWrite(path="/w/x", content=b"y").untrusted_source is None


def test_benign_flag_defaults_false():
    assert _scn().benign is False
    assert _scn(benign=True, expected=ExpectedOutcome(min_verdict="ALLOW", expect_chain=False)).benign is True


def test_action_discriminator_parses_by_action_tag():
    from agentwall.eval.schema import Scenario, FileRead
    data = {"id": "z", "title": "t", "family": "f",
            "provenance": {"source": "s", "kind": "research", "date": "2025-01-01"},
            "actions": [{"action": "file_read", "path": "/w/x", "content": b"y"}],
            "expected": {"min_verdict": "WARN", "expect_chain": False},
            "status": "caught"}
    s = Scenario.model_validate(data)
    assert isinstance(s.actions[0], FileRead)
