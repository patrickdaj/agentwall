from agentwall.events import new_event
from agentwall.provenance import ChainCorrelator


def _e(source, ts, **attrs):
    trust = attrs.pop("trust", "trusted")
    et = attrs.pop("event_type", "x")
    return new_event(event_type=et, session_id="s", source=source, ts=ts, trust=trust, attrs=attrs)


def test_full_chain_detected():
    c = ChainCorrelator(window_s=120)
    assert c.observe(_e("workspace", 1.0, untrusted_source="evil.example/README")) is None
    assert c.observe(_e("workspace", 2.0, event_type="file_read", path="/w/.env", sensitive=True)) is None
    chain = c.observe(_e("egress", 3.0, destination="first-seen.xyz", size=4_000_000))
    assert chain is not None
    assert len(chain.steps) == 3 and chain.session_id == "s"


def test_no_chain_when_egress_without_precursors():
    c = ChainCorrelator()
    assert c.observe(_e("egress", 1.0, destination="x")) is None


def test_non_workspace_sensitive_event_cannot_be_step2():
    c = ChainCorrelator(window_s=120)
    # step 1: untrusted source
    c.observe(_e("workspace", 1.0, untrusted_source="evil"))
    # a premature EGRESS carrying sensitive=True must NOT be consumed as sensitive-access
    assert c.observe(_e("egress", 2.0, destination="exfil-1.xyz", sensitive=True)) is None
    # a later legitimate-looking egress must NOT fraudulently complete a chain,
    # because a real workspace sensitive-access step never occurred
    assert c.observe(_e("egress", 3.0, destination="exfil-2.xyz")) is None


def test_window_expiry_breaks_chain():
    c = ChainCorrelator(window_s=10)
    c.observe(_e("workspace", 1.0, untrusted_source="evil"))
    c.observe(_e("workspace", 2.0, event_type="file_read", path="/w/.env", sensitive=True))
    assert c.observe(_e("egress", 100.0, destination="x")) is None
