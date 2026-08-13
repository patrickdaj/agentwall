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


def _tainted(ts=1.0):
    return new_event(event_type="file_write", session_id="s", source="workspace", ts=ts,
                     trust="tainted", attrs={"untrusted_source": "evil/README.md"})


def _egress(ts=2.0):
    return new_event(event_type="network_upload", session_id="s", source="egress", ts=ts,
                     attrs={"destination": "first-seen.xyz"})


def test_secret_egress_completes_two_hop_chain():
    corr = ChainCorrelator()
    assert corr.observe(_tainted()) is None
    chain = corr.observe(_egress(), has_secret=True)
    assert chain is not None
    assert chain.steps == ["untrusted-source: evil/README.md", "secret-egress: first-seen.xyz"]
    assert len(chain.event_ids) == 2


def test_egress_without_secret_or_sensitive_is_not_a_chain():
    corr = ChainCorrelator()
    assert corr.observe(_tainted()) is None
    assert corr.observe(_egress(), has_secret=False) is None


def test_secret_egress_outside_window_resets():
    corr = ChainCorrelator(window_s=10.0)
    assert corr.observe(_tainted(ts=1.0)) is None
    assert corr.observe(_egress(ts=100.0), has_secret=True) is None
