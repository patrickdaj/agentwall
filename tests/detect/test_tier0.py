from agentwall.detect.tier0_rules import RulesConfig, RulesDetector, shannon_entropy
from agentwall.events import new_event


def _cfg():
    return RulesConfig(
        sensitive_path_globs=["**/.env", "**/.ssh/*", "**/.aws/*"],
        denied_dest_domains=["evil.example"],
        max_upload_bytes=1_000_000,
        entropy_threshold=7.5,
    )


def test_sensitive_path_access_flagged():
    det = RulesDetector(_cfg())
    e = new_event(event_type="file_read", session_id="s", source="workspace", ts=1.0,
                  attrs={"path": "/work/project/.env"})
    out = det.inspect(e, None)
    assert any(d.classification == "sensitive_path_access" for d in out)


def test_denied_destination_and_oversize():
    det = RulesDetector(_cfg())
    e = new_event(event_type="network_upload", session_id="s", source="egress", ts=1.0,
                  attrs={"destination": "evil.example", "size": 5_000_000})
    cls = {d.classification for d in det.inspect(e, None)}
    assert "denied_destination" in cls and "oversize_upload" in cls


def test_high_entropy_payload():
    det = RulesDetector(_cfg())
    import os
    e = new_event(event_type="network_upload", session_id="s", source="egress", ts=1.0, attrs={})
    out = det.inspect(e, os.urandom(4096))
    assert any(d.classification == "high_entropy" for d in out)


def test_benign_event_is_silent():
    det = RulesDetector(_cfg())
    e = new_event(event_type="file_read", session_id="s", source="workspace", ts=1.0,
                  attrs={"path": "/work/project/README.md"})
    assert det.inspect(e, b"hello world") == []


def test_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"aaaa") < 1.0
