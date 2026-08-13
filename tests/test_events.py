from agentwall.events import SecurityEvent, new_event, content_hash


def test_new_event_generates_id_and_defaults():
    e = new_event(event_type="file_write", session_id="s1", source="workspace", ts=1.0)
    assert e.schema_version == 1
    assert len(e.event_id) == 32
    assert e.agent_id == "unknown"
    assert e.trust == "trusted"


def test_content_hash_is_stable_and_prefixed():
    assert content_hash(b"abc") == content_hash(b"abc")
    assert content_hash(b"abc").startswith("sha256:")
    assert content_hash(b"abc") != content_hash(b"abd")


def test_event_roundtrips_json():
    e = new_event(event_type="file_write", session_id="s1", source="workspace", ts=1.0)
    assert SecurityEvent.model_validate_json(e.model_dump_json()) == e
