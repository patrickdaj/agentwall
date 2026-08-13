from agentwall.events import SecurityEvent, new_event

EXPECT = {"min_verdict": "QUARANTINE", "expect_chain": True}


def events() -> list[SecurityEvent]:
    return [
        new_event(event_type="file_read", session_id="s1", source="workspace", ts=1.0,
                  trust="tainted", attrs={"untrusted_source": "evil.example/README.md"}),
        new_event(event_type="file_read", session_id="s1", source="workspace", ts=2.0,
                  attrs={"path": "/w/.env", "sensitive": True}),
        new_event(event_type="network_upload", session_id="s1", source="egress", ts=3.0,
                  attrs={"destination": "first-seen.xyz", "size": 4_000_000}),
    ]
