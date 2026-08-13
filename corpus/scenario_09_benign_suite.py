from agentwall.events import SecurityEvent, new_event

EXPECT = {"min_verdict": "ALLOW", "expect_chain": False}


def events() -> list[SecurityEvent]:
    # Ordinary coding session: editing source, reading a normal README, a git push.
    return [
        new_event(event_type="file_write", session_id="s9", source="workspace", ts=1.0,
                  attrs={"path": "/w/src/main.py"}),
        new_event(event_type="file_read", session_id="s9", source="workspace", ts=2.0,
                  attrs={"path": "/w/README.md"}),
        new_event(event_type="network_upload", session_id="s9", source="egress", ts=3.0,
                  attrs={"destination": "github.com", "size": 20_000}),
    ]
