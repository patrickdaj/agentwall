from agentwall.events import SecurityEvent, new_event

EXPECT = {"min_verdict": "WARN", "expect_chain": False}


def events() -> list[SecurityEvent]:
    # Injected postinstall script added to package.json (implicit-exec file).
    return [
        new_event(event_type="file_write", session_id="s3", source="workspace", ts=1.0,
                  attrs={"path": "/w/package.json", "implicit_exec": True, "sensitive": True}),
    ]
