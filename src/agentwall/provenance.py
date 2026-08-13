from __future__ import annotations

from dataclasses import dataclass, field

from pydantic import BaseModel

from agentwall.events import SecurityEvent


class Chain(BaseModel):
    session_id: str
    steps: list[str]
    event_ids: list[str]


def is_untrusted(event: SecurityEvent) -> bool:
    return event.trust == "tainted" or bool(event.attrs.get("untrusted_source"))


@dataclass
class _State:
    tainted_at: float | None = None
    steps: list[str] = field(default_factory=list)
    ids: list[str] = field(default_factory=list)
    sensitive_seen: bool = False


class ChainCorrelator:
    def __init__(self, window_s: float = 120.0) -> None:
        self._w = window_s
        self._states: dict[str, _State] = {}

    def observe(self, event: SecurityEvent) -> Chain | None:
        st = self._states.setdefault(event.session_id, _State())

        if is_untrusted(event):
            label = str(event.attrs.get("untrusted_source", "tainted-source"))
            st.tainted_at = event.ts
            st.steps = [f"untrusted-source: {label}"]
            st.ids = [event.event_id]
            st.sensitive_seen = False
            return None

        if st.tainted_at is not None and not st.sensitive_seen:
            sensitive = (event.source == "workspace") and (
                event.attrs.get("sensitive")
                or (event.event_type in {"file_read", "file_write"} and event.attrs.get("path"))
            )
            if sensitive:
                st.sensitive_seen = True
                st.steps.append(f"sensitive-access: {event.attrs.get('path', '?')}")
                st.ids.append(event.event_id)
                return None

        if event.source == "egress" and st.tainted_at is not None and st.sensitive_seen:
            if event.ts - st.tainted_at <= self._w:
                st.steps.append(f"egress: {event.attrs.get('destination', '?')}")
                st.ids.append(event.event_id)
                chain = Chain(session_id=event.session_id, steps=list(st.steps), event_ids=list(st.ids))
                self._states[event.session_id] = _State()
                return chain
            self._states[event.session_id] = _State()
        return None
