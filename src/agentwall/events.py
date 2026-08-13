from __future__ import annotations

import hashlib
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field

Source = Literal["egress", "workspace", "mcp", "lifecycle"]
Trust = Literal["trusted", "tainted"]


class SecurityEvent(BaseModel):
    schema_version: int = 1
    event_id: str
    event_type: str
    session_id: str
    agent_id: str = "unknown"
    source: Source
    content_hash: str | None = None
    trust: Trust = "trusted"
    payload_ref: str | None = None
    ts: float
    attrs: dict[str, Any] = Field(default_factory=dict)


def new_event(*, event_type: str, session_id: str, source: Source, ts: float, **kw: Any) -> SecurityEvent:
    return SecurityEvent(event_id=uuid4().hex, event_type=event_type, session_id=session_id, source=source, ts=ts, **kw)


def content_hash(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()
