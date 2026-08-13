from __future__ import annotations

from enum import IntEnum
from typing import Protocol

from pydantic import BaseModel, Field

from agentwall.events import SecurityEvent


class Verdict(IntEnum):
    ALLOW = 0
    WARN = 1
    REQUIRE_APPROVAL = 2
    BLOCK = 3
    QUARANTINE = 4


class Detection(BaseModel):
    tier: int
    classification: str
    confidence: float
    evidence: list[str] = Field(default_factory=list)


class Detector(Protocol):
    def inspect(self, event: SecurityEvent, payload: bytes | None) -> list[Detection]: ...


class SecurityClassifier(Protocol):
    async def classify(self, event: SecurityEvent, payload: bytes | None) -> Detection | None: ...


class NullClassifier:
    async def classify(self, event: SecurityEvent, payload: bytes | None) -> Detection | None:
        return None
