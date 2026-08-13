from __future__ import annotations

import asyncio
from typing import Callable

from pydantic import BaseModel

from agentwall.detect.model import Detection, Detector, SecurityClassifier
from agentwall.events import SecurityEvent


class CascadeStats(BaseModel):
    total: int = 0
    tier2_invocations: int = 0

    @property
    def tier2_rate(self) -> float:
        return self.tier2_invocations / self.total if self.total else 0.0


class CascadeResult(BaseModel):
    detections: list[Detection]
    escalated: bool


def escalate_on_any(dets: list[Detection]) -> bool:
    return len(dets) > 0


class Cascade:
    def __init__(self, tier0: list[Detector], tier1: list[Detector],
                 classifier: SecurityClassifier,
                 escalate_when: Callable[[list[Detection]], bool]) -> None:
        self._t0 = tier0
        self._t1 = tier1
        self._clf = classifier
        self._escalate = escalate_when
        self.stats = CascadeStats()

    async def run(self, event: SecurityEvent, payload: bytes | None) -> CascadeResult:
        self.stats.total += 1
        dets: list[Detection] = []
        for d in self._t0:
            dets.extend(d.inspect(event, payload))
        for d in self._t1:
            dets.extend(await asyncio.to_thread(d.inspect, event, payload))
        escalated = False
        if self._escalate(dets):
            self.stats.tier2_invocations += 1
            extra = await self._clf.classify(event, payload)
            escalated = True
            if extra is not None:
                dets.append(extra)
        return CascadeResult(detections=dets, escalated=escalated)
