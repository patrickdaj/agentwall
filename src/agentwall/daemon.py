from __future__ import annotations

import asyncio
from pathlib import Path

from pydantic import BaseModel

from agentwall.adapters.base import RuntimeAdapter
from agentwall.bus import EventBus
from agentwall.detect.cascade import Cascade, escalate_on_any
from agentwall.detect.model import NullClassifier, SecurityClassifier, Verdict
from agentwall.detect.tier0_rules import RulesConfig, RulesDetector
from agentwall.detect.tier1_gitleaks import GitleaksScanner
from agentwall.detect.tier1_presidio import PresidioScanner
from agentwall.events import SecurityEvent
from agentwall.policy.engine import Decision, PolicyEngine
from agentwall.provenance import Chain, ChainCorrelator
from agentwall.sensors.workspace import WorkspaceSensor
from agentwall.storage import EventStore


class DaemonConfig(BaseModel):
    workspace: Path
    session_id: str
    db_path: Path
    policy_path: Path
    rules: RulesConfig
    skills_store: Path | None = None


class Daemon:
    def __init__(self, config: DaemonConfig, adapter: RuntimeAdapter,
                 classifier: SecurityClassifier | None = None) -> None:
        self._cfg = config
        self._adapter = adapter
        self._store = EventStore(config.db_path)
        self._bus = EventBus(self._store)
        self._gitleaks = GitleaksScanner()
        self._presidio = PresidioScanner()
        self._cascade = Cascade(
            tier0=[RulesDetector(config.rules)],
            tier1=[self._gitleaks, self._presidio],
            classifier=classifier or NullClassifier(),
            escalate_when=escalate_on_any,
        )
        self._correlator = ChainCorrelator()
        self._policy = PolicyEngine.from_yaml(config.policy_path, adapter.capabilities())
        self._sensor = WorkspaceSensor(config.workspace, config.session_id, config.skills_store)
        self._sensor_task: asyncio.Task | None = None
        self.decisions: list[tuple[SecurityEvent, Decision, Chain | None]] = []
        self._bus.subscribe(self._on_event)

    async def _on_event(self, event: SecurityEvent) -> None:
        payload = self._store.get_blob(event.payload_ref) if event.payload_ref else None
        result = await self._cascade.run(event, payload)
        chain = self._correlator.observe(event)
        decision = self._policy.evaluate(event, result.detections, in_chain=chain is not None)
        if decision.verdict == Verdict.QUARANTINE and "quarantine" in self._adapter.capabilities():
            self._adapter.quarantine(self._cfg.session_id)
        self.decisions.append((event, decision, chain))

    async def submit(self, event: SecurityEvent) -> None:
        await self._bus.publish(event)

    async def start(self) -> None:
        await self._bus.replay_unprocessed()
        self._sensor_task = asyncio.create_task(self._sensor.run(self._bus))

    async def stop(self) -> None:
        self._sensor.stop()
        if self._sensor_task:
            await self._sensor_task
        self._store.close()

    def health(self) -> dict:
        return {
            "degraded": self._gitleaks.degraded or self._presidio.degraded,
            "events": self._cascade.stats.total,
            "tier2_rate": self._cascade.stats.tier2_rate,
            "capabilities": sorted(self._adapter.capabilities()),
        }
