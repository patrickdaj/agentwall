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
from agentwall.sensors.egress import EgressSensor, default_socket_path
from agentwall.sensors.workspace import WorkspaceSensor
from agentwall.storage import EventStore


class DaemonConfig(BaseModel):
    workspace: Path
    session_id: str
    db_path: Path
    policy_path: Path
    rules: RulesConfig
    skills_store: Path | None = None
    enable_egress: bool = False
    egress_socket: Path | None = None
    proxy_port: int = 8888


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
        self._sensor = WorkspaceSensor(config.workspace, config.session_id, config.skills_store,
                                       blob_put=self._store.put_blob)
        self._egress: EgressSensor | None = None
        self._egress_task: asyncio.Task | None = None
        if config.enable_egress:
            self._egress = EgressSensor(
                socket_path=str(config.egress_socket or default_socket_path()),
                blob_put=self._store.put_blob, session_id=config.session_id,
                dead_letter=self._store.dead_letter, proxy_port=config.proxy_port)
        self._sensor_task: asyncio.Task | None = None
        self.decisions: list[tuple[SecurityEvent, Decision, Chain | None]] = []
        self._bus.subscribe(self._on_event)

    async def _on_event(self, event: SecurityEvent) -> None:
        payload = self._store.get_blob(event.payload_ref) if event.payload_ref else None
        result = await self._cascade.run(event, payload)
        has_secret = any(
            d.classification.startswith("secret:") or d.classification.startswith("pii:")
            for d in result.detections
        )
        chain = self._correlator.observe(event, has_secret=has_secret)
        decision = self._policy.evaluate(event, result.detections, in_chain=chain is not None)
        if decision.verdict == Verdict.QUARANTINE and "quarantine" in self._adapter.capabilities():
            await asyncio.to_thread(self._adapter.quarantine, self._cfg.session_id)
        self.decisions.append((event, decision, chain))

    async def submit(self, event: SecurityEvent) -> None:
        await self._bus.publish(event)

    async def start(self) -> None:
        await self._bus.replay_unprocessed()
        self._sensor_task = asyncio.create_task(self._sensor.run(self._bus))
        if self._egress is not None:
            self._egress_task = asyncio.create_task(self._egress.run(self._bus))

    async def stop(self) -> None:
        self._sensor.stop()
        if self._egress is not None:
            self._egress.stop()
        try:
            tasks = [t for t in (self._sensor_task, self._egress_task) if t is not None]
            if tasks:
                # return_exceptions=True: a failed sensor/egress task must be retrieved
                # here, not re-raised — otherwise a bad egress bind (e.g. port already in
                # use) would skip store.close() below and leak the sqlite handle, plus
                # asyncio would log "Task exception was never retrieved".
                await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            self._store.close()

    def health(self) -> dict:
        return {
            "degraded": self._gitleaks.degraded or self._presidio.degraded,
            "egress_degraded": self._egress.degraded if self._egress is not None else False,
            "events": self._cascade.stats.total,
            "tier2_rate": self._cascade.stats.tier2_rate,
            "capabilities": sorted(self._adapter.capabilities()),
        }
