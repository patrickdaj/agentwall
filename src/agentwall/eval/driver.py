from __future__ import annotations

import base64
from pathlib import Path

from pydantic import BaseModel

from agentwall.adapters.docker_sandbox import DockerSandboxAdapter
from agentwall.daemon import Daemon, DaemonConfig
from agentwall.detect.model import Verdict
from agentwall.detect.tier0_rules import RulesConfig
from agentwall.eval.schema import Egress, FileRead, FileWrite, Scenario
from agentwall.sensors.egress import egress_event_from_record
from agentwall.sensors.workspace import WorkspaceSensor

_POLICY = Path("src/agentwall/policy/default_policy.yaml")


class ObservedOutcome(BaseModel):
    verdicts: list[str]
    chains: list[list[str]]
    warned_or_worse: int


async def run_scenario(scenario: Scenario, tmp_path: Path, rules: RulesConfig) -> ObservedOutcome:
    workspace = tmp_path / "ws"
    workspace.mkdir(parents=True, exist_ok=True)
    cfg = DaemonConfig(workspace=workspace, session_id=scenario.id, db_path=tmp_path / "ev.db",
                       policy_path=_POLICY, rules=rules)
    d = Daemon(cfg, adapter=DockerSandboxAdapter(workspace=workspace))
    ws_sensor = WorkspaceSensor(workspace, scenario.id, blob_put=d._store.put_blob)
    ts = 1.0
    for act in scenario.actions:
        if isinstance(act, (FileWrite, FileRead)):
            p = workspace / act.path.lstrip("/")
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(act.content)
            kind = "file_write" if isinstance(act, FileWrite) else "file_read"
            ev = ws_sensor.make_event(kind, str(p))
            update = {"ts": ts}
            if act.untrusted_source is not None:  # declared ground-truth taint origin
                update["trust"] = "tainted"
                update["attrs"] = {**ev.attrs, "untrusted_source": act.untrusted_source}
            ev = ev.model_copy(update=update)
        elif isinstance(act, Egress):
            rec = {"host": act.host, "method": act.method, "path": "/",
                   "size": len(act.body), "truncated": False,
                   "body_b64": base64.b64encode(act.body).decode() if act.body else None,
                   "ts": ts}
            ev = egress_event_from_record(rec, scenario.id, d._store.put_blob)
        else:
            continue
        await d.submit(ev)
        ts += 1.0
    verdicts = [dec.verdict.name for _, dec, _ in d.decisions]
    chains = [c.steps for _, _, c in d.decisions if c is not None]
    warned = sum(1 for _, dec, _ in d.decisions if dec.verdict >= Verdict.WARN)
    await d.stop()
    return ObservedOutcome(verdicts=verdicts, chains=chains, warned_or_worse=warned)
