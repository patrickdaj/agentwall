from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel

from agentwall.adapters.docker_sandbox import DockerSandboxAdapter
from agentwall.daemon import Daemon, DaemonConfig
from agentwall.detect.model import Verdict
from agentwall.detect.tier0_rules import RulesConfig
from agentwall.events import SecurityEvent

_POLICY = Path("src/agentwall/policy/default_policy.yaml")


class ScenarioResult(BaseModel):
    name: str
    verdicts: list[str]
    chains: list[list[str]]
    warned_or_worse: int


async def run_scenario(events: list[SecurityEvent], tmp_path: Path, rules: RulesConfig,
                       name: str = "scenario") -> ScenarioResult:
    cfg = DaemonConfig(workspace=tmp_path, session_id=events[0].session_id if events else "s",
                       db_path=tmp_path / "ev.db", policy_path=_POLICY, rules=rules)
    d = Daemon(cfg, adapter=DockerSandboxAdapter(workspace=tmp_path))
    for e in events:
        await d.submit(e)
    verdicts = [dec.verdict.name for _, dec, _ in d.decisions]
    chains = [c.steps for _, _, c in d.decisions if c is not None]
    warned = sum(1 for _, dec, _ in d.decisions if dec.verdict >= Verdict.WARN)
    await d.stop()
    return ScenarioResult(name=name, verdicts=verdicts, chains=chains, warned_or_worse=warned)
