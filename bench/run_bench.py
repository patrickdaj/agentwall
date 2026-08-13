from __future__ import annotations

import time
from pathlib import Path
from statistics import quantiles

from pydantic import BaseModel

from agentwall.adapters.docker_sandbox import DockerSandboxAdapter
from agentwall.daemon import Daemon, DaemonConfig
from agentwall.detect.tier0_rules import RulesConfig
from agentwall.events import new_event

_POLICY = Path("src/agentwall/policy/default_policy.yaml")
_RULES = RulesConfig(sensitive_path_globs=["**/.env"], denied_dest_domains=[],
                     max_upload_bytes=5_000_000, entropy_threshold=7.5)


class BenchResult(BaseModel):
    events: int
    p50_ms: float
    p95_ms: float
    p99_ms: float
    tier2_rate: float


def _pct(latencies_ms: list[float], p: float) -> float:
    if len(latencies_ms) < 2:
        return latencies_ms[0] if latencies_ms else 0.0
    return quantiles(latencies_ms, n=100)[min(int(p) - 1, 98)]


async def run_bench(n: int, tmp_path: Path) -> BenchResult:
    cfg = DaemonConfig(workspace=tmp_path, session_id="bench", db_path=tmp_path / "ev.db",
                       policy_path=_POLICY, rules=_RULES)
    d = Daemon(cfg, adapter=DockerSandboxAdapter(workspace=tmp_path))
    lat: list[float] = []
    for i in range(n):
        # benign, detail-free event → no detections → no escalation → pure overhead
        e = new_event(event_type="noop", session_id="bench", source="workspace", ts=float(i), attrs={})
        t0 = time.perf_counter()
        await d.submit(e)
        lat.append((time.perf_counter() - t0) * 1000)
    health = d.health()
    await d.stop()
    return BenchResult(events=n, p50_ms=_pct(lat, 50), p95_ms=_pct(lat, 95),
                       p99_ms=_pct(lat, 99), tier2_rate=health["tier2_rate"])


def assert_targets(res: BenchResult) -> None:
    assert res.p95_ms < 10.0, f"p95 {res.p95_ms:.2f}ms exceeds 10ms target"
    assert res.tier2_rate < 0.02, f"tier2 rate {res.tier2_rate:.3f} exceeds 2% target"


if __name__ == "__main__":
    import asyncio
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        r = asyncio.run(run_bench(1000, Path(d)))
        print(r.model_dump_json(indent=2))
