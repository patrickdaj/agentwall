from pathlib import Path

from agentwall.adapters.docker_sandbox import DockerSandboxAdapter
from agentwall.daemon import Daemon, DaemonConfig
from agentwall.detect.model import Verdict
from agentwall.detect.tier0_rules import RulesConfig
from agentwall.events import new_event

POLICY = Path("src/agentwall/policy/default_policy.yaml")


def _config(tmp_path):
    return DaemonConfig(
        workspace=tmp_path, session_id="s", db_path=tmp_path / "ev.db", policy_path=POLICY,
        rules=RulesConfig(sensitive_path_globs=["**/.env"], denied_dest_domains=["evil.example"],
                          max_upload_bytes=1_000_000, entropy_threshold=7.5),
    )


async def test_daemon_processes_injected_chain(tmp_path):
    d = Daemon(_config(tmp_path), adapter=DockerSandboxAdapter(workspace=tmp_path))
    await d.submit(new_event(event_type="file_read", session_id="s", source="workspace", ts=1.0,
                             trust="tainted", attrs={"untrusted_source": "evil/README"}))
    await d.submit(new_event(event_type="file_read", session_id="s", source="workspace", ts=2.0,
                             attrs={"path": "/w/.env", "sensitive": True}))
    await d.submit(new_event(event_type="network_upload", session_id="s", source="egress", ts=3.0,
                             attrs={"destination": "first-seen.xyz", "size": 4_000_000}))
    verdicts = [dec.verdict for _, dec, _ in d.decisions]
    assert Verdict.QUARANTINE in verdicts


async def test_health_reports_capabilities(tmp_path):
    d = Daemon(_config(tmp_path), adapter=DockerSandboxAdapter(workspace=tmp_path))
    h = d.health()
    assert "quarantine" in h["capabilities"] and h["tier2_rate"] == 0.0
