from pathlib import Path

import pytest

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


_POLICY = Path("src/agentwall/policy/default_policy.yaml")
_RULES = RulesConfig(sensitive_path_globs=["**/.env"], denied_dest_domains=[],
                     max_upload_bytes=5_000_000, entropy_threshold=7.5)

# A real secret Gitleaks detects (GitHub PAT shape; AWS EXAMPLE keys are allowlisted).
_SECRET = b"token=ghp_012345678901234567890123456789ABCD"


@pytest.mark.asyncio
async def test_secret_bearing_egress_completes_chain_and_quarantines(tmp_path):
    cfg = DaemonConfig(workspace=tmp_path, session_id="s1", db_path=tmp_path / "ev.db",
                       policy_path=_POLICY, rules=_RULES)
    d = Daemon(cfg, adapter=DockerSandboxAdapter(workspace=tmp_path))

    tainted = new_event(event_type="file_write", session_id="s1", source="workspace", ts=1.0,
                        trust="tainted", attrs={"untrusted_source": "evil.example/README.md"})
    await d.submit(tainted)

    ref = d._store.put_blob(_SECRET)  # simulate the EgressSensor having stored a body
    egress = new_event(event_type="network_upload", session_id="s1", source="egress", ts=2.0,
                       payload_ref=ref, attrs={"destination": "first-seen.xyz"})
    await d.submit(egress)

    verdicts = [dec.verdict for _, dec, _ in d.decisions]
    chains = [c for _, _, c in d.decisions if c is not None]
    assert Verdict.QUARANTINE in verdicts
    assert chains and chains[-1].steps == [
        "untrusted-source: evil.example/README.md", "secret-egress: first-seen.xyz"]
    await d.stop()


@pytest.mark.asyncio
async def test_health_reports_egress_degraded_field(tmp_path):
    cfg = DaemonConfig(workspace=tmp_path, session_id="s", db_path=tmp_path / "ev.db",
                       policy_path=_POLICY, rules=_RULES)
    d = Daemon(cfg, adapter=DockerSandboxAdapter(workspace=tmp_path))
    assert "egress_degraded" in d.health()
    await d.stop()


@pytest.mark.asyncio
async def test_stop_survives_failed_egress_task_and_closes_store(tmp_path):
    import asyncio
    import socket

    # Bind the proxy port ourselves so EgressSensor._start_proxy() finds it in use,
    # sets `degraded = True`, and raises — making self._egress_task fail immediately.
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    port = blocker.getsockname()[1]
    try:
        cfg = DaemonConfig(workspace=tmp_path, session_id="s", db_path=tmp_path / "ev.db",
                           policy_path=_POLICY, rules=_RULES, enable_egress=True,
                           egress_socket=tmp_path / "egress.sock", proxy_port=port)
        d = Daemon(cfg, adapter=DockerSandboxAdapter(workspace=tmp_path))
        await d.start()
        await asyncio.sleep(0.2)  # let the egress task hit the bound port and fail
        assert d._egress.degraded is True

        await d.stop()  # must not raise, and must close the store

        assert d.health()["egress_degraded"] is True
        import sqlite3
        with pytest.raises(sqlite3.ProgrammingError):
            d._store.append(new_event(event_type="x", session_id="s", source="workspace", ts=1.0))
    finally:
        blocker.close()
