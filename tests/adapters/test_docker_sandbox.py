from pathlib import Path

from agentwall.adapters.docker_sandbox import DockerSandboxAdapter


def test_capabilities_are_honest_for_v0(tmp_path):
    a = DockerSandboxAdapter(workspace=tmp_path)
    caps = a.capabilities()
    assert "quarantine" in caps and "observe" in caps
    assert "block" not in caps  # no inline egress block until v1


def test_resolve_workspace(tmp_path):
    a = DockerSandboxAdapter(workspace=tmp_path)
    assert a.resolve_workspace_path() == Path(tmp_path)


def test_quarantine_missing_binary_is_fail_safe(tmp_path):
    a = DockerSandboxAdapter(workspace=tmp_path, sbx_binary="not-a-real-sbx-xyz")
    assert a.quarantine("session-1") is False
