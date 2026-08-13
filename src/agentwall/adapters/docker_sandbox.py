from __future__ import annotations

import subprocess
from pathlib import Path


class DockerSandboxAdapter:
    def __init__(self, workspace: Path, sbx_binary: str = "sbx") -> None:
        self._workspace = Path(workspace)
        self._sbx = sbx_binary

    def capabilities(self) -> set[str]:
        return {"observe", "quarantine"}

    def resolve_workspace_path(self) -> Path:
        return self._workspace

    def quarantine(self, session_id: str) -> bool:
        try:
            r = subprocess.run([self._sbx, "stop", session_id], capture_output=True, timeout=10, check=False)
            return r.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
