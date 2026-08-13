from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from agentwall.detect.model import Detection
from agentwall.events import SecurityEvent


class GitleaksScanner:
    def __init__(self, binary: str = "gitleaks", timeout_s: float = 2.0) -> None:
        self._bin = binary
        self._timeout = timeout_s
        self.degraded = False

    def inspect(self, event: SecurityEvent, payload: bytes | None) -> list[Detection]:
        if payload is None:
            return []
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "payload"
            report = Path(d) / "report.json"
            src.write_bytes(payload)
            try:
                subprocess.run(
                    [self._bin, "detect", "--no-git", "--report-format", "json",
                     "--report-path", str(report), "--source", str(src)],
                    capture_output=True, timeout=self._timeout, check=False,
                )
            except (FileNotFoundError, subprocess.TimeoutExpired):
                self.degraded = True
                return []
            if not report.exists():
                return []
            findings = json.loads(report.read_text() or "[]")
        return [
            Detection(tier=1, classification=f"secret:{f.get('RuleID', 'unknown')}",
                      confidence=0.95, evidence=[f.get("Description", "")])
            for f in findings
        ]
