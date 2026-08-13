from __future__ import annotations

import math
from fnmatch import fnmatch

from pydantic import BaseModel

from agentwall.detect.model import Detection
from agentwall.events import SecurityEvent


class RulesConfig(BaseModel):
    sensitive_path_globs: list[str]
    denied_dest_domains: list[str]
    max_upload_bytes: int
    entropy_threshold: float


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


class RulesDetector:
    def __init__(self, config: RulesConfig) -> None:
        self._c = config

    def inspect(self, event: SecurityEvent, payload: bytes | None) -> list[Detection]:
        out: list[Detection] = []
        path = event.attrs.get("path")
        if path and any(fnmatch(path, g) for g in self._c.sensitive_path_globs):
            out.append(Detection(tier=0, classification="sensitive_path_access",
                                  confidence=1.0, evidence=[path]))
        dest = event.attrs.get("destination")
        if dest and any(dest == d or dest.endswith("." + d) for d in self._c.denied_dest_domains):
            out.append(Detection(tier=0, classification="denied_destination",
                                 confidence=1.0, evidence=[dest]))
        size = event.attrs.get("size")
        if isinstance(size, int) and size > self._c.max_upload_bytes:
            out.append(Detection(tier=0, classification="oversize_upload",
                                 confidence=1.0, evidence=[f"{size} bytes"]))
        if payload is not None and shannon_entropy(payload) >= self._c.entropy_threshold:
            out.append(Detection(tier=0, classification="high_entropy",
                                 confidence=0.7, evidence=[f"entropy>={self._c.entropy_threshold}"]))
        return out
