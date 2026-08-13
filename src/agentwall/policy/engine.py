from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel

from agentwall.detect.model import Detection, Verdict
from agentwall.events import SecurityEvent

_CAP_FOR = {Verdict.BLOCK: "block", Verdict.QUARANTINE: "quarantine"}


class Decision(BaseModel):
    verdict: Verdict
    matched_rule: str | None
    explanation: str
    downgraded: bool = False


class PolicyEngine:
    def __init__(self, rules: list[dict], capabilities: set[str]) -> None:
        self._rules = rules
        self._caps = capabilities

    @classmethod
    def from_yaml(cls, path: str | Path, capabilities: set[str]) -> "PolicyEngine":
        doc = yaml.safe_load(Path(path).read_text()) or {}
        return cls(doc.get("rules", []), capabilities)

    def _matches(self, match: dict, event: SecurityEvent, detections: list[Detection], in_chain: bool) -> bool:
        if "classification_prefix" in match:
            pref = match["classification_prefix"]
            if not any(d.classification.startswith(pref) for d in detections):
                return False
        if "source" in match and match["source"] != event.source:
            return False
        if "in_chain" in match and bool(match["in_chain"]) != in_chain:
            return False
        return True

    def evaluate(self, event: SecurityEvent, detections: list[Detection], in_chain: bool) -> Decision:
        best: Decision | None = None
        for rule in self._rules:
            if self._matches(rule.get("match", {}), event, detections, in_chain):
                verdict = Verdict[rule["action"]]
                need = _CAP_FOR.get(verdict)
                if need and need not in self._caps:
                    cand = Decision(verdict=Verdict.WARN, matched_rule=rule["name"],
                                    explanation=f"{verdict.name} downgraded to WARN: adapter lacks '{need}'",
                                    downgraded=True)
                else:
                    cand = Decision(verdict=verdict, matched_rule=rule["name"],
                                    explanation=f"matched rule '{rule['name']}'")
                if best is None or cand.verdict > best.verdict:
                    best = cand
        if best is None:
            return Decision(verdict=Verdict.ALLOW, matched_rule=None, explanation="no rule matched")
        return best
