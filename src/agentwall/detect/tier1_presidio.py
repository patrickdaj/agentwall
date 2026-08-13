from __future__ import annotations

from agentwall.detect.model import Detection
from agentwall.events import SecurityEvent


class PresidioScanner:
    def __init__(self, min_score: float = 0.6, entities: list[str] | None = None) -> None:
        self._min = min_score
        self._entities = entities
        self._engine = None
        self.degraded = False

    def _analyzer(self):
        if self._engine is None:
            from presidio_analyzer import AnalyzerEngine
            self._engine = AnalyzerEngine()
        return self._engine

    def inspect(self, event: SecurityEvent, payload: bytes | None) -> list[Detection]:
        if not payload:
            return []
        text = payload.decode("utf-8", errors="ignore")
        try:
            results = self._analyzer().analyze(text=text, entities=self._entities, language="en")
        except Exception:
            self.degraded = True
            return []
        return [
            Detection(tier=1, classification=f"pii:{r.entity_type}",
                      confidence=r.score, evidence=[r.entity_type])
            for r in results if r.score >= self._min
        ]
