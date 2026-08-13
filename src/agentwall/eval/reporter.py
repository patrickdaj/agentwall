from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path

from agentwall.detect.tier0_rules import RulesConfig
from agentwall.eval.driver import run_scenario
from agentwall.eval.schema import Scenario
from agentwall.eval.scorer import ScenarioScore, score

_RULES = RulesConfig(sensitive_path_globs=["**/.env", "**/.env.*", "**/.ssh/*", "**/.aws/*",
                                           "**/.git/hooks/*", "**/package.json", "**/.npmrc"],
                     denied_dest_domains=[], max_upload_bytes=5_000_000, entropy_threshold=7.5)


def load_scenarios(package: str) -> list[Scenario]:
    pkg = importlib.import_module(package)
    found: list[Scenario] = []
    for info in pkgutil.iter_modules(pkg.__path__):
        mod = importlib.import_module(f"{package}.{info.name}")
        scn = getattr(mod, "SCENARIO", None)
        if isinstance(scn, Scenario):
            found.append(scn)
    return sorted(found, key=lambda s: s.id)


def has_regression(scores: list[ScenarioScore]) -> bool:
    return any(s.is_regression for s in scores)


def render_report(scores: list[ScenarioScore]) -> str:
    attacks = [s for s in scores if not _is_benign(s)]
    benigns = [s for s in scores if _is_benign(s)]
    caught = sum(1 for s in attacks if s.outcome == "caught")
    fps = sum(1 for s in benigns if s.is_false_positive)
    lines = ["# AgentWall eval report", "",
             f"- Detection rate: {caught}/{len(attacks)}",
             f"- False-positive rate: {fps}/{len(benigns)}",
             f"- Regressions: {sum(1 for s in scores if s.is_regression)}", "",
             "## Coverage matrix", "", "| family | id | status | outcome |",
             "|---|---|---|---|"]
    for s in sorted(scores, key=lambda x: (x.family, x.id)):
        lines.append(f"| {s.family} | {s.id} | {s.status} | {s.outcome} |")
    return "\n".join(lines)


def _is_benign(s: ScenarioScore) -> bool:
    return s.benign


async def run_eval(rules: RulesConfig | None = None) -> tuple[list[ScenarioScore], str]:
    rules = rules or _RULES
    scenarios = load_scenarios("agentwall.eval.scenarios") + load_scenarios("agentwall.eval.benign")
    scores: list[ScenarioScore] = []
    for scn in scenarios:
        try:
            observed = await run_scenario(scn, Path("/tmp") / f"eval-{scn.id}", rules)
            scores.append(score(scn, observed))
        except Exception:  # a broken scenario is an error outcome, never crashes the run
            scores.append(ScenarioScore(id=scn.id, family=scn.family, status=scn.status,
                                        outcome="error", is_regression=(scn.status == "caught"),
                                        is_false_positive=False, benign=scn.benign))
    return scores, render_report(scores)
