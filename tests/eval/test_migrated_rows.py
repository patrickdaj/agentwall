import pytest

from agentwall.detect.tier0_rules import RulesConfig
from agentwall.eval.driver import run_scenario
from agentwall.eval.reporter import load_scenarios
from agentwall.eval.scorer import score

_RULES = RulesConfig(sensitive_path_globs=["**/.env", "**/.git/hooks/*", "**/package.json"],
                     denied_dest_domains=[], max_upload_bytes=5_000_000, entropy_threshold=7.5)


@pytest.mark.asyncio
async def test_all_migrated_rows_meet_expectation(tmp_path):
    scenarios = load_scenarios("agentwall.eval.scenarios") + load_scenarios("agentwall.eval.benign")
    ids = {s.id for s in scenarios}
    assert {"row1", "row2", "row3", "row9"} <= ids
    for scn in scenarios:
        observed = await run_scenario(scn, tmp_path / scn.id, _RULES)
        r = score(scn, observed)
        assert r.outcome == "caught", f"{scn.id}: {r.outcome}"  # incl. benign row9 staying silent
        assert r.is_regression is False
