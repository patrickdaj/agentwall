from agentwall.eval.reporter import load_scenarios

REQUIRED_FAMILIES = {
    "prompt-injection-exfil", "supply-chain-postinstall", "mcp-tool-poisoning",
    "secret-harvest-egress", "persistence", "cloud-metadata-ssrf"}


def test_catalog_has_breadth_and_provenance():
    attacks = load_scenarios("agentwall.eval.scenarios")
    benign = load_scenarios("agentwall.eval.benign")
    assert len(attacks) >= 9          # 3 migrated + >=6 sourced
    assert len(benign) >= 3           # 1 migrated + >=2 sourced
    families = {s.family for s in attacks}
    assert REQUIRED_FAMILIES <= families, f"missing families: {REQUIRED_FAMILIES - families}"
    for s in attacks + benign:
        assert s.provenance.source and s.provenance.date, f"{s.id} missing provenance"
        # honesty rule: any scenario relying on declared taint must mark the ingress-taint gap
        needs_taint = any(getattr(a, "untrusted_source", None) for a in s.actions)
        if needs_taint:
            assert "ingress-taint" in s.sensors_required, f"{s.id} hides its taint dependency"


def test_blind_spots_are_present_and_honest():
    attacks = load_scenarios("agentwall.eval.scenarios")
    # AgentWall today lacks MCP/lifecycle/allowed-domain sensors, so some sourced
    # attacks MUST be marked blind-spot rather than softballed into 'caught'.
    assert any(s.status == "blind-spot" for s in attacks), "no blind spots — likely softballed"
