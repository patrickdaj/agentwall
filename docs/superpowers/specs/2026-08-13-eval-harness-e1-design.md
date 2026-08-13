# Eval harness E1 — evaluation foundation — design

**Date:** 2026-08-13
**Status:** approved (design), pending spec review
**Position in v1:** built NEXT, right after sub-project B, before A (see
[v1 order](#relationship-to-the-v1-roadmap)).

## Problem

AgentWall's attack corpus (rows 1–3, 9) is authored by the same people who wrote
the detectors, and — worse — each scenario hand-builds `SecurityEvent`s with the
answers **pre-filled**. `corpus/scenario_02_git_hook.py` literally sets
`attrs={"implicit_exec": True, "sensitive": True}` on the event, so the detector
is *told* it's a git hook instead of discovering it. Two consequences:

1. **Self-marking.** We only include attacks our own rules catch, and the events
   are pre-labeled, so the corpus measures policy/correlator wiring, not
   detection. It cannot honestly gauge whether AgentWall *identifies* an attack.
2. **No honest scorecard.** There is no false-positive measurement, no notion of
   an attack we legitimately *can't* see, and no way to track detection rate as
   capabilities are added.

## Goal

An honest, offline **measurement instrument**: reproduce real-world attacks
faithfully (defanged), run them through the *real* detection pipeline so
detectors earn every attribute, and report AgentWall's true detection rate
(including attacks it cannot catch) and false-positive rate, with a coverage
matrix. It reframes rows 1–9 onto the new schema. It is the yardstick every
later sub-project is measured against.

Non-goals for E1 (they are later workstream pieces): live-sandbox replay and
substrate comparison (E2); adversarial red-team generation (E3).

## Key design decisions

- **Honest measurement instrument** (not a demo). Optimizes for breadth +
  truthful scoring; demo-worthy catches fall out for free.
- **Offline fidelity, driven from real artifacts.** Scenarios declare real
  actions with real (defanged) payloads; the driver reconstructs events through
  the *real sensor code* so classification is earned, not authored. The one
  thing this tier cannot exercise is OS-level sensor *observation* (the watchdog
  actually firing, mitmproxy actually capturing) — that is E2, and the coverage
  matrix marks it as an honest gap.
- **External provenance + faithfulness bar.** Every scenario must cite a real
  documented incident or published research PoC and clear "would a real analyst
  recognize this attack." No invented attacks. (Adversarial generation is E3.)
- **Expected-status + regression gate.** Each scenario carries an expected
  outcome and a status (`caught` / `blind-spot` / `partial`). CI fails only on
  regressions — a `caught` scenario now missed, or a benign scenario newly
  flagged. Blind spots are first-class expected-misses that do NOT fail the
  build; detection rate, FP rate, and the coverage matrix are tracked metrics.
- **No substrate column in E1.** Substrate-vs-AgentWall comparison requires a
  live substrate to observe and is Docker-Sandboxes-only; it belongs in E2. A
  "modeled" substrate column here would be fake measurement — omitted
  deliberately.

## Architecture

```
 eval/
 ├── schema.py        Scenario, Action types, ExpectedOutcome, Status, provenance
 ├── driver.py        build real artifacts → real sensor event-construction → daemon → observed outcome
 ├── scorer.py        compare observed vs expected; classify caught/missed/regression/FP
 ├── reporter.py      detection rate, FP rate, coverage matrix; CLI entry
 ├── scenarios/       one file per attack scenario (externally sourced)
 └── benign/          benign-but-scary sessions (FP suite)
```

Data flow per scenario: `scenario.actions` → `driver` writes real temp
artifacts and calls the **real** `WorkspaceSensor.make_event` /
`EgressSensor._to_event` on them (so `classify_path`, Gitleaks, Presidio derive
`implicit_exec`/`sensitive`/`secret:`/`pii:` from raw path+bytes) → events are
submitted to a real `Daemon` → observed verdicts + chains → `scorer` vs
`expected` → `reporter` aggregates.

## Components

### 1. `eval/schema.py`

```
class Provenance(BaseModel):
    source: str            # URL or citation
    kind: Literal["incident", "research", "advisory"]
    date: str              # ISO; when the attack/PoC was documented
    note: str = ""

# Declarative actions — real artifacts, defanged payloads:
FileWrite(path: str, content: bytes)      # written to the scenario workspace
FileRead(path: str, content: bytes)       # seeds a file, models a read (see note)
Egress(host: str, method: str, body: bytes)

class ExpectedOutcome(BaseModel):
    min_verdict: str       # "ALLOW" | "WARN" | "BLOCK" | "QUARANTINE"
    expect_chain: bool

class Scenario(BaseModel):
    id: str
    title: str
    family: str            # e.g. "prompt-injection-exfil", "supply-chain-postinstall"
    provenance: Provenance
    actions: list[Action]
    expected: ExpectedOutcome
    status: Literal["caught", "blind-spot", "partial"]
    sensors_required: list[str]   # sensors that would observe it live; feeds the matrix
```

Benign scenarios reuse `Scenario` with `expected.min_verdict = "ALLOW"`,
`expect_chain=False`, `status="caught"` (i.e. correctly staying silent is the
pass condition); they live in `eval/benign/` and are the FP suite.

**Read modeling note:** live read observation does not exist (a v1.x concern),
so a `FileRead` action seeds the file and, for taint modeling, emits a
workspace read event constructed via the real `make_event` path — its purpose
is to let chains that depend on a read step be represented; scenarios whose
realism depends on true read observation are marked `blind-spot` until that
sensor exists.

### 2. `eval/driver.py`

- `run_scenario(scenario, tmp_path, rules) -> ObservedOutcome` where
  `ObservedOutcome = {verdicts: list[str], chains: list[list[str]], warned_or_worse: int}`.
- For each action, construct the event through the **real** sensor code (not
  hand-built): `FileWrite`/`FileRead` → write a real temp file with the given
  bytes, then `WorkspaceSensor(workspace, session, blob_put=store.put_blob).make_event(kind, path)`;
  `Egress` → build a record from the real body and pass it through
  `EgressSensor._to_event` (blob-backed), so Tier-1 scans the real bytes.
- Submit events to a real `Daemon` (egress disabled — no proxy), collect
  decisions. Reuses the existing `corpus/runner.py` daemon pattern.
- The driver reuses the sensors' real event-construction so classification is
  earned. `WorkspaceSensor.make_event` is public; `EgressSensor._to_event` is
  currently private — the plan should extract egress event-construction into a
  small reusable function (or a public classmethod) that both the sensor and the
  driver call, rather than the driver reaching into a private method. Detection
  itself (Gitleaks/Presidio on the real bytes, `has_secret` → chain) happens in
  the real cascade/daemon, unchanged.
- Fail-safe: a scenario that errors during driving is reported as an `error`
  outcome (distinct from a detection miss), never crashes the run.

### 3. `eval/scorer.py`

- `score(scenario, observed) -> ScenarioResult` with fields
  `{id, family, status, outcome: "caught"|"missed"|"error", is_regression: bool, is_false_positive: bool}`.
- **caught** iff the observed verdict ≥ `expected.min_verdict` and
  `expect_chain` matches. **missed** otherwise.
- For benign scenarios: **false_positive** iff `warned_or_worse > 0`.
- **is_regression** iff a `status="caught"` attack scenario is now `missed`, OR
  a benign scenario is now a false positive. (A `blind-spot` scenario that is
  missed is expected, not a regression; a `blind-spot` that is now *caught* is
  surfaced as a "promote status" note, not a failure.)

### 4. `eval/reporter.py` + CLI

- Aggregates `ScenarioResult`s into: **detection rate** (caught ÷ attack
  scenarios), **false-positive rate** (FPs ÷ benign scenarios), and a
  **coverage matrix** (rows = family, columns = `sensors_required`, cell =
  status/outcome), rendered as a Markdown table.
- CLI: `agentwall eval` (a Typer subcommand alongside `run`/`status`/…) prints
  the summary + matrix; `--json` for machine consumption; exit code non-zero iff
  any `is_regression` is true (the CI gate). A `--update-baseline` mode rewrites
  the tracked metrics snapshot.

## Seed catalog

E1 ships ~10–15 scenarios across ~8 families, each with a real citation. Sourcing
requires a research pass (documented incidents + research PoCs) — done during
implementation with the web/deep-research tooling, and each citation verified.
Rows 1–3 and 9 are migrated onto the schema as the first entries (real artifacts
replacing pre-labeled events). Candidate families (final list set during the
sourced research pass): prompt-injection→exfil, supply-chain postinstall /
slopsquatting, MCP tool poisoning / rug-pull, secret harvesting → egress
(incl. allowlisted-channel exfil), git-hook / CI / config persistence,
zero-click / markdown-render exfil, invisible-Unicode instruction smuggling,
cloud-metadata (SSRF) access. Scenarios whose realism needs sensors AgentWall
lacks today (MCP, lifecycle, read observation, allowed-domain payload egress)
are included and marked `blind-spot` — that is the point.

## Testing

- Unit: `schema` round-trips; `driver` builds a real file and produces an event
  whose attrs were *derived by the real classifier* (e.g. a `.git/hooks/x` write
  yields `implicit_exec=True` without the scenario setting it — the anti-
  self-marking property, asserted directly); `scorer` classifies
  caught/missed/regression/FP correctly incl. the blind-spot rules; `reporter`
  renders the matrix and the CLI exit code gates on regression only.
- Migration: the four migrated rows (1–3, 9) reproduce their v0 outcomes through
  the new driver (row 1 QUARANTINE + chain; rows 2–3 WARN+; row 9 silent).
- The whole `agentwall eval` run is itself exercised in CI as the regression
  gate.

## Relationship to the existing corpus

`eval/` subsumes `corpus/`: rows 1–3 and 9 are re-authored as `Scenario`s and the
old `corpus/` package + `tests/corpus/` are retired once parity is shown. Rows
4–8 (previously "sub-project E") become sourced scenarios in `eval/scenarios/`.

## Relationship to the v1 roadmap

Order: **B (done) → E1 (this) → A → C → D → E2 → MCP/Lifecycle sensors → E3.**
E1 is next because a measurement instrument is worth most before the capabilities
it measures: its first report is an honest, low baseline (row-1 egress chain
caught; a long column of blind spots), and that ranked blind-spot list makes the
prioritization of A/C/D/E data-driven rather than guessed. E1 also serves as the
regression guard for A's plugin refactor. E2 (live replay + Docker-Sandboxes
substrate comparison) and E3 (adversarial red-team generation) build on E1's
schema and scorer.
