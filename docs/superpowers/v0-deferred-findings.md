# AgentWall v0 — Deferred Findings & v1 Backlog

Findings surfaced during v0 subagent-driven implementation and the final
whole-branch review. None block the v0 foundation; each is either genuinely
deferred scope or a hardening item for v1. Ordered by impact.

## Important (parked, deferred to v1)

- **Tier-1 scanners are inert end-to-end.** Gitleaks/Presidio and the Tier-0
  entropy rule are implemented and unit-tested, but no v0 sensor attaches
  payload bytes — `WorkspaceSensor` computes a `content_hash` yet sets no
  `payload_ref`, so `daemon._on_event` always gets `payload=None` and the
  scanners early-return `[]`. **v1:** wire a payload source (e.g. attach
  `store.put_blob(...)` output to `payload_ref` for sensitive/implicit-exec
  writes, with a size cap). *(README carries a caveat.)*
- **Row-1 chain is not observable by a live v0 sensor.** WorkspaceSensor emits
  only write/create events; there is no read observation and no EgressSensor,
  so the corpus row-1 chain is exercised via synthetically injected events.
  **v1:** EgressSensor + read observation make row 1 live. *(README caveat.)*
- **Blocking subprocess in the async loop** (`daemon._on_event`): Gitleaks
  (timeout 2s) and `adapter.quarantine` (timeout 10s) run synchronously inside
  the event loop. Not load-bearing for v0 (scanners never run in the live loop
  per the payload gap above; quarantine is rare), but **v1:** offload via
  `asyncio.to_thread`.
- **Unguarded `Verdict[action]` / `rule["name"]`** in `PolicyEngine.evaluate`:
  a malformed policy YAML raises `KeyError` (fails loud, not fail-open).
  Acceptable in v0 (only the trusted default policy ships). **v1:** validate
  rules when policies become user-editable.

## Minor (deferred)

- `escalate_on_any` escalates to Tier-2 on *any* detection — harmless with the
  `NullClassifier`, but will blow the <2% Tier-2 budget once a real SLM lands.
  Design a smarter escalation predicate before wiring the SLM.
- Provenance sensitive-access step fires on *any* tainted-session `file_read`/
  `file_write` with a path (workspace-scoped but not sensitive-path-scoped) — a
  real-world FP source. Consider tightening to sensitive paths.
- Dead/inert surface: `oversize_upload` and `high_entropy` classifications have
  no matching policy rule; `Verdict.REQUIRE_APPROVAL` is never emitted;
  `classify_path` always returns `skills_store: False` (set later in
  `make_event`).
- `bench/run_bench.py` and `corpus/runner.py` hardcode a **relative** policy
  path — only work from repo root.
- Bus replay re-invokes already-succeeded handlers on partially-failed events
  (needs handler idempotency); documented.
- `ChainCorrelator._states` grows unbounded per `session_id` — add eviction for
  long-running processes.
- `WorkspaceSensor.make_event` reads full file bytes on the watchdog thread per
  event — add a size cap / streaming hash.
- `run_scenario` (corpus) and the CLI lack `try/finally` around daemon stop —
  `EventStore` can leak on mid-loop exception.
- `test_detects_aws_key` (gitleaks) actually uses a GitHub PAT payload (AWS
  EXAMPLE keys are allowlisted by gitleaks) — rename to `test_detects_secret`.
- Unused `import pytest` in `tests/test_bus.py`.
- `corpus/` importable only via pytest's `sys.path` insertion (not an installed
  package).
- `WorkspaceSensor.stop()` does a synchronous `Observer.join()` from the event
  loop thread.

## v1 direction: full plugin architecture (decided 2026-08-13)

AgentWall v1 becomes a **full plugin system**, not a monolith. The v0 `Protocol`
seams (`RuntimeSensor`, `Detector`, `SecurityClassifier`, `PolicyEngine`,
`RuntimeAdapter`) exist, but the daemon hardcodes which implementations it
constructs. v1 formalizes:

- a **registry** the daemon loads from instead of hardcoding constructors;
- **entry-point discovery** (e.g. `agentwall.detectors` / `agentwall.sensors` /
  `agentwall.adapters` groups) so third parties pip-install a package and it is
  picked up automatically;
- **config-driven enablement** — which plugins are on, in what order, with what
  settings;
- the **policy engine remains the trust anchor**: plugins emit `Detection`s only
  and never produce a `Verdict`, so a third-party scanner cannot escalate
  privilege. This boundary already holds in v0 and is what makes a plugin
  ecosystem safe.

This lets the community add detectors (YARA, Semgrep, TruffleHog), sensors, and
runtime adapters (clawk, Clawker) without forking.

## Human-run task (not code)

- **TLS egress spike** (plan Task 2): determine whether Docker Sandboxes'
  upstream-proxy chain exposes request plaintext or only CONNECT+SNI. Gates the
  v1 egress-DLP direction. Requires a live Docker Sandbox + manual traffic;
  write up in `docs/spikes/tls-egress.md`.
