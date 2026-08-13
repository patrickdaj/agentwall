# AgentWall

**The sandbox handles containment ("the agent can't escape"). AgentWall handles
understanding ("should it be doing this?") — including the host-boundary attacks the
sandbox model itself leaves open — and rides on top of whichever sandbox you already
use.**

AgentWall is a local-first, host-side security daemon for AI coding agents. It watches
agent activity through sensors, classifies it with a deterministic-first detection
cascade, correlates events into provenance chains, and enforces a capability-gated YAML
policy. It is not a sandbox and does not compete with one — see "Substrates vs.
competitors" below.

Full design rationale: `docs/superpowers/specs/2026-08-13-agentwall-design.md`.

## Status: v0 foundation

This is the **v0 foundation** milestone, not a full v1 ship. v0 delivers the load-bearing
skeleton — daemon, real sensor, deterministic detection, provenance, policy, one runtime
adapter, CLI, and a benchmark harness — proven against a subset of the attack corpus.
Several pieces named in the design spec are explicitly **not** in v0 (see below); they
are scoped for v1.

### What v0 ships

- **Host-side daemon** — event bus + SQLite (WAL) event store, health reporting.
- **WorkspaceSensor** (real, not mocked) — watches the workspace via file write/create
  events for implicit-execution files (git hooks, `package.json` scripts, etc.); it does
  not observe file reads (see the corpus caveat below).
- **Detection cascade** — Tier 0 deterministic rules (path/entropy/size rules) and
  Tier 1 Gitleaks (secrets) + Presidio (PII), wired through a cascade with a **Tier-2
  seam** (`SecurityClassifier` protocol) currently satisfied by a `NullClassifier`. No
  SLM is registered in v0 — Tier-2 classification is v1 work; the interface exists so it
  drops in without changing callers. **Caveat:** Tier-1 secret/PII scanning (Gitleaks,
  Presidio) and the Tier-0 entropy check are implemented and unit-tested, but no v0
  sensor attaches payload bytes yet, so they do not run in the live pipeline —
  `WorkspaceSensor` computes a `content_hash` but sets no `payload_ref`, so
  `daemon._on_event` always receives `payload=None` and these scanners early-return
  `[]`. Wiring a payload source is v1 work.
- **Provenance chain correlator** — source-scoped, hash-linked taint chains
  (untrusted-source → sensitive-access → egress), not session-wide taint.
- **Capability-gated YAML policy engine** — `(event_class, data_class, ...)` →
  `ALLOW / WARN / BLOCK / QUARANTINE`, checked against what the active runtime adapter
  actually declares it can enforce.
- **Docker Sandbox runtime adapter** — declares `observe` and `quarantine` capabilities.
  It does **not** declare an inline-block capability in v0 — there is no inline egress
  gating yet; that is v1 work gated behind the TLS spike outcome (design spec §7).
- **CLI** (`agentwall`) — `status`, `replay`, `policy`, `run` (including a `--check`
  health-check mode used in the quickstart below).
- **Attack corpus, rows 1–3 and row 9** — the host-boundary/provenance-chain scenarios
  that a network-only detector structurally cannot see, plus the benign control suite:
  - Row 1: malicious README → agent reads `.env` → POST to a new domain (classic taint
    chain; a network-only tool sees only the final hop).
  - Row 2: injection → agent edits `.git/hooks/post-commit` → payload runs on the host
    later (invisible to any network-vantage tool).
  - Row 3: injection → `package.json` postinstall script added → runs on host
    `npm install` (same: no network signal exists to see).
  - Row 9: benign control suite — real-shaped coding-session activity must produce
    **zero** WARN-or-worse (the false-positive budget the whole cascade is honest
    about).
  - **Caveat:** row 1's read and egress steps are injected synthetically into the event
    bus to exercise the correlator and prove the chain logic — v0 has no EgressSensor
    and `WorkspaceSensor` does not observe file reads, so row 1 is not yet observed via
    live sensors; that awaits v1 (EgressSensor, read observation). Rows 2–3 are
    reachable through the live v0 `WorkspaceSensor` (real file-write/file-create
    events).
- **Benchmark harness** — `bench/run_bench.py`, measuring event-path p50/p95/p99
  latency and Tier-2 invocation rate against the daemon's own submit path.

### Explicitly deferred to v1 (not in v0, do not assume otherwise)

- **EgressSensor, MCPSensor, LifecycleSensor** — only WorkspaceSensor is real in v0.
  Corpus rows that need egress/MCP/lifecycle visibility (4–8) are not implemented.
- **Tier-2 SLM classifier** — the `SecurityClassifier` seam exists and is exercised by
  the cascade, but only the `NullClassifier` (always-abstain) is registered. No
  encoder/SLM model is loaded or invoked in v0; Tier-2 invocation rate is therefore
  always 0.
- **Attack corpus rows 4–8** — shared skills-store poisoning, malicious MCP
  registration, allowed-domain exfil, low-and-slow exfil, and policy-drift detection
  are v1 scope (they depend on the sensors above).
- **Inline egress blocking** — the Docker Sandbox adapter can observe and quarantine
  (pause/kill the sandbox); it cannot yet block an individual outbound request inline.
- **Golden-replay snapshotting** — `agentwall replay` exists and reconstructs chains,
  but a CI-enforced snapshot corpus for BLOCK/QUARANTINE scenarios lands with the
  fuller (v1) attack corpus.

## Substrates vs. competitors

Sandbox runtimes (Docker Sandboxes, clawk, Clawker) are **substrates AgentWall rides
on**, not competitors — they do containment, and their own documentation explicitly
disclaims content inspection, DLP, prompt-injection detection, and provenance tracking.
Tools like Pipelock, AEGIS, TokenWall, and Strathon are the actual detection
competitors: they watch from a single vantage point (network, or a single tool call)
and cannot see attacks that cross the workspace/host boundary the way AgentWall's
WorkspaceSensor and chain correlator can (design spec §13).

## Quickstart

```bash
# Install dependencies
uv sync

# Run the test suite
uv run pytest

# Run the daemon health check against this workspace
uv run agentwall run \
  --workspace . \
  --session dev \
  --db /tmp/aw.db \
  --policy src/agentwall/policy/default_policy.yaml \
  --check
```

The health check prints the daemon's health payload (degraded flag, event count,
Tier-2 rate, and the active runtime adapter's declared capabilities) and exits without
starting a long-running watch loop.

## Benchmarks

Measured, not claimed (design spec §6), via `uv run python -m bench.run_bench` (1,000
synthetic no-op workspace events through the live daemon submit path):

```json
{
  "events": 1000,
  "p50_ms": 0.0813750084489584,
  "p95_ms": 0.13953993620816618,
  "p99_ms": 0.1739342208020389,
  "tier2_rate": 0.0
}
```

Host: Apple Silicon macOS (Apple M3 Pro, macOS 15.5), Python 3.12.11, via `uv run`.
Well under the design spec's Tier 0/1 p95 < 10 ms target. `tier2_rate` is 0 because v0
has no SLM registered on the Tier-2 seam (`NullClassifier` only) — every event resolves
at Tier 0/1, so nothing is escalated. This will move once a real Tier-2 classifier
lands in v1, and the <2% budget will start meaning something rather than being trivially
satisfied.

## Test suite

```bash
uv run pytest -q
```

54 passed as of this writing. Gitleaks and Presidio integration tests run for real
(not skipped) — both tools are installed as part of the Tier-1 scanner setup.

## Sandbox dev workflow

Repeatable Docker Sandboxes (sbx) workflow for developing with a Claude agent
sandboxed on this repo. All host state (egress allow rules, proxy settings,
background mitmweb) is owned and undone by the script.

| Command | Does |
|---|---|
| `make sandbox` | Launch/attach the Claude sandbox; ensures the dev egress allowlist and the Anthropic no-proxy bypass (login works on first run) |
| `make sandbox-inspect` | Chain all sandbox egress (except Anthropic auth/API) through mitmproxy on :8888 with the CA trusted in-sandbox; web UI URL in `~/.cache/agentwall/mitmweb.log` |
| `make sandbox-direct` | Back to direct egress (default state) |

> **Note:** switching between inspect and direct runs `sbx daemon restart` —
> `proxy.sandbox` changes only take effect on a daemon restart, not a sandbox
> restart (verified). The daemon restart briefly stops any other running
> sandboxes on your machine and adds a few seconds to the toggle.
| `make sandbox-clean` | Remove sandbox, script-owned policy rules and settings overrides, stop mitmweb |

`scripts/sandbox.sh verify` proves the current mode: it checks the TLS issuer
seen inside the sandbox (`CN=mitmproxy` vs the real CA) and that an HTTPS POST
egresses successfully. `ATTACH=0` skips the interactive attach for scripting.

Findings behind this design (CONNECT chaining, CA-trust requirement, no_proxy
bypass for OAuth) are in `docs/spikes/tls-egress.md` and
`docs/superpowers/specs/2026-08-13-sandbox-dev-workflow-design.md`.
