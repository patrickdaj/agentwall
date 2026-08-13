# AgentWall — Design Spec

**Date:** 2026-08-13
**Status:** Approved for planning
**Goal:** Serious open-source project

---

## 1. Summary

**AgentWall** is a local-first, agent-agnostic runtime security plane for AI coding
agents. It runs as a host-side daemon that observes agent activity through sensors,
classifies it with a deterministic-first detection cascade, correlates events into
provenance chains, and enforces YAML policy — with **Docker Sandboxes** as the
flagship runtime and plain Docker / clawk / Clawker as reduced-fidelity targets.

The differentiator is **cross-layer correlation and host-boundary coverage**, not
"another egress firewall." Existing tools (Pipelock, Strathon, Coder Agent Firewall,
AEGIS, TokenWall) sit on a single vantage point — usually the network or the tool
call — and therefore cannot see attacks that cross the workspace/host boundary.
Docker's own documentation names several such gaps in its trust model; AgentWall
targets exactly those.

### Design principles

1. **Deterministic-first.** Cheap, exact detectors handle the fast path; the local
   SLM only sees ambiguous events (<2% of traffic). This is survival, not
   optimization — base rates make naive semantic detection unusable.
2. **Enforcement lives outside the sandbox trust boundary.** The daemon runs on the
   host. A compromised agent must not be able to tamper with its own watcher.
3. **Honesty over theater.** The tool claims only what the attack corpus proves, and
   only gates where the runtime adapter genuinely can. Where we observe rather than
   block, we say so.
4. **Fail-safe, not fail-closed** (in v1). A crashed sensor or SLM timeout degrades
   to lower tiers and logs a gap; it never silently kills the user's agent.
5. **YAGNI ruthlessly.** The source conversations sprawled into a multi-year
   platform. v1 is a focused wedge; everything else is explicitly deferred.

---

## 2. Background & source synthesis

This spec synthesizes seven exploratory conversations. Their converged idea: a tiered
detection cascade (deterministic → local SLM → policy engine), taint/provenance
tracking, DLP on egress, prompt-injection detection on inbound content, assembled from
existing components rather than reinvented.

**Deviations made deliberately** (issues found in the source material):

- **Sidecar-inside-sandbox is wrong.** Conversation 1's first diagram placed the
  security sidecar inside the microVM, sharing the trust domain with a potentially
  compromised agent. Enforcement is host-side here.
- **TLS is the make-or-break question, not a footnote.** Docker's host-side proxy
  injects credentials into outbound HTTPS, so Docker terminates TLS and exposes no
  documented inspection hook. If we cannot see request plaintext, egress payload DLP
  collapses to domain-level control Docker already does. This is gated behind a
  Week-1 spike (§7).
- **Session-wide taint is a fiction.** A real coding agent reads untrusted content
  constantly; session taint saturates to 100% within minutes. We use source-scoped,
  hash-linked taint and alert on *chains*, not on the taint bit itself (§5).
- **Latency targets were fantasy.** "<100ms SLM" ignores prefill on multi-MB
  payloads. We chunk/sample and set honest, CI-enforced targets (§6).
- **Scope explosion.** Secrets broker, agent-to-agent zero trust, risk scoring, EDR
  containment, eBPF collectors — all deferred. eBPF/Tetragon/Falco are additionally
  moot on the macOS host and un-instrumentable inside Docker's VM.
- **No OPA / no OpenTelemetry in v1.** Both are interface-backed so they can be added
  later, but neither earns its complexity at v1 scale.

---

## 3. Scope

### In scope for v1

- Host-side daemon: event bus, SQLite store, health.
- Four sensors: Workspace, Egress, MCP (observation), Lifecycle.
- Detection cascade: Tier 0 (rules), Tier 1 (Gitleaks + Presidio), Tier 2
  (off-the-shelf SLM behind an interface).
- Provenance graph: source-scoped taint + chain correlation.
- YAML policy engine.
- Docker Sandboxes runtime adapter (flagship).
- Attack corpus (scenarios 1–9) as CI-enforced test suite.
- Benchmark harness.
- CLI: `run`, `status`, `replay`, `policy`.

### Explicitly deferred (not v1)

Secrets broker · agent-to-agent trust · dynamic risk scoring · EDR-style
auto-containment · eBPF/Tetragon/Falco · OPA policy backend · OpenTelemetry export ·
Rust data plane (only if benchmarks prove need) · in-path MCP shim (v1.x) ·
clawk/plain-Docker adapters (v1.x) · custom-tuned SLM.

---

## 4. Architecture

```
HOST (macOS / Linux)
┌────────────────────────────────────────────────────────────┐
│  agentwall daemon  (Python 3.12+, asyncio, long-running)   │
│                                                            │
│   Sensors ──► Event Bus ──► Detection Cascade ──► Policy   │
│      │        (SQLite WAL,   T0 rules    (µs)      engine  │
│      │         versioned     T1 scanners (ms)        │     │
│      │         JSON events)  T2 SLM (budgeted)       ▼     │
│      │             │                            Enforcement│
│      │             ▼                            + Alerts   │
│      │        Provenance graph ◄────────────────+ Replay   │
│      │        (chains, taint)                              │
└──────┼─────────────────────────────────────────────────────┘
       │ observes / controls (RuntimeAdapter interface)
       ▼
 Docker Sandboxes (flagship) │ plain Docker │ clawk/Clawker (later)
       └── sandboxed agent: Claude Code / Codex / custom
```

The daemon is one long-running process. Models stay loaded in memory (never
load-per-event). SQLite in WAL mode is the event store and durability boundary.
Events are versioned Pydantic-schema JSON — the language boundary exists from day one
so a future Rust sensor can produce events without changing consumers.

### 4.1 Sensors (`RuntimeSensor` interface)

1. **WorkspaceSensor** — FSEvents/watchdog over the mounted workspace and the shared
   skills store. The host-guardian differentiator. Watches:
   - *implicit-execution files*: git hooks, `package.json` scripts, `Makefile`, CI
     configs, `.claude/` and agent project config, IDE task configs — the files
     Docker's docs name as their trust gap (edited live on the host via passthrough,
     invisible to network firewalls);
   - the cross-sandbox shared **skills store** (writable across sandboxes);
   - sensitive-path access (`~/.ssh`, `~/.aws`, `.env`, etc.).
2. **EgressSensor** — Docker Sandboxes: upstream-proxy chaining. Metadata always
   (domain, method, size, timing); payloads if the TLS spike passes. Plain Docker /
   clawk: our own mitmproxy with injected CA → full payload DLP. **Candidate cheaper
   feed:** Clawker already emits per-decision egress events over eBPF (allowed /
   denied / bypassed). Where AgentWall rides on Clawker, subscribing to that stream is
   a ready-made EgressSensor source that sidesteps the MITM-CA setup — evaluate it
   before building our own proxy on that path. (It is network-decision telemetry, not
   payload inspection, so it complements rather than replaces payload DLP.)
3. **MCPSensor** (observation in v1) — watches MCP gateway registration/config, flags
   host-side stdio servers (they run with *host* permissions — a documented gap),
   feeds registrations into the provenance graph. Does **not** overlap Docker's
   gateway, which *authorizes* servers but never inspects arguments/outputs, taints
   output, or correlates. In-path inspection is the v1.x MCP shim.
4. **LifecycleSensor** — sandbox start/stop, mount config, and **policy drift**:
   snapshots `sbx policy ls`, alerts when allowlists silently widen.

### 4.2 Detection cascade

- **Tier 0** (µs, synchronous): path rules, allowlist/denylist, entropy, size, file
  type.
- **Tier 1** (ms, synchronous): Gitleaks (secrets), Presidio (PII). Reused, not
  rewritten.
- **Tier 2** (budgeted, async, behind `SecurityClassifier` protocol): two model
  classes —
  - **encoder classifiers** (DeBERTa-scale, ~200MB, tens of ms) for
    prompt-injection detection;
  - a **generative SLM via Ollama** (MLX optional on Apple Silicon) only for
    ambiguous cases needing a structured verdict.

  Hard invocation budget. Large payloads use head+tail+sampled-window chunking, never
  full-payload prefill. Classifiers **never decide policy** — they emit
  `{classification, confidence, evidence}`; the policy engine decides.

### 4.3 Policy engine (`PolicyEngine` interface)

YAML rules over `(event_class, data_class, destination_class, taint_chain,
runtime_capabilities)` → `ALLOW / WARN / BLOCK / QUARANTINE / REQUIRE_APPROVAL`.
`BLOCK` is only legal where the runtime adapter declares that capability; the
capability table keeps policy honest per runtime. `QUARANTINE` = pause/kill the
sandbox (available on every runtime). OPA is a possible future backend, not v1.

### 4.4 Runtime adapters (`RuntimeAdapter` + capability table)

Each adapter declares what it can observe and what it can enforce. Docker Sandboxes
is the flagship; plain Docker and clawk/Clawker come in v1.x. The capability table is
what prevents the policy engine from promising enforcement a runtime can't deliver.

---

## 5. Data flow & provenance

**Event flow:** sensor → normalized event → Tier 0 (inline) → verdict or escalate →
Tier 1 (inline) → verdict or escalate → Tier 2 (async, budgeted) → policy → action +
provenance write.

Tier 0/1 run synchronously in the event path. **Tier 2 never blocks the event
stream.** On observed paths (the common v1 case) it can only upgrade a verdict after
the fact (WARN→BLOCK/QUARANTINE) — pretending to be inline where we merely observe
would be theater. On the one path where the adapter genuinely owns the wire and
declares an inline-gate capability (plain-Docker MITM egress), the event *can* be held
pending a Tier-1 verdict; even there, Tier 2 stays asynchronous and advisory so its
prefill latency never sits in the request path. Which behavior applies is read from
the runtime adapter's capability table, never assumed.

**Normalized event schema (versioned Pydantic):**

```json
{
  "event_type": "network_upload",
  "session_id": "...",
  "agent_id": "best-effort",
  "source": "egress|workspace|mcp|lifecycle",
  "content_hash": "...",
  "trust": "trusted|tainted",
  "payload_ref": "sqlite-blob-id|null",
  "ts": "..."
}
```

**Provenance / taint — pragmatic model.** Taint attaches to *sources* (fetch from an
unfamiliar domain, a file written after untrusted ingestion, MCP output), scoped
per-file / per-domain with content-hash linkage — **not** session-wide. "Unfamiliar"
/ "first-seen" is defined against a per-project rolling domain-reputation store: a
domain is familiar if it is on the policy allowlist or has been seen in ≥ N prior
sessions of this project; everything else is first-seen. The threshold and store
location are policy-configurable. Alerts fire
on **chains**:

```
untrusted-source → sensitive-access → egress   (within a time window,
                                                 correlated by hash + causality)
```

Example chain: "content from unfamiliar-domain README → `.env` read → 4 MB POST to a
first-seen domain." Chains are the signal single-vantage competitors cannot produce.

---

## 6. Non-functional requirements (CI-enforced against the corpus)

- **False-positive budget:** < 1 WARN-or-worse per benign 30-minute agent session on
  the benign workload suite (corpus row 9).
- **Tier-2 invocation rate:** < 2% of events.
- **Event-path overhead:** Tier 0/1 p95 < 10 ms; zero perceptible agent latency on
  observed (non-gated) paths.
- **Explainability:** every BLOCK/QUARANTINE must produce a human-readable chain via
  `agentwall replay`.

The benchmark harness measures event throughput, p50/p95/p99 latency, Tier-2
invocation rate, and RSS. Numbers are **published in the README, not claimed**.

---

## 7. The TLS spike (Week 1, blocking gate)

A throwaway experiment answering one question: *on Docker Sandboxes, chained through
our upstream proxy, do we see request plaintext or only CONNECT + SNI?* Written up in
`docs/spikes/tls-egress.md`.

- **Plaintext visible** → inline egress payload DLP on Docker Sandboxes in v1.
- **Opaque** → egress DLP ships first on plain-Docker/clawk adapters (where we own
  the network); Docker Sandboxes v1 gets domain + metadata egress plus full
  host-guardian coverage; and we file a proxy-inspection-hook request upstream with
  Docker (a legitimate play to become the semantic layer they don't want to build).

Either outcome ships v1 value; the spike only decides which value lands where.

---

## 8. Attack corpus (first-class deliverable)

Each scenario is a reproducible harness: a rigged workspace/repo + scripted or real
agent run + expected detection outcome, tagged by which vantage point can see it.
The corpus is the test suite, the proof of differentiation, and the marketing.

| # | Scenario | Network-only tools see it? |
|---|----------|----------------------------|
| 1 | Malicious README → agent reads `.env` → POST to new domain (classic chain) | Partially (final hop only) |
| 2 | Injection → agent edits `.git/hooks/post-commit` → payload runs **on host** later | ❌ No |
| 3 | Injection → `package.json` postinstall script added → runs on host `npm install` | ❌ No |
| 4 | Compromised sandbox writes shared skills store → second sandbox's agent executes it | ❌ No |
| 5 | Malicious MCP server registration (host stdio, host perms) | ❌ No |
| 6 | Secret exfil via *allowed* domain (e.g. gist on github.com) — allowlists useless | ❌ Domain-level: no |
| 7 | Slow/low exfil: secrets chunked across many small requests | ❌ Mostly |
| 8 | Sandbox policy drift: agent-induced allowlist widening | ❌ No |
| 9 | Benign control suite: real coding sessions → **must stay silent** (FP budget) | n/a |

Rows 2–5 and 8 are what Pipelock/AEGIS/Coder (and the substrate egress firewalls)
structurally cannot see. Row 9 is the discipline that keeps detection honest.

---

## 9. Testing strategy

- **Unit** (pytest): each sensor, each cascade tier, policy evaluation, provenance
  chain-matching. Deterministic, fast.
- **Corpus/integration:** every scenario asserts expected verdict + reconstructed
  chain; row 9 asserts silence. Runs in CI. FP-rate or detection regressions fail the
  build.
- **Benchmark harness** (from day one): throughput, latency percentiles, Tier-2
  invocation rate, RSS.
- **Golden replays:** BLOCK/QUARANTINE scenarios snapshot their `agentwall replay`
  output; changes are reviewed.

---

## 10. Error handling & failure modes

- **Fail-safe, not fail-closed** (v1): crashed sensor or SLM timeout degrades to
  lower tiers and logs a gap; never silently kills the agent. (Fail-closed is a later
  enterprise opt-in.) Rationale: a security tool that bricks the dev loop gets
  uninstalled.
- SLM/Ollama unavailable → cascade runs Tier 0/1 only, emits a `degraded` health
  event.
- Malformed events → dead-letter table, never crash the bus.
- SQLite is the durability boundary; on restart the daemon replays unprocessed
  events.

---

## 11. Repository structure

```
agentwall/
├── daemon/         orchestration, event bus, health
├── sensors/        workspace, egress, mcp, lifecycle (RuntimeSensor)
├── adapters/       docker_sandbox, docker_plain, clawk (RuntimeAdapter + capabilities)
├── cascade/        tier0_rules, tier1_scanners, tier2_slm (SecurityClassifier)
├── policy/         yaml engine (PolicyEngine)
├── provenance/     taint + chain correlation
├── mcp_shim/       host-side MCP wrapper (v1.x)
├── cli/            agentwall run|status|replay|policy (Typer)
├── storage/        sqlite, schemas (Pydantic, versioned)
└── corpus/         attack scenarios + benign suite + runner
```

**Stack:** Python 3.12+, uv, asyncio, Pydantic, Typer, SQLite, pytest. Local models
via Ollama (MLX optional on Apple Silicon). Gitleaks + Presidio as Tier-1 components.

---

## 12. Roadmap

Phases, ordered by dependency — not time-boxed. Each phase ends on a demonstrable
state proven against the corpus.

- **v0 (foundation):** TLS spike; daemon + event bus + SQLite; WorkspaceSensor +
  Tier 0/1; corpus rows 1–3 + 9 green; benchmark harness.
- **v1 (ship):** Docker Sandbox adapter; Tier 2 (Llama-Guard-class encoder + Ollama
  SLM); provenance chains; policy engine; egress per spike outcome; corpus rows 1–9;
  `replay`.
- **v1.x:** in-path MCP shim; clawk/plain-Docker adapters; policy-drift enforcement.
- **Later (deferred):** secrets broker, agent-to-agent trust, risk scoring, EDR
  auto-containment, eBPF/Tetragon, OPA/OTel backends, Rust data plane, custom SLM.

---

## 13. Substrates vs. competitors

A critical distinction the source conversations blurred: the sandbox tools are **not
competitors** — they are the **runtimes AgentWall rides on**. They do containment; we
do understanding. Their own docs disclaim everything in AgentWall's charter, which is
the strongest validation the charter is real.

### 13.1 Substrates (runtime adapter targets — we consume, never rebuild)

| Substrate | Provides (isolation layer) | Explicitly does NOT do (per its own docs) | AgentWall relationship |
|-----------|----------------------------|-------------------------------------------|------------------------|
| **Docker Sandboxes** | microVM, host-side proxy w/ credential injection, deny-by-default allowlist, MCP gateway (authorization) | content inspection, DLP, injection detection, provenance, dynamic policy | Flagship adapter; TLS wall gates egress payload visibility (§7) |
| **clawk** | Firecracker/HVF microVM, gvproxy DNS-aware egress allowlist, ssh-agent forwarding | *"content inspection or DLP, prompt injection detection, provenance tracking, policy engines beyond network allow-listing"* — verbatim | v1.x adapter; we own the network here → MITM payload DLP viable |
| **Clawker** | Docker-container isolation, deny-by-default egress firewall, **eBPF per-decision egress events**, optional OTel/Prometheus | *"content inspection or DLP, taint tracking, policy engine (static only), prompt-injection neutralization"* — verbatim | v1.x adapter; its eBPF egress stream is a **candidate EgressSensor feed** (§4.1), making it more integration target than rival |

The takeaway: every substrate author has independently decided *not* to build the
semantic layer. AgentWall is that layer, portable across all three.

### 13.2 Competitors (detection tools — same job, different vantage)

| System | Vantage | What AgentWall adds |
|--------|---------|---------------------|
| Pipelock | Network (HTTP/WS/MCP/A2A) | Host-boundary + workspace attacks it can't see; correlation |
| Coder Agent Firewall | Process/network authorization | Semantic provenance; implicit-execution-file coverage |
| AEGIS | Pre-execution tool-call classification | "What happened before this call" — taint chains |
| TokenWall | Token-flow provenance (research) | Production system on real runtimes, deterministic-first latency |
| Strathon | Tool-call firewall + MCP gateway | Whole-runtime plane vs per-call firewall |

**One-line positioning:** *The sandbox handles containment ("the agent can't
escape"). AgentWall handles understanding ("should it be doing this?") — including the
host-boundary attacks the sandbox model itself leaves open — and rides on top of
whichever sandbox you already use.*
