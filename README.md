# AgentWall

**The sandbox handles containment — "the agent can't escape." AgentWall handles
understanding — "should it be doing this?"** It rides on top of whichever sandbox
you already use and catches the host-boundary attacks the sandbox model itself
leaves open.

AgentWall is a local-first, host-side security daemon for AI coding agents. It
watches agent activity through sensors, classifies it with a deterministic-first
detection cascade, correlates events into provenance chains, and enforces a
capability-gated YAML policy. It is **not** a sandbox and does not compete with
one.

> **Status: v0 foundation.** The load-bearing skeleton is built and benchmarked;
> several sensors and the Tier-2 classifier are scoped for v1. See
> **[docs/status/v0.md](docs/status/v0.md)** for exactly what ships, what's
> deferred, and the honest caveats.

## Why it exists

Existing agent-security tools watch from a single vantage point — the network,
or one tool call — so they never see an attack that crosses the workspace/host
boundary. The canonical case: a poisoned README tells the agent to read `.env`
and POST it to a new domain. A network-only tool sees only the final HTTP
request, stripped of the fact that it carries secrets sourced from an untrusted
file. AgentWall sees the whole chain.

```mermaid
flowchart TB
    subgraph sandbox["Sandbox runtime (containment — Docker Sandboxes / clawk / Clawker)"]
        agent["AI coding agent<br/>(Claude Code / Codex)"]
    end

    subgraph aw["AgentWall daemon (understanding — host-side)"]
        direction TB
        sensors["Sensors<br/>WorkspaceSensor (v0)<br/>Egress · MCP · Lifecycle (v1)"]
        bus["Event bus"]
        store[("SQLite WAL<br/>event store")]
        cascade["Detection cascade<br/>Tier 0 → Tier 1 → Tier 2 seam"]
        prov["Provenance chain<br/>correlator"]
        policy["Capability-gated<br/>YAML policy engine"]
        adapter["Runtime adapter<br/>observe · quarantine"]
    end

    agent -->|"file / egress / lifecycle activity"| sensors
    sensors --> bus
    bus --> store
    bus --> cascade
    cascade --> prov
    prov --> policy
    cascade --> policy
    policy -->|"ALLOW / WARN / BLOCK / QUARANTINE"| adapter
    adapter -.->|"quarantine = sbx stop"| sandbox
```

## How detection works

Events flow through a **deterministic-first cascade** — cheap, exact rules run
first and most events resolve there; the expensive model tier is a seam that
only fires when the cheap tiers abstain. In v0 the Tier-2 seam holds a
`NullClassifier` (always abstain); a small language model drops in for v1
without changing any caller.

```mermaid
flowchart LR
    event["Event"] --> t0{"Tier 0<br/>path · entropy · size rules<br/>(µs)"}
    t0 -->|"resolved"| verdict["Verdict"]
    t0 -->|"abstain"| t1{"Tier 1<br/>Gitleaks · Presidio<br/>(ms)"}
    t1 -->|"resolved"| verdict
    t1 -->|"abstain"| t2{"Tier 2 seam<br/>NullClassifier (v0)<br/>SLM (v1)"}
    t2 --> verdict
    verdict --> policy["Policy engine"]
```

Detection alone isn't the differentiator — **correlation across layers is.** The
provenance correlator links events by source-scoped, hash-linked taint, so an
individually-benign sequence becomes a single high-severity chain:

```mermaid
flowchart LR
    a["Untrusted source<br/>evil.example/README.md<br/><i>tainted</i>"] --> b["Sensitive access<br/>reads /w/.env<br/><i>ALLOW alone</i>"]
    b --> c["Egress<br/>POST to first-seen.xyz<br/><i>WARN alone</i>"]
    c --> d["Correlator links the chain"]
    d --> e["QUARANTINE<br/><b>untrusted → sensitive → egress</b>"]

    style e fill:#c0392b,color:#fff
```

## Not a sandbox — a layer on top of one

Sandbox runtimes do containment; their own docs explicitly disclaim content
inspection, DLP, prompt-injection detection, and provenance. AgentWall is that
missing semantic layer, portable across all of them.

```mermaid
flowchart TB
    subgraph understanding["Understanding layer"]
        aw["<b>AgentWall</b><br/>content inspection · DLP · provenance ·<br/>cross-layer correlation · dynamic policy"]
    end
    subgraph containment["Containment layer (substrates AgentWall rides on)"]
        subs["Docker Sandboxes · clawk · Clawker<br/>microVM · egress allowlist · credential injection"]
    end
    competitors["Single-vantage detectors<br/>Pipelock · AEGIS · TokenWall · Strathon<br/><i>network-only or single-tool-call</i>"]

    aw --> subs
    competitors -.->|"blind to host-boundary attacks"| aw

    style aw fill:#2c3e50,color:#fff
```

## CLI walkthrough

> Illustrative session. Output shapes are real (captured from the v0 daemon);
> the row-1 attack is driven through the corpus/replay path, since v0 has no
> live EgressSensor yet — see the [v0 status caveats](docs/status/v0.md).

Inspect the active policy — capability-gated rules mapping event classes to
actions:

```console
$ agentwall policy --policy src/agentwall/policy/default_policy.yaml
block-secret-egress: BLOCK
quarantine-exfil-chain: QUARANTINE
warn-sensitive-access: WARN
warn-pii-egress: WARN
```

Health-check the daemon against a workspace — note the runtime adapter only
declares capabilities it can actually enforce:

```console
$ agentwall run --check --workspace . --session dev \
    --db /tmp/aw.db --policy src/agentwall/policy/default_policy.yaml
{'degraded': False, 'events': 0, 'tier2_rate': 0.0, 'capabilities': ['observe', 'quarantine']}
```

As events flow, each gets a verdict — and a correlated exfil chain escalates
past the individual verdicts to QUARANTINE:

```console
verdict=ALLOW       chain=-
verdict=WARN        chain=-
verdict=QUARANTINE  chain=untrusted-source: evil.example/README.md -> sensitive-access: /w/.env -> egress: first-seen.xyz
```

Then summarize and reconstruct what happened in a session:

```console
$ agentwall status --db /tmp/aw.db
events: 3
dead_letters: 0

$ agentwall replay --db /tmp/aw.db --session s1
untrusted-source: evil.example/README.md -> sensitive-access: /w/.env -> egress: first-seen.xyz
```

## Quickstart

```bash
uv sync                 # install dependencies
uv run pytest           # run the test suite (54 tests)

# daemon health check against this workspace (exits without a long-running watch)
uv run agentwall run --check \
  --workspace . --session dev \
  --db /tmp/aw.db --policy src/agentwall/policy/default_policy.yaml
```

Want to see the detection engine catch the attack corpus?

```bash
uv run pytest tests/corpus/test_scenarios.py -v   # row-1 exfil chain, git-hook, package.json, benign control
```

## Documentation

| Doc | What's in it |
|---|---|
| [docs/status/v0.md](docs/status/v0.md) | v0 milestone status — what ships, what's deferred to v1, benchmarks, caveats |
| [docs/superpowers/specs/2026-08-13-agentwall-design.md](docs/superpowers/specs/2026-08-13-agentwall-design.md) | Full design rationale and architecture |
| [docs/spikes/tls-egress.md](docs/spikes/tls-egress.md) | TLS egress inspection spike — verdict that routes v1 egress DLP |
| [docs/sandbox-dev-workflow.md](docs/sandbox-dev-workflow.md) | `make sandbox*` dev tooling for working in a real Docker Sandbox |
