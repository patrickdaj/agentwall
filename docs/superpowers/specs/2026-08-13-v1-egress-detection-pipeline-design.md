# v1 sub-project B — Live egress detection pipeline — design

**Date:** 2026-08-13
**Status:** approved (design), pending spec review
**Milestone:** first of the v1 sub-projects (see [v1 decomposition](#v1-decomposition-context)).

## Problem

v0 proves the detection/correlation/policy *brain*, but its flagship scenario —
row 1, the cross-layer exfil chain — is exercised with **synthetically injected
events**. Two v0 gaps cause this:

1. **Tier-1 scanners are inert.** `WorkspaceSensor.make_event` computes a
   `content_hash` but never stores the bytes or sets `payload_ref`, so
   `daemon._on_event` always passes `payload=None` and Gitleaks/Presidio
   early-return `[]`.
2. **No egress observation.** There is no EgressSensor, and file *reads* are not
   observable (filesystem watchers see only writes/creates/deletes, and the
   agent reads inside a Docker Sandbox microVM the host cannot watch).

The TLS egress spike ([docs/spikes/tls-egress.md](../../spikes/tls-egress.md))
resolved **PLAINTEXT-with-CA-injection**: an inspection proxy the sandbox trusts
sees full request bodies. That unlocks a stronger design than observing the read.

## Goal

Make the row-1 exfil chain observable **end-to-end by real sensors**, with no
synthetic events: a poisoned file write taints the session; when a secret leaves
the sandbox, an EgressSensor catches it in the request **body** via Tier-1 DLP;
the correlator links the two into a QUARANTINE.

## Key design decisions (and roads not taken)

- **Catch the secret on egress, not on read.** The "sensitive-access" signal
  becomes "a Tier-1 secret/PII detection fired on an egress body," not "the agent
  read `.env`." Reads inside the microVM have no clean host-side observation
  mechanism; the secret leaving is a stronger, lower-false-positive signal.
  *Not taken:* in-sandbox read hooks (eBPF/auditd/LD_PRELOAD) — complex,
  sandbox-specific, adds an in-guest agent; deferred.
- **Managed `mitmdump` + addon over a unix socket.** The daemon spawns and
  supervises a headless `mitmdump` subprocess running a mitmproxy addon; the
  addon ships each captured request to the daemon over a local unix socket.
  *Not taken:* embedding mitmproxy in-process (couples a proxy bug / slow body to
  the daemon's event loop; harder to keep fail-safe). *Not taken:* metadata-only
  substrate feeds (`sbx policy log`, Clawker eBPF) — no request bodies, so
  Tier-1-on-egress is impossible.
- **Reuse the dev tooling's *setup* mechanisms, but the daemon owns the proxy.**
  CA injection into the sandbox and `proxy.sandbox` chaining + daemon restart are
  the proven bits we reuse (from `scripts/sandbox.sh`). The proxy **listener**,
  however, is the daemon's own `mitmdump`+addon — not the dev workflow's
  `mitmweb`, which carries no addon and would capture nothing. So B reuses the
  CA-inject + chaining steps but replaces the proxy-start step. Productizing
  provisioning into `DockerSandboxAdapter` is a fast-follow, not part of B.
- **No inline blocking, no plugin machinery.** B observes/detects/correlates and
  can quarantine the whole sandbox; blocking an individual request inline is
  sub-project D. EgressSensor is wired into the daemon hardcoded (like
  WorkspaceSensor), ready to become a plugin in sub-project A.

## Architecture

```
 sandbox (egress chained → mitmdump, CA trusted via `make sandbox-inspect`)
        │  HTTPS request (e.g. POST secret to first-seen.xyz)
        ▼
 mitmdump  ── addon (sensors/egress_addon.py) ──► unix socket ──►  EgressSensor
   (subprocess, daemon-supervised)                                (sensors/egress.py)
                                                                      │ blob_put(body)→payload_ref
                                                                      ▼
                                              EventBus ──► Daemon._on_event
                                                              │ payload = get_blob(payload_ref)
                                                              │ cascade → Tier-1 secret detection
                                                              │ correlator.observe(event, detections)
                                                              │ policy.evaluate → QUARANTINE
                                                              ▼
                                                 adapter.quarantine(session) = `sbx stop`
```

## Components (new / changed)

### 1. mitmproxy addon — `src/agentwall/sensors/egress_addon.py` (new)

- Runs inside the `mitmdump` process; **does not import the daemon** — its only
  output is the unix socket.
- On the mitmproxy `request` hook, builds a record:
  `{host, method, path, scheme, ts, size, body}` where `body` is the request
  content truncated to `MAX_BODY` (default 1 MiB, matching the proxy's
  `stream_large_bodies`); over the cap → `body=None, truncated=true, size` kept.
- Skips Anthropic hosts (`*.anthropic.com`, `claude.ai`, `claude.com`) — defense
  in depth even though `no_proxy.sandbox` already bypasses them.
- Writes the record as one length-prefixed JSON frame to
  `${XDG_RUNTIME_DIR:-/tmp}/agentwall/egress.sock`.
- **Fail-safe:** if the socket connect/write fails, drop the record and return —
  never delays or blocks the request. (B does no blocking at all.)

### 2. `EgressSensor` — `src/agentwall/sensors/egress.py` (new)

Implements the existing `RuntimeSensor` protocol (`async run(bus)`, `stop()`).

- `__init__(self, socket_path, blob_put, session_id, mitm_ca_dir, clock=time.time)`.
- `run(bus)`:
  - Spawns `mitmdump -s <egress_addon.py> -p <PROXY_PORT> --set stream_large_bodies=1m`
    as a supervised subprocess (env points the addon at `socket_path`). **The
    daemon owns the proxy listener** — it must be *our* addon-bearing `mitmdump`,
    because a plain proxy (e.g. the dev workflow's `mitmweb`) captures nothing to
    the socket. If `PROXY_PORT` is already bound, that is an error the sensor
    reports (`degraded`, with a message to stop the conflicting proxy), not a
    proxy to reuse. See Testing for how inspection setup coordinates with this.
  - Binds `socket_path` (unlinking a stale socket) and accepts addon frames in a
    loop. Per frame: `payload_ref = blob_put(body)` when `body` present; build
    `SecurityEvent(source="egress", event_type="network_upload",
    payload_ref=..., attrs={destination, method, path, size, truncated})`;
    publish to `bus`.
  - `trust` on the egress event is left `"trusted"`; taint lives in the
    correlator's per-session state, not on the egress event itself.
- Supervises the subprocess: on unexpected exit set `self.degraded = True` and
  attempt one restart; surface `degraded` in daemon health.
- `stop()`: close the socket, terminate the owned subprocess (do **not** kill a
  proxy it did not spawn), unlink the socket path.
- Malformed frames are dead-lettered (`store.dead_letter`) via the bus's existing
  path, never crash the accept loop.

### 3. `blob_put` injection (changed: `daemon.py`, `sensors/workspace.py`)

- `Daemon` passes `blob_put=self._store.put_blob` to both sensors.
- `WorkspaceSensor.__init__` gains `blob_put: Callable[[bytes], str] | None`.

### 4. WorkspaceSensor payload wiring — `src/agentwall/sensors/workspace.py` (changed)

- In `make_event`, when the path is `sensitive` or `implicit_exec` and readable,
  read up to `MAX_BODY` bytes (capped, not full-file), set
  `payload_ref = blob_put(bytes)` and `content_hash` from the same bytes.
  Non-matching paths keep `payload_ref=None` (no need to scan every write).
- Fixes the deferred finding "reads full file bytes on the watchdog thread" by
  capping the read.

### 5. Provenance reframe — `src/agentwall/provenance.py` (changed)

- `ChainCorrelator.observe` gains a second parameter:
  `observe(event, has_secret: bool = False)` where `has_secret` is true when the
  cascade produced a Tier-1 `secret:`/`pii:` detection for this event.
- New completion rule: when `event.source == "egress"`, the session is tainted,
  `has_secret` is true, and within the window → complete the chain
  `untrusted-source → secret-egress` **without** requiring the prior
  `sensitive-access` node. The `secret-egress` step label is
  `f"secret-egress: {destination}"`.
- The existing 3-node path (`untrusted-source → sensitive-access → egress`) is
  retained for when a real read signal exists later, but is no longer required.
- `Daemon._on_event` computes `has_secret` from `result.detections` and passes it
  to `observe`. This tightens the deferred FP finding (chain keys on an actual
  secret, not any tainted read/write).

### 6. Async offload — `src/agentwall/daemon.py` (changed)

- Wrap the now-live blocking calls in `asyncio.to_thread`: the Gitleaks
  subprocess inside the cascade and `adapter.quarantine`. (Presidio is in-process
  Python; measure and offload only if it shows up in the benchmark.)

## Data flow (row-1, live)

1. Agent in the sandbox (egress chained through mitmdump, CA trusted) is told by a
   poisoned README to exfiltrate `.env`.
2. WorkspaceSensor observes the README write → `untrusted-source` event (tainted).
3. Agent issues `POST https://first-seen.xyz` with the secret. mitmdump addon
   captures the decrypted body → unix socket → EgressSensor → `network_upload`
   event with `payload_ref` = body bytes.
4. `Daemon._on_event`: resolves payload → Gitleaks/Presidio detect the secret →
   `has_secret=true`.
5. `correlator.observe(event, has_secret=True)` → completes
   `untrusted-source → secret-egress`.
6. Policy: in-chain + secret detection → QUARANTINE → `adapter.quarantine` →
   `sbx stop`.

## Error handling & fail-safe

- **Never blocks egress.** B does no inline blocking, so any failure (proxy dead,
  socket down, daemon slow) degrades to "no inspection on that request," never
  "request stalled/blocked." This matches the design spec's fail-safe posture.
- **Body cap** (`MAX_BODY`) bounds blob growth; oversize bodies recorded
  metadata-only with `truncated=true`.
- **Proxy supervision:** unexpected `mitmdump` exit → `degraded=true` + one
  restart attempt; persistent failure stays degraded and is reported in health.
- **Malformed socket frames** → dead-lettered, accept loop continues.
- **Blocking subprocesses** offloaded via `asyncio.to_thread` so the event loop
  is not stalled by a 2 s Gitleaks run or a 10 s quarantine.

## Testing

**Unit (no network, deterministic):**
- `egress_addon` builds the correct record from a synthetic mitmproxy flow object
  (host/method/body/truncation), and skips Anthropic hosts.
- `EgressSensor` ingest: a hand-written frame on the socket produces the expected
  `SecurityEvent` + a stored blob; a malformed frame is dead-lettered and the loop
  survives; oversize body → `truncated` metadata event, no blob.
- `WorkspaceSensor` sets `payload_ref` for sensitive/implicit-exec writes within
  the cap and leaves it `None` otherwise.
- `ChainCorrelator.observe(event, has_secret=True)` builds
  `untrusted-source → secret-egress` from synthetic events; `has_secret=False`
  egress does not complete a chain.
- Tier-1 fires on an egress payload containing a planted secret (reuses the
  existing gitleaks/presidio test fixtures).

**Integration (opt-in, live sandbox — marked/skippable like the spike):**
- **Inspection setup vs. the daemon's proxy — the coordination that matters.**
  The daemon's `EgressSensor` is the proxy listener (mitmdump+addon on
  `PROXY_PORT`). `make sandbox-inspect` also tries to start its own `mitmweb` on
  that port, which would conflict *and* capture nothing. So the integration test
  must reuse only the **CA-injection** and **`proxy.sandbox` chaining + daemon
  restart** steps from the dev workflow, not its proxy-start step. Concretely:
  start the daemon (EgressSensor spawns mitmdump+addon on `PROXY_PORT`), then run
  the CA-inject + proxy-chain steps pointing sandbox egress at `PROXY_PORT`. This
  implies a small, test-only setup path that does inspection setup *without*
  starting a proxy — either a `scripts/sandbox.sh` "setup-only" mode (a fast
  follow if reused often) or the test invoking the CA-inject + `sbx settings set
  proxy.sandbox` + daemon-restart steps directly. **The plan must pick one and
  make it explicit; do not assume `make sandbox-inspect` can be used as-is.**
- Then drive an in-sandbox `curl -X POST` carrying a canary secret; assert the
  daemon (a) captured the egress body, (b) Tier-1 flagged it, (c) built the
  `untrusted-source → secret-egress` chain, (d) reached QUARANTINE. This is the
  "row-1 live" proof.

**Benchmark:** extend `bench/run_bench.py` (or a sibling) to measure the egress
event path p95 — body scanning is Tier-1 (ms); confirm it stays within the design
spec's Tier 0/1 p95 < 10 ms target for non-scanned events and report the scanned
path separately.

## Scope boundaries (explicit non-goals for B)

- No inline request blocking (sub-project D).
- No CA/proxy provisioning automation in `DockerSandboxAdapter` (reuse
  `make sandbox-inspect`; fast-follow).
- No response-body inspection (request bodies are the exfil target; add later).
- No plugin registry / entry-point discovery (sub-project A). EgressSensor is
  constructed by the daemon exactly like WorkspaceSensor.
- No MCP/Lifecycle sensors, no corpus rows 4–8 (sub-project E).

## v1 decomposition context

v1 is decomposed into sub-projects, each with its own spec → plan → implement
cycle. Agreed order: **B (this) → A (plugin architecture) → C (Tier-2 SLM) →
D (inline egress enforcement) → E (MCP/Lifecycle sensors + corpus 4–8 + golden
snapshots)**. B is first because it turns the flagship row-1 chain from
synthetic into live, using the existing Protocol seams — the highest-value
vertical slice. See [docs/status/v0.md](../../status/v0.md) and the design spec
§12 roadmap for the full backlog.
