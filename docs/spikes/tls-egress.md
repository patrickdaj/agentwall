# TLS egress spike — Docker Sandboxes chained through an inspection proxy

**Date:** 2026-08-13
**Question:** On a Docker Sandbox, chained through our upstream proxy, do we
see request **plaintext** (headers + body) or only a `CONNECT host:443` tunnel
with SNI?
**Method:** `scripts/sandbox.sh inspect` — sets `proxy.sandbox` to a host-side
mitmproxy (`:8888`), applies it with `sbx daemon restart`, injects the
mitmproxy CA into the sandbox trust store, then drives HTTPS from inside the
sandbox. Reproducible any time with `make sandbox-inspect`.

## Setup

- Docker Sandboxes (`sbx`) v0.38, flagship runtime, sandbox `claude-agentwall`.
- Upstream proxy: `mitmweb` (mitmproxy 12.2.3) on `127.0.0.1:8888`, decrypted-
  flow web UI on `127.0.0.1:8081`.
- The sbx host proxy chains sandbox egress to the upstream via `proxy.sandbox`.
  Anthropic domains (`*.anthropic.com`, `claude.ai`, `claude.com`) are exempt
  from the chain via `no_proxy.sandbox`, so OAuth tokens never transit
  mitmproxy — verified: login works in inspect mode.
- The mitmproxy CA is trusted **inside** the sandbox by injecting
  `~/.mitmproxy/mitmproxy-ca-cert.pem` into the system trust store (this is a
  legitimate deployment step because AgentWall provisions the sandbox
  image/kit).

## Observations

### With CA trust in the sandbox → **(a) full request plaintext**

The sandbox's HTTPS connection is terminated by mitmproxy, which presents a
cert it minted for the target host. mitmproxy therefore sees the full
decrypted request — method, path, headers, and body.

Redacted evidence excerpt (in-sandbox `curl -v` to `https://httpbin.org/`, and
a secret-bearing POST echoed back by the server):

```
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
*   subject: CN=httpbin.org
*   issuer:  CN=mitmproxy; O=mitmproxy        # <-- cert minted by the proxy

# POST https://httpbin.org/post from inside the sandbox, server-side echo:
  form data seen server-side:   {"note": "exfil-simulation", "secret": "SPIKE_CANARY_7f3a"}
  marker header seen server-side: agentwall-tls-spike
  verify: mode=inspect  issuer=CN=mitmproxy  http=200   → verify OK (inspect mode)
```

The `issuer: CN=mitmproxy` on a connection the sandbox nonetheless completed
with `http=200` is the proof: TLS was terminated at the proxy, so the full
plaintext body (including the `SPIKE_CANARY_7f3a` secret) was visible to it.
The decrypted flow is also viewable in the mitmweb UI at
`http://127.0.0.1:8081`.

### Without CA trust in the sandbox → **(b) CONNECT + SNI only**

Observed earlier in this session: a client that does **not** trust the
mitmproxy CA (e.g. Claude Code's Node runtime during `/login` before any CA
injection) rejects the minted cert and the TLS handshake fails ("socket hang
up" / `CONNECT tunnel` error). In that mode mitmproxy sees only the
`CONNECT host:443` tunnel establishment and the SNI hostname — no headers, no
body. This is the default state of a Docker Sandbox we do not provision.

### Also observed (bonus, for the EgressSensor design)

- The sbx host proxy distinguishes `forward` vs `forward-bypass` per host (it
  MITMs some hosts itself for credential injection), and `sbx policy log
  <sandbox>` emits a per-decision egress record (host, rule, count,
  timestamp) — a candidate metadata feed for the EgressSensor alongside the
  Clawker eBPF stream noted in the design.
- `proxy.sandbox` changes take effect only on `sbx daemon restart`, not a
  sandbox restart (this drove a correction in the dev-workflow tooling).

## Verdict: **PLAINTEXT (conditional on CA provisioning)**

Full egress payload visibility on Docker Sandboxes **is** achievable — but only
because AgentWall controls sandbox provisioning and can inject a trusted CA.
With that provisioning, mitmproxy (or our own in-path inspector) sees complete
request plaintext. Without CA injection, the same chain yields only
`CONNECT + SNI` (OPAQUE).

**Routing implication (per design §7):** because the plaintext path depends on
a provisioning step AgentWall owns, v1 can do **inline egress payload DLP on
Docker Sandboxes** — contingent on the adapter injecting the inspection CA at
sandbox-create time. Where AgentWall does **not** own provisioning, the runtime
degrades to domain + metadata egress (CONNECT + SNI + `sbx policy log`) plus
host-guardian coverage. This is a stronger result than a flat OPAQUE finding:
it does not require filing a proxy-inspection-hook request upstream with
Docker, because we can establish trust ourselves through the image/kit.

**Caveat:** CA injection into the agent's sandbox is a real trust decision —
it lets our inspector read all non-bypassed TLS. The Anthropic no-proxy bypass
must stay in place so agent-provider credentials are never exposed to the
inspection layer.

## Reproduce

```bash
make sandbox-inspect     # engage the chain, inject CA, self-verify (issuer=mitmproxy)
scripts/sandbox.sh verify
# view decrypted flows at http://127.0.0.1:8081
make sandbox-direct      # restore direct egress
make sandbox-clean       # tear down (removes rules/settings/sandbox, stops mitmweb)
```
