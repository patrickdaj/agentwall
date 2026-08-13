# Sandbox dev workflow — design

**Date:** 2026-08-13
**Status:** approved
**Scope:** dev tooling only. No changes to v0 plan Python tasks. The sbx-kit
variant is a documented v1 direction, not built here.

## Problem

Getting a working Claude sandbox on this repo currently takes a pile of manual,
undocumented host-state tweaks: `sbx policy allow` rules for Anthropic
login/API endpoints (the claude kit's 3 allow rules don't cover them, so
`/login` fails with proxy 403s), `sbx settings` proxy overrides for mitmproxy
chaining, CA injection by hand, and sandbox restarts in the right order.
Chained mitmproxy inspection additionally breaks Claude login ("socket hang
up") unless Anthropic traffic bypasses the upstream proxy. None of this is
repeatable or reviewable.

## Goal

One command each for: a working dev sandbox (auth working, sane egress
allowlist), the same sandbox with mitmproxy egress inspection, back to direct
egress, and full teardown. Idempotent; safe to re-run; undoes only what it
created.

## Design

### Components

- `scripts/sandbox.sh` — bash, all logic, subcommands below.
- `Makefile` — thin wrappers: `sandbox`, `sandbox-inspect`, `sandbox-direct`,
  `sandbox-clean`.

Constants at the top of the script:

- `SANDBOX_NAME=claude-agentwall`, `PROXY_PORT=8888`.
- `ALLOW_DOMAINS` — the dev-essentials egress allowlist, owned by the script:
  `api.anthropic.com`, `platform.claude.com`, `github.com`,
  `raw.githubusercontent.com`, `pypi.org`, `files.pythonhosted.org`,
  `registry.npmjs.org`, `httpbin.org`.
- `NO_PROXY_SANDBOX="claude.com,*.claude.com,claude.ai,*.claude.ai,*.anthropic.com"`
  — Anthropic traffic always bypasses the upstream proxy, so login/API never
  depend on mitmproxy CA trust and OAuth tokens never transit mitmproxy.

### Subcommands

- **`up`** — ensure each `ALLOW_DOMAINS` entry is allowed (check-then-add via
  `sbx policy check network`), ensure `no_proxy.sandbox` equals
  `NO_PROXY_SANDBOX`, then `sbx run claude --name $SANDBOX_NAME .` (attaches
  when the sandbox already exists).
- **`inspect`** — ensure mitmproxy is listening on `$PROXY_PORT` (else launch
  `uvx mitmweb -p $PROXY_PORT` in the background — web UI, since a script
  can't drive the TUI), set `proxy.sandbox=http://localhost:$PROXY_PORT`,
  restart the sandbox, inject the mitmproxy CA
  (`sbx cp ~/.mitmproxy/mitmproxy-ca-cert.pem` → system trust store via
  `update-ca-certificates`, plus `/etc/profile.d/mitm-ca.sh` exporting
  `NODE_EXTRA_CA_CERTS` and `REQUESTS_CA_BUNDLE`), run `verify`, attach.
- **`direct`** — unset `proxy.sandbox`, restart sandbox, attach. Default
  state.
- **`verify`** — repeatable spike check; detects the current mode by reading
  the `proxy.sandbox` setting. Inspect mode: in-sandbox curl asserts
  `httpbin.org` cert issuer is `CN=mitmproxy` and an HTTPS POST returns 200.
  Direct mode: asserts the issuer is the real CA. Exit non-zero on mismatch.
- **`clean`** — remove the sandbox, remove exactly the `ALLOW_DOMAINS` rules
  (never rules the script doesn't own), unset `proxy.sandbox` and
  `no_proxy.sandbox` overrides.

### Behavior rules

- Every step is check-then-act (`sbx policy check`, `sbx settings ls --json`,
  `lsof` on the proxy port); re-running any subcommand is safe and fast.
- Fail fast with a plain message naming the failed step and likely fix; on
  egress-looking failures print the `sbx policy log $SANDBOX_NAME` hint. No
  retries.

### Known limitations (accepted)

- Policy allow rules are global host state; `clean` is the owner-scoped undo.
- `NODE_EXTRA_CA_CERTS` via profile.d only reaches login-shell descendants;
  non-shell-spawned Node processes may miss it. Noted in the script.
- Kits (declarative per-sandbox policy + files + env) are the better long-term
  mechanism and the intended v1 `DockerSandboxAdapter` direction; they are
  experimental in sbx v0.38 and still need the host-side half of this script,
  so deferred.

## Testing

- `shellcheck scripts/sandbox.sh` clean.
- `verify` subcommand is the functional test, run automatically at the end of
  `inspect`; manual pass: `up` → `inspect` (flow visible in mitmweb, verify
  green) → `direct` (verify green) → `clean` (policy rules and settings
  overrides gone; `sbx policy ls` / `sbx settings ls` confirm).

## Spike linkage

Findings this workflow reproduces, for `docs/spikes/tls-egress.md`: sbx
upstream chaining forwards CONNECT to the upstream proxy (mitmproxy always
sees domain+SNI); full request plaintext is visible once the sandbox trusts
the mitmproxy CA (verified end-to-end 2026-08-13 with an in-sandbox HTTPS
POST decrypted by mitmproxy); without CA trust, clients fail TLS ("socket
hang up") and mitmproxy logs only failed handshakes.
