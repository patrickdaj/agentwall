# Sandbox dev workflow

Repeatable Docker Sandboxes (`sbx`) workflow for developing with a Claude agent
sandboxed on this repo. All host state (egress allow rules, proxy settings,
background mitmweb) is owned and undone by the script (`scripts/sandbox.sh`).

| Command | Does |
|---|---|
| `make sandbox` | Launch/attach the Claude sandbox; ensures the dev egress allowlist and the Anthropic no-proxy bypass (login works on first run) |
| `make sandbox-inspect` | Chain all sandbox egress (except Anthropic auth/API) through mitmproxy on :8888 with the CA trusted in-sandbox; web UI URL in `~/.cache/agentwall/mitmweb.log` |
| `make sandbox-direct` | Back to direct egress (default state) |
| `make sandbox-clean` | Remove sandbox, script-owned policy rules and settings overrides, stop mitmweb |

> **Note:** switching between inspect and direct runs `sbx daemon restart` —
> `proxy.sandbox` changes only take effect on a daemon restart, not a sandbox
> restart (verified). The daemon restart briefly stops any other running
> sandboxes on your machine and adds a few seconds to the toggle.

`scripts/sandbox.sh verify` proves the current mode: it checks the TLS issuer
seen inside the sandbox (`CN=mitmproxy` vs the real CA) and that an HTTPS POST
egresses successfully. `ATTACH=0` skips the interactive attach for scripting.

## Background

Findings behind this design (CONNECT chaining, CA-trust requirement, no_proxy
bypass for OAuth) are documented in
[`docs/superpowers/specs/2026-08-13-sandbox-dev-workflow-design.md`](superpowers/specs/2026-08-13-sandbox-dev-workflow-design.md);
the TLS egress spike verdict is in [`docs/spikes/tls-egress.md`](spikes/tls-egress.md).
