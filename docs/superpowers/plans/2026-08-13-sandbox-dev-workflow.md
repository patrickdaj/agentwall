# Sandbox Dev Workflow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One-command Docker Sandboxes dev workflow for this repo: launch a working Claude sandbox (`up`), toggle mitmproxy egress inspection on (`inspect`) and off (`direct`), prove the current mode (`verify`), and tear everything down (`clean`).

**Architecture:** A single bash script `scripts/sandbox.sh` holding all logic as `cmd_*` functions behind a case dispatcher, plus a thin `Makefile` with four targets. All host state the script touches (sbx policy rules, sbx settings overrides, a background mitmweb) is check-then-act idempotent and owned by constants at the top of the script so `clean` can undo exactly what the script created.

**Tech Stack:** bash (macOS/BSD userland), the `sbx` CLI (Docker Sandboxes v0.38+), `uvx mitmweb` (ephemeral, not a project dependency), `python3` for JSON parsing, `shellcheck` for linting.

**Spec:** `docs/superpowers/specs/2026-08-13-sandbox-dev-workflow-design.md`

## Global Constraints

- Script is bash with `set -euo pipefail`; must pass `shellcheck scripts/sandbox.sh` with zero findings at every commit.
- Host is macOS (BSD `awk`/`lsof`); no GNU-only flags.
- No new entries in `pyproject.toml`; mitmweb runs via `uvx`, shellcheck via Homebrew (already installed).
- `SANDBOX_NAME=claude-agentwall`, `PROXY_PORT=8888`.
- `NO_PROXY_SANDBOX="claude.com,*.claude.com,claude.ai,*.claude.ai,*.anthropic.com"` — verbatim; Anthropic traffic must never chain through mitmproxy.
- `ALLOW_DOMAINS` — exactly: `api.anthropic.com platform.claude.com github.com raw.githubusercontent.com pypi.org files.pythonhosted.org registry.npmjs.org httpbin.org`.
- Interactive attach must be skippable with `ATTACH=0` (scripted testing); every subcommand except `up`/`inspect`/`direct`'s final attach must run non-interactively.
- Testing is live-command verification (this is ops tooling): each task runs its subcommand against the real sbx daemon and checks observable state. There is no unit-test harness.
- **Live-state caveat for executors:** the machine currently has hand-added state from the debugging session (allow rules for `api.anthropic.com`, `platform.claude.com`, `httpbin.org`; `proxy.sandbox` and `no_proxy.sandbox` overrides; a running mitmproxy on 8888; a `claude-agentwall` sandbox). Idempotent steps must tolerate it; Task 6's `clean` removes it.

## File Structure

```
Makefile                 # 4 thin targets → scripts/sandbox.sh (Task 1)
scripts/
└── sandbox.sh           # constants, helpers, cmd_up/cmd_inspect/cmd_direct/cmd_verify/cmd_clean (Tasks 1–6)
README.md                # + "Sandbox dev workflow" section (Task 6)
```

---

## Task 1: Script skeleton, shared helpers, Makefile

**Files:**
- Create: `scripts/sandbox.sh`
- Create: `Makefile`

**Interfaces:**
- Consumes: nothing.
- Produces (used by every later task): constants `SANDBOX_NAME`, `WORKSPACE`, `PROXY_PORT`, `PROXY_URL`, `NO_PROXY_SANDBOX`, `ALLOW_DOMAINS` (bash array), `MITM_DIR`, `MITM_LOG`, `MITM_PID`, `CA_CERT`; functions `info(msg)`, `die(msg)` (exit 1), `require(cmd, hint)`, `get_setting(key)` (prints value or empty), `sandbox_exists()`, `sandbox_running()`, `ensure_sandbox()` (create detached if missing), `start_sandbox()` (start if stopped), `attach()` (exec interactive attach unless `ATTACH=0`), `run_in_sandbox(sh_snippet)`; a `main`/case dispatcher where later tasks add `up|inspect|direct|verify|clean` cases.

- [ ] **Step 1: Write `scripts/sandbox.sh`**

```bash
#!/usr/bin/env bash
# Dev workflow for the AgentWall Claude sandbox (Docker Sandboxes / sbx).
# Owns: the ALLOW_DOMAINS egress rules, the proxy.sandbox/no_proxy.sandbox
# overrides, and a background mitmweb. `clean` undoes exactly that set.
set -euo pipefail

SANDBOX_NAME="claude-agentwall"
WORKSPACE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROXY_PORT=8888
PROXY_URL="http://localhost:${PROXY_PORT}"
NO_PROXY_SANDBOX="claude.com,*.claude.com,claude.ai,*.claude.ai,*.anthropic.com"
ALLOW_DOMAINS=(
  api.anthropic.com
  platform.claude.com
  github.com
  raw.githubusercontent.com
  pypi.org
  files.pythonhosted.org
  registry.npmjs.org
  httpbin.org
)
MITM_DIR="${HOME}/.cache/agentwall"
MITM_LOG="${MITM_DIR}/mitmweb.log"
MITM_PID="${MITM_DIR}/mitmweb.pid"
CA_CERT="${HOME}/.mitmproxy/mitmproxy-ca-cert.pem"

info() { printf '==> %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
require() { command -v "$1" >/dev/null 2>&1 || die "'$1' not found — $2"; }

# Read one sbx setting's effective value ("" when unset). Tolerates the JSON
# being either a top-level list or an object wrapping a list.
get_setting() {
  sbx settings ls --json 2>/dev/null | python3 -c '
import json, sys
key = sys.argv[1]
data = json.load(sys.stdin)
items = data if isinstance(data, list) else next(
    (v for v in data.values() if isinstance(v, list)), [])
for it in items:
    if it.get("key") == key or it.get("name") == key:
        print(it.get("value") or "")
        break
' "$1"
}

# `sbx ls` columns: SANDBOX AGENT STATUS PORTS WORKSPACE
sandbox_exists() { sbx ls 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "$SANDBOX_NAME"; }
sandbox_running() { sbx ls 2>/dev/null | awk -v n="$SANDBOX_NAME" '$1==n && $3=="running"' | grep -q .; }

ensure_sandbox() {
  if ! sandbox_exists; then
    info "creating sandbox $SANDBOX_NAME (detached)"
    sbx run claude --name "$SANDBOX_NAME" -d "$WORKSPACE" >/dev/null
  fi
}

start_sandbox() {
  if ! sandbox_running; then
    info "starting sandbox $SANDBOX_NAME"
    sbx run --name "$SANDBOX_NAME" -d >/dev/null
  fi
}

attach() {
  [ "${ATTACH:-1}" = "0" ] && return 0
  exec sbx run claude --name "$SANDBOX_NAME"
}

run_in_sandbox() { sbx exec "$SANDBOX_NAME" -- sh -c "$1"; }

usage() {
  cat <<EOF
Usage: scripts/sandbox.sh <subcommand>

  up       Launch/attach the Claude dev sandbox (policy + no_proxy ensured)
  inspect  Chain sandbox egress through mitmproxy (CA injected) and attach
  direct   Remove the mitmproxy chain (default state) and attach
  verify   Prove the current mode via in-sandbox TLS issuer + HTTPS POST
  clean    Remove the sandbox, script-owned policy rules, settings, mitmweb

Env: ATTACH=0 skips the interactive attach (for scripting).
EOF
}

main() {
  require sbx "install Docker Sandboxes (https://docs.docker.com/ai/sandboxes/)"
  require python3 "needed to parse sbx settings JSON"
  case "${1:-help}" in
    help|-h|--help) usage ;;
    *) usage; die "unknown subcommand: ${1:-}" ;;
  esac
}
main "$@"
```

- [ ] **Step 2: Make it executable and lint**

Run: `chmod +x scripts/sandbox.sh && shellcheck scripts/sandbox.sh`
Expected: no output (clean).

- [ ] **Step 3: Run the help path**

Run: `scripts/sandbox.sh help && scripts/sandbox.sh bogus; echo "exit=$?"`
Expected: usage text twice; `ERROR: unknown subcommand: bogus`; `exit=1`.

- [ ] **Step 4: Write `Makefile`**

```make
.PHONY: sandbox sandbox-inspect sandbox-direct sandbox-clean

sandbox:
	scripts/sandbox.sh up

sandbox-inspect:
	scripts/sandbox.sh inspect

sandbox-direct:
	scripts/sandbox.sh direct

sandbox-clean:
	scripts/sandbox.sh clean
```

- [ ] **Step 5: Sanity-check a make target fails cleanly (subcommand not implemented yet)**

Run: `make sandbox; echo "exit=$?"`
Expected: usage text, `ERROR: unknown subcommand: up`, non-zero exit propagated by make (`exit=2` from make is fine).

- [ ] **Step 6: Commit**

```bash
git add scripts/sandbox.sh Makefile
git commit -m "feat: sandbox.sh skeleton with shared sbx helpers and Makefile targets"
```

---

## Task 2: `up` subcommand

**Files:**
- Modify: `scripts/sandbox.sh` (add functions above `usage`; add case to `main`)

**Interfaces:**
- Consumes: Task 1 constants and helpers (`get_setting`, `ensure_sandbox`, `start_sandbox`, `attach`, `info`, `ALLOW_DOMAINS`, `NO_PROXY_SANDBOX`).
- Produces: `ensure_policy()`, `ensure_no_proxy()`, `cmd_up()` — reused verbatim by Task 5's `cmd_inspect`.

- [ ] **Step 1: Add `ensure_policy`, `ensure_no_proxy`, `cmd_up`**

```bash
ensure_policy() {
  local d
  for d in "${ALLOW_DOMAINS[@]}"; do
    if sbx policy check network "$d" 2>/dev/null | grep -q '^Allowed'; then
      continue
    fi
    info "allowing egress: $d"
    sbx policy allow network "$d" >/dev/null
  done
}

ensure_no_proxy() {
  if [ "$(get_setting no_proxy.sandbox)" != "$NO_PROXY_SANDBOX" ]; then
    info "setting no_proxy.sandbox (Anthropic auth/API bypasses any upstream proxy)"
    sbx settings set no_proxy.sandbox "$NO_PROXY_SANDBOX" >/dev/null
  fi
}

cmd_up() {
  ensure_policy
  ensure_no_proxy
  ensure_sandbox
  start_sandbox
  attach
}
```

Add to the `case` in `main`, above the `help` line:

```bash
    up) cmd_up ;;
```

- [ ] **Step 2: Lint**

Run: `shellcheck scripts/sandbox.sh`
Expected: clean.

- [ ] **Step 3: Run it non-interactively and check state**

Run: `ATTACH=0 scripts/sandbox.sh up && sbx policy check network registry.npmjs.org | head -1 && sbx ls`
Expected: `info` lines only for whatever was missing (idempotent — most rules already exist from the debugging session); `Allowed: registry.npmjs.org:443`; `claude-agentwall ... running`.

- [ ] **Step 4: Re-run to prove idempotency**

Run: `ATTACH=0 scripts/sandbox.sh up`
Expected: no `allowing egress` / `setting no_proxy` lines, exits 0 quickly.

- [ ] **Step 5: Commit**

```bash
git add scripts/sandbox.sh
git commit -m "feat: sandbox.sh up — idempotent policy/no_proxy ensure + launch"
```

---

## Task 3: `direct` subcommand

**Files:**
- Modify: `scripts/sandbox.sh`

**Interfaces:**
- Consumes: Task 1 helpers; Task 2's `ensure_policy`/`ensure_no_proxy` are NOT called here (direct only removes the chain).
- Produces: `restart_sandbox()` (used by Task 5's `cmd_inspect`), `cmd_direct()`.

- [ ] **Step 1: Add `restart_sandbox` and `cmd_direct`**

```bash
restart_sandbox() {
  info "restarting sandbox $SANDBOX_NAME"
  sbx stop "$SANDBOX_NAME" >/dev/null 2>&1 || true
  start_sandbox
}

cmd_direct() {
  if [ -n "$(get_setting proxy.sandbox)" ]; then
    info "unsetting proxy.sandbox (direct egress)"
    sbx settings unset proxy.sandbox >/dev/null
    restart_sandbox
  else
    info "already direct (proxy.sandbox unset)"
    ensure_sandbox
    start_sandbox
  fi
  attach
}
```

Add case: `    direct) cmd_direct ;;`

- [ ] **Step 2: Lint**

Run: `shellcheck scripts/sandbox.sh`
Expected: clean.

- [ ] **Step 3: Run it (live host currently has proxy.sandbox set — this exercises the unset path)**

Run: `ATTACH=0 scripts/sandbox.sh direct && sbx settings ls --no-trunc | grep -c "proxy.sandbox.*override"; echo ok`
Expected: `unsetting proxy.sandbox` + restart lines; grep count `0` (no override left; grep exiting 1 into `-c` prints 0); `ok`.

- [ ] **Step 4: Re-run to prove idempotency**

Run: `ATTACH=0 scripts/sandbox.sh direct`
Expected: `already direct (proxy.sandbox unset)`, sandbox stays running, exit 0.

- [ ] **Step 5: Commit**

```bash
git add scripts/sandbox.sh
git commit -m "feat: sandbox.sh direct — drop upstream proxy chain and restart"
```

---

## Task 4: `verify` subcommand

**Files:**
- Modify: `scripts/sandbox.sh`

**Interfaces:**
- Consumes: `get_setting`, `run_in_sandbox`, `sandbox_running`, `info`, `die`, `SANDBOX_NAME`.
- Produces: `cmd_verify()` — called at the end of Task 5's `cmd_inspect`.

- [ ] **Step 1: Add `cmd_verify`**

```bash
cmd_verify() {
  sandbox_running || die "sandbox $SANDBOX_NAME is not running (run: scripts/sandbox.sh up)"
  local mode issuer code
  if [ -n "$(get_setting proxy.sandbox)" ]; then mode=inspect; else mode=direct; fi
  issuer="$(run_in_sandbox \
    'curl -sv --max-time 15 https://httpbin.org/ -o /dev/null 2>&1 | grep -i "issuer:"' || true)"
  code="$(run_in_sandbox \
    'curl -sS --max-time 15 -X POST https://httpbin.org/post -d probe=agentwall -o /dev/null -w "%{http_code}"' || true)"
  info "mode=$mode ${issuer:-issuer=<none>} http=$code"
  if [ "$mode" = "inspect" ]; then
    if ! printf '%s' "$issuer" | grep -q mitmproxy; then
      die "inspect mode but issuer is not mitmproxy — is mitmweb running and the CA injected? (hint: sbx policy log $SANDBOX_NAME)"
    fi
  else
    if printf '%s' "$issuer" | grep -q mitmproxy; then
      die "direct mode but issuer is mitmproxy — stale proxy chain? (run: scripts/sandbox.sh direct)"
    fi
  fi
  if [ "$code" != "200" ]; then
    die "in-sandbox HTTPS POST to httpbin.org failed (HTTP ${code:-none}) — hint: sbx policy log $SANDBOX_NAME"
  fi
  info "verify OK ($mode mode)"
}
```

Add case: `    verify) cmd_verify ;;`

- [ ] **Step 2: Lint**

Run: `shellcheck scripts/sandbox.sh`
Expected: clean.

- [ ] **Step 3: Run in the current (direct) state**

Run: `scripts/sandbox.sh verify`
Expected: `mode=direct`, an `issuer:` line naming a real CA (e.g. Amazon), `http=200`, `verify OK (direct mode)`.

Note: the sandbox trust store may still contain the mitmproxy CA from the debugging session — that's fine; `verify` checks which issuer the server presented, not what's trusted.

- [ ] **Step 4: Prove the failure path**

Run: `sbx stop claude-agentwall >/dev/null; scripts/sandbox.sh verify; echo "exit=$?"; ATTACH=0 scripts/sandbox.sh up`
Expected: `ERROR: sandbox claude-agentwall is not running...`, `exit=1`, then `up` restores it.

- [ ] **Step 5: Commit**

```bash
git add scripts/sandbox.sh
git commit -m "feat: sandbox.sh verify — TLS-issuer + POST proof of current egress mode"
```

---

## Task 5: `inspect` subcommand

**Files:**
- Modify: `scripts/sandbox.sh`

**Interfaces:**
- Consumes: `ensure_policy`, `ensure_no_proxy` (Task 2), `restart_sandbox` (Task 3), `cmd_verify` (Task 4), Task 1 helpers/constants.
- Produces: `mitm_running()`, `start_mitmweb()`, `inject_ca()` (reused by Task 6's `clean` only via `MITM_PID`), `cmd_inspect()`.

- [ ] **Step 1: Add `mitm_running`, `start_mitmweb`, `inject_ca`, `cmd_inspect`**

```bash
mitm_running() { lsof -nP -iTCP:"$PROXY_PORT" -sTCP:LISTEN >/dev/null 2>&1; }

start_mitmweb() {
  if mitm_running; then
    info "proxy already listening on :$PROXY_PORT"
    return 0
  fi
  require uvx "install uv (https://docs.astral.sh/uv/)"
  mkdir -p "$MITM_DIR"
  info "starting mitmweb on :$PROXY_PORT (web UI URL + token: $MITM_LOG)"
  nohup uvx mitmweb -p "$PROXY_PORT" \
    --set web_open_browser=false \
    --set stream_large_bodies=1m >"$MITM_LOG" 2>&1 &
  echo $! >"$MITM_PID"
  local i
  for i in $(seq 1 30); do mitm_running && break; sleep 0.5; done
  mitm_running || die "mitmweb did not start listening on :$PROXY_PORT — see $MITM_LOG"
  for i in $(seq 1 30); do [ -f "$CA_CERT" ] && break; sleep 0.5; done
  [ -f "$CA_CERT" ] || die "mitmproxy CA never appeared at $CA_CERT — see $MITM_LOG"
}

# Trust the mitmproxy CA inside the sandbox: system store (curl/git/python)
# plus /etc/profile.d exports for Node and requests. Limitation (accepted in
# the spec): profile.d only reaches login-shell descendants.
inject_ca() {
  info "injecting mitmproxy CA into sandbox trust store"
  sbx cp "$CA_CERT" "$SANDBOX_NAME:/tmp/mitmproxy-ca.pem"
  run_in_sandbox '
    as_root() { if [ "$(id -u)" = "0" ]; then "$@"; else sudo -n "$@"; fi; }
    as_root cp /tmp/mitmproxy-ca.pem /usr/local/share/ca-certificates/mitmproxy-ca.crt &&
    as_root update-ca-certificates >/dev/null &&
    printf "export NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt\nexport REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt\n" \
      | as_root tee /etc/profile.d/mitm-ca.sh >/dev/null
  ' || die "CA injection failed — can the sandbox user reach root (sudo -n)?"
}

cmd_inspect() {
  ensure_policy
  ensure_no_proxy
  start_mitmweb
  if [ "$(get_setting proxy.sandbox)" != "$PROXY_URL" ]; then
    info "chaining sandbox egress through $PROXY_URL"
    sbx settings set proxy.sandbox "$PROXY_URL" >/dev/null
  fi
  ensure_sandbox
  restart_sandbox
  inject_ca
  cmd_verify
  attach
}
```

Add case: `    inspect) cmd_inspect ;;`

- [ ] **Step 2: Lint**

Run: `shellcheck scripts/sandbox.sh`
Expected: clean.

- [ ] **Step 3: Run it end-to-end**

Run: `ATTACH=0 scripts/sandbox.sh inspect`
Expected: policy/no_proxy already ensured (quiet); either `proxy already listening` (session mitmproxy still up) or `starting mitmweb`; `chaining sandbox egress`; restart; CA injection; `verify OK (inspect mode)` with `issuer: CN=mitmproxy`.

- [ ] **Step 4: Re-run to prove idempotency**

Run: `ATTACH=0 scripts/sandbox.sh inspect`
Expected: no re-setting of proxy.sandbox; restart + CA re-injection still run (harmless, overwrite-in-place); `verify OK (inspect mode)`.

- [ ] **Step 5: Flip back and forth**

Run: `ATTACH=0 scripts/sandbox.sh direct && scripts/sandbox.sh verify && ATTACH=0 scripts/sandbox.sh inspect`
Expected: `verify OK (direct mode)` in the middle, `verify OK (inspect mode)` at the end. This is the spec's toggle requirement.

- [ ] **Step 6: Commit**

```bash
git add scripts/sandbox.sh
git commit -m "feat: sandbox.sh inspect — mitmweb chain with CA injection and verify"
```

---

## Task 6: `clean` subcommand, README, final end-to-end

**Files:**
- Modify: `scripts/sandbox.sh`
- Modify: `README.md` (append section)

**Interfaces:**
- Consumes: everything prior; `MITM_PID`, `ALLOW_DOMAINS`, `get_setting`, `sandbox_exists`.
- Produces: `cmd_clean()`; final workflow documented for humans.

- [ ] **Step 1: Add `cmd_clean`**

```bash
cmd_clean() {
  if sandbox_exists; then
    info "removing sandbox $SANDBOX_NAME"
    sbx rm "$SANDBOX_NAME" >/dev/null
  fi
  local d
  for d in "${ALLOW_DOMAINS[@]}"; do
    if sbx policy check network "$d" 2>/dev/null | grep -q '^Allowed'; then
      info "removing egress allow: $d"
      sbx policy rm network --resource "$d" >/dev/null 2>&1 || true
    fi
  done
  if [ -n "$(get_setting proxy.sandbox)" ]; then
    info "unsetting proxy.sandbox"
    sbx settings unset proxy.sandbox >/dev/null
  fi
  if [ -n "$(get_setting no_proxy.sandbox)" ]; then
    info "unsetting no_proxy.sandbox"
    sbx settings unset no_proxy.sandbox >/dev/null
  fi
  if [ -f "$MITM_PID" ] && kill -0 "$(cat "$MITM_PID")" 2>/dev/null; then
    info "stopping mitmweb (pid $(cat "$MITM_PID"))"
    kill "$(cat "$MITM_PID")"
  fi
  rm -f "$MITM_PID"
  info "clean done — sbx policy ls / sbx settings ls to confirm"
}
```

Add case: `    clean) cmd_clean ;;`

Note: `sbx policy rm network --resource <d>` only ever matches local rules; kit-managed rules (claude.com etc.) are not in `ALLOW_DOMAINS` and are not touched. A rule the user added by hand for a domain that happens to be in `ALLOW_DOMAINS` (today's debugging rules) is intentionally removed — the script owns that list now.

- [ ] **Step 2: Lint**

Run: `shellcheck scripts/sandbox.sh`
Expected: clean.

- [ ] **Step 3: Full end-to-end pass (spec's manual test, scripted)**

Run:
```bash
ATTACH=0 scripts/sandbox.sh up \
  && ATTACH=0 scripts/sandbox.sh inspect \
  && ATTACH=0 scripts/sandbox.sh direct \
  && scripts/sandbox.sh verify \
  && scripts/sandbox.sh clean \
  && sbx policy check network httpbin.org | head -1 \
  && sbx settings ls --no-trunc | grep -c override; echo "grep-exit=$?"
```
Expected: `verify OK (inspect mode)` inside inspect; `verify OK (direct mode)` after direct; clean's removal lines; `Denied: httpbin.org:443`; override count `0` (only script-owned overrides existed).

Caveat: `clean` deletes the sandbox including its Claude login state; the next `up` needs `/login` once. That's the accepted cost of a real teardown — don't "optimize" it away.

- [ ] **Step 4: Append README section**

Append to `README.md`:

```markdown
## Sandbox dev workflow

Repeatable Docker Sandboxes (sbx) workflow for developing with a Claude agent
sandboxed on this repo. All host state (egress allow rules, proxy settings,
background mitmweb) is owned and undone by the script.

| Command | Does |
|---|---|
| `make sandbox` | Launch/attach the Claude sandbox; ensures the dev egress allowlist and the Anthropic no-proxy bypass (login works on first run) |
| `make sandbox-inspect` | Chain all sandbox egress (except Anthropic auth/API) through mitmproxy on :8888 with the CA trusted in-sandbox; web UI URL in `~/.cache/agentwall/mitmweb.log` |
| `make sandbox-direct` | Back to direct egress (default state) |
| `make sandbox-clean` | Remove sandbox, script-owned policy rules and settings overrides, stop mitmweb |

`scripts/sandbox.sh verify` proves the current mode: it checks the TLS issuer
seen inside the sandbox (`CN=mitmproxy` vs the real CA) and that an HTTPS POST
egresses successfully. `ATTACH=0` skips the interactive attach for scripting.

Findings behind this design (CONNECT chaining, CA-trust requirement, no_proxy
bypass for OAuth) are in `docs/spikes/tls-egress.md` and
`docs/superpowers/specs/2026-08-13-sandbox-dev-workflow-design.md`.
```

- [ ] **Step 5: Recreate the dev sandbox for continued use**

Run: `ATTACH=0 scripts/sandbox.sh up && sbx ls`
Expected: allowlist re-added, `claude-agentwall ... running`. (Login inside the sandbox happens next time the user attaches.)

- [ ] **Step 6: Commit**

```bash
git add scripts/sandbox.sh README.md
git commit -m "feat: sandbox.sh clean + README workflow docs; end-to-end pass"
```

---

## Self-Review

**Spec coverage:** components (script + Makefile) → Task 1; `up` + allowlist + no_proxy → Task 2; `direct` → Task 3; `verify` incl. mode detection via `proxy.sandbox` → Task 4; `inspect` incl. mitmweb launch, CA injection, verify-at-end → Task 5; `clean` owner-scoped undo + mitmweb stop → Task 6; check-then-act idempotency → explicit re-run steps in Tasks 2/3/5; fail-fast with `sbx policy log` hint → `cmd_verify`/`inject_ca` messages; shellcheck at every commit → Global Constraints; spike-linkage docs → Task 6 README pointer. ✓

**Placeholder scan:** every code step contains complete code; no TBD/TODO/"similar to". ✓

**Type consistency:** helper names (`get_setting`, `ensure_sandbox`, `start_sandbox`, `restart_sandbox`, `run_in_sandbox`, `ensure_policy`, `ensure_no_proxy`, `mitm_running`, `start_mitmweb`, `inject_ca`, `attach`, `cmd_*`) consistent across Tasks 1–6; constants referenced match Task 1 definitions. ✓

**Known live-behavior risks flagged to executors (not placeholders — the steps state expected output so deviations surface immediately):** `sbx run --name X -d` as "start stopped sandbox", `^Allowed` grep on `sbx policy check` output, and the shape of `sbx settings ls --json` were not all exercised in the design session; each has a single call site (`start_sandbox`, `ensure_policy`/`cmd_clean`, `get_setting`) so a fix lands in one place.
