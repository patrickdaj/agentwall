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

wait_daemon() {
  local _
  for _ in $(seq 1 30); do
    sbx daemon status >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  die "sbx daemon did not become ready after restart (see: sbx daemon status)"
}

# proxy.sandbox changes only apply on a daemon restart (a sandbox restart is
# insufficient — verified). This briefly stops ALL sandboxes on the host.
apply_proxy_change() {
  info "restarting sbx daemon to apply proxy change (briefly stops all sandboxes)"
  sbx daemon restart >/dev/null 2>&1 || die "sbx daemon restart failed (see: sbx daemon status)"
  wait_daemon
  start_sandbox
}

cmd_direct() {
  if [ -n "$(get_setting proxy.sandbox)" ]; then
    info "unsetting proxy.sandbox (direct egress)"
    sbx settings unset proxy.sandbox >/dev/null
    apply_proxy_change
  else
    info "already direct (proxy.sandbox unset)"
    ensure_sandbox
    start_sandbox
  fi
  attach
}

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
  local _
  for _ in $(seq 1 30); do mitm_running && break; sleep 0.5; done
  mitm_running || die "mitmweb did not start listening on :$PROXY_PORT — see $MITM_LOG"
  for _ in $(seq 1 30); do [ -f "$CA_CERT" ] && break; sleep 0.5; done
  [ -f "$CA_CERT" ] || die "mitmproxy CA never appeared at $CA_CERT — see $MITM_LOG"
}

# Trust the mitmproxy CA inside the sandbox: system store (curl/git/python)
# plus /etc/profile.d exports for Node and requests. Limitation (accepted in
# the spec): profile.d only reaches login-shell descendants.
inject_ca() {
  info "injecting mitmproxy CA into sandbox trust store"
  sbx cp "$CA_CERT" "$SANDBOX_NAME:/tmp/mitmproxy-ca.pem"
  # shellcheck disable=SC2016  # single-quoted: expands inside the sandbox, not here
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
  ensure_sandbox
  if [ "$(get_setting proxy.sandbox)" != "$PROXY_URL" ]; then
    info "chaining sandbox egress through $PROXY_URL"
    sbx settings set proxy.sandbox "$PROXY_URL" >/dev/null
    apply_proxy_change            # daemon restart — required for the change to engage
  else
    info "proxy.sandbox already $PROXY_URL"
    start_sandbox
  fi
  inject_ca
  cmd_verify
  attach
}

cmd_clean() {
  if sandbox_exists; then
    info "removing sandbox $SANDBOX_NAME"
    sbx rm --force "$SANDBOX_NAME" >/dev/null
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
    up) cmd_up ;;
    inspect) cmd_inspect ;;
    direct) cmd_direct ;;
    verify) cmd_verify ;;
    clean) cmd_clean ;;
    help|-h|--help) usage ;;
    *) usage; die "unknown subcommand: ${1:-}" ;;
  esac
}
main "$@"
