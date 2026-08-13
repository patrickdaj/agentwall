# AgentWall v0 (Foundation) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the AgentWall v0 foundation — a host-side daemon that ingests agent events, runs them through a deterministic-first detection cascade (Tier 0 rules + Tier 1 scanners), correlates them into provenance chains, evaluates YAML policy, and proves detection against attack-corpus rows 1–3 and the benign row 9 — plus the blocking TLS spike and a benchmark harness.

**Architecture:** A single long-running asyncio daemon. Sensors publish versioned Pydantic events onto an in-process event bus backed by SQLite (WAL). Each event flows synchronously through Tier 0 (rules, µs) and Tier 1 (Gitleaks + Presidio, ms); a `SecurityClassifier` seam exists for the v1 SLM but v0 registers a `NullClassifier`. A provenance correlator watches the event stream for `untrusted-source → sensitive-access → egress` chains. A YAML policy engine turns detections + chains into capability-gated verdicts. The attack corpus drives events into the bus and asserts verdicts/chains; the benchmark harness measures throughput and latency.

**Tech Stack:** Python 3.12+, uv, asyncio, Pydantic v2, Typer, SQLite (stdlib `sqlite3`, WAL), watchdog, Gitleaks (external binary), Microsoft Presidio, pytest.

## Global Constraints

- **Python floor:** 3.12+ (`requires-python = ">=3.12"`). Dev machine has 3.14; do not use 3.14-only syntax.
- **Package manager:** uv only. No pip, no poetry. Add deps with `uv add`.
- **Event schema is versioned:** every `SecurityEvent` carries `schema_version: int` (currently `1`). Never reorder or repurpose existing fields; additive changes only.
- **Classifiers never decide policy.** Tier detectors and the SLM emit `Detection` objects (`classification`, `confidence`, `evidence`); only `PolicyEngine` produces a `Verdict`.
- **Enforcement is capability-gated.** A `Verdict` of `BLOCK` is only legal if the active `RuntimeAdapter.capabilities()` contains `"block"`. `QUARANTINE` requires `"quarantine"`. The policy engine must downgrade illegal verdicts to `WARN` and record why.
- **Fail-safe, not fail-closed.** A sensor crash or scanner timeout degrades to lower tiers and emits a `degraded` health event; it never kills the agent.
- **Verdict enum (exact, ordered by severity):** `ALLOW < WARN < REQUIRE_APPROVAL < BLOCK < QUARANTINE`.
- **Source enum (exact):** `"egress" | "workspace" | "mcp" | "lifecycle"`.
- **Trust enum (exact):** `"trusted" | "tainted"`.
- **Non-functional targets (asserted by the benchmark task):** Tier 0/1 p95 < 10 ms per event; Tier-2 invocation rate < 2% (trivially 0 in v0, since no classifier is registered — assert the accounting works).
- **Commit style:** conventional commits (`feat:`, `test:`, `chore:`, `docs:`). Commit at the end of every task.
- **v0 sensor scope:** WorkspaceSensor is the only real sensor. Egress and MCP events in the corpus are **injected synthetically** by the corpus harness to exercise correlation logic; real EgressSensor/MCPSensor are v1.

---

## File Structure

```
agentwall/
├── pyproject.toml                      # uv project, deps, pytest/ruff config
├── src/agentwall/
│   ├── __init__.py
│   ├── events.py                       # SecurityEvent, enums, hashing (Task 3)
│   ├── storage.py                      # EventStore: SQLite WAL, dead-letter, replay (Task 4)
│   ├── bus.py                          # EventBus: asyncio pub/sub (Task 5)
│   ├── detect/
│   │   ├── __init__.py
│   │   ├── model.py                    # Verdict, Detection, Detector/Classifier protocols (Task 6)
│   │   ├── tier0_rules.py              # RulesDetector (Task 7)
│   │   ├── tier1_gitleaks.py           # GitleaksScanner (Task 8)
│   │   ├── tier1_presidio.py           # PresidioScanner (Task 9)
│   │   └── cascade.py                  # Cascade orchestrator (Task 10)
│   ├── policy/
│   │   ├── __init__.py
│   │   ├── engine.py                   # PolicyEngine, Decision (Task 11)
│   │   └── default_policy.yaml         # shipped default rules (Task 11)
│   ├── provenance.py                   # TaintStore, ChainCorrelator (Task 12)
│   ├── adapters/
│   │   ├── __init__.py
│   │   ├── base.py                     # RuntimeAdapter protocol + capability table (Task 13)
│   │   └── docker_sandbox.py           # DockerSandboxAdapter (Task 13)
│   ├── sensors/
│   │   ├── __init__.py
│   │   ├── base.py                     # RuntimeSensor protocol (Task 14)
│   │   └── workspace.py                # WorkspaceSensor (Task 14)
│   ├── daemon.py                       # Daemon wiring + health (Task 15)
│   └── cli.py                          # Typer app: run/status/replay/policy (Task 16)
├── corpus/
│   ├── __init__.py
│   ├── runner.py                       # ScenarioRunner harness (Task 17)
│   ├── scenario_01_readme_env_post.py  # (Task 17)
│   ├── scenario_02_git_hook.py         # (Task 17)
│   ├── scenario_03_package_json.py     # (Task 17)
│   └── scenario_09_benign_suite.py     # (Task 17)
├── bench/
│   └── run_bench.py                    # Benchmark harness (Task 18)
├── docs/spikes/tls-egress.md           # TLS spike writeup (Task 2)
└── tests/
    └── ... (mirrors src layout)
```

---

## Task 1: Project scaffolding

**Files:**
- Create: `pyproject.toml`, `src/agentwall/__init__.py`, `tests/__init__.py`, `tests/test_smoke.py`

**Interfaces:**
- Consumes: nothing.
- Produces: importable package `agentwall` with `__version__`; `uv run pytest` works.

- [ ] **Step 1: Initialize the uv project**

Run:
```bash
cd /Users/patrick/Development/agentwall
uv init --package --name agentwall --python 3.12
uv add pydantic typer watchdog
uv add --dev pytest pytest-asyncio ruff
```

- [ ] **Step 2: Set `requires-python` and pytest config in `pyproject.toml`**

Ensure `pyproject.toml` contains:
```toml
[project]
requires-python = ">=3.12"

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]

[tool.ruff]
line-length = 100
```

- [ ] **Step 3: Write the smoke test**

```python
# tests/test_smoke.py
import agentwall


def test_package_has_version():
    assert isinstance(agentwall.__version__, str)
    assert agentwall.__version__
```

- [ ] **Step 4: Set `__version__`**

```python
# src/agentwall/__init__.py
__version__ = "0.0.1"
```

- [ ] **Step 5: Run the test**

Run: `uv run pytest tests/test_smoke.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "chore: scaffold agentwall uv package"
```

---

## Task 2: TLS spike (blocking gate — parallelizable, does not block v0 code)

This is a **throwaway experiment**, not TDD. It answers one question and produces a written artifact. It gates the *v1 egress-DLP direction*, so start it early, but v0 code tasks (3–18) do not depend on its outcome.

**Files:**
- Create: `docs/spikes/tls-egress.md`

- [ ] **Step 1: Stand up a chained inspection proxy on the host**

Install mitmproxy in a throwaway venv (do NOT add to the project): `uvx mitmproxy --version`. Start it as an upstream target: `uvx mitmproxy -p 8888 --set stream_large_bodies=1m`.

- [ ] **Step 2: Point a Docker Sandbox's upstream proxy at it and drive traffic**

Configure the Docker Sandbox upstream proxy (per `sbx` docs) to chain through `http://host.docker.internal:8888`. From inside a sandbox, run an agent action that issues an HTTPS POST (e.g. `curl -X POST https://httpbin.org/post -d @somefile`).

- [ ] **Step 3: Record what the proxy sees**

In `docs/spikes/tls-egress.md`, document under an **Observations** heading: for each request, whether mitmproxy showed (a) full request plaintext (headers + body), (b) only a `CONNECT host:443` tunnel with SNI, or (c) nothing. Capture one redacted screenshot/log excerpt as evidence.

- [ ] **Step 4: Write the verdict and route**

In the same file, under **Verdict**, state one of:
- `PLAINTEXT` → v1 does inline egress payload DLP on Docker Sandboxes.
- `OPAQUE` → v1 egress DLP ships on plain-Docker/clawk first; Docker Sandboxes gets domain+metadata egress + host-guardian; file the proxy-hook ask upstream.

- [ ] **Step 5: Commit**

```bash
git add docs/spikes/tls-egress.md
git commit -m "docs: TLS egress spike results and v1 routing decision"
```

---

## Task 3: Event schema and hashing

**Files:**
- Create: `src/agentwall/events.py`
- Test: `tests/test_events.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `Source = Literal["egress", "workspace", "mcp", "lifecycle"]`
  - `Trust = Literal["trusted", "tainted"]`
  - `class SecurityEvent(BaseModel)` with fields: `schema_version: int = 1`, `event_id: str`, `event_type: str`, `session_id: str`, `agent_id: str = "unknown"`, `source: Source`, `content_hash: str | None = None`, `trust: Trust = "trusted"`, `payload_ref: str | None = None`, `ts: float`, `attrs: dict[str, Any] = {}`.
  - `def new_event(*, event_type, session_id, source, ts, **kw) -> SecurityEvent` (generates `event_id` via `uuid4().hex`).
  - `def content_hash(data: bytes) -> str` (returns `"sha256:" + hexdigest`).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_events.py
from agentwall.events import SecurityEvent, new_event, content_hash


def test_new_event_generates_id_and_defaults():
    e = new_event(event_type="file_write", session_id="s1", source="workspace", ts=1.0)
    assert e.schema_version == 1
    assert len(e.event_id) == 32
    assert e.agent_id == "unknown"
    assert e.trust == "trusted"


def test_content_hash_is_stable_and_prefixed():
    assert content_hash(b"abc") == content_hash(b"abc")
    assert content_hash(b"abc").startswith("sha256:")
    assert content_hash(b"abc") != content_hash(b"abd")


def test_event_roundtrips_json():
    e = new_event(event_type="file_write", session_id="s1", source="workspace", ts=1.0)
    assert SecurityEvent.model_validate_json(e.model_dump_json()) == e
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_events.py -v`
Expected: FAIL with `ModuleNotFoundError` / `ImportError`.

- [ ] **Step 3: Write minimal implementation**

```python
# src/agentwall/events.py
from __future__ import annotations

import hashlib
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field

Source = Literal["egress", "workspace", "mcp", "lifecycle"]
Trust = Literal["trusted", "tainted"]


class SecurityEvent(BaseModel):
    schema_version: int = 1
    event_id: str
    event_type: str
    session_id: str
    agent_id: str = "unknown"
    source: Source
    content_hash: str | None = None
    trust: Trust = "trusted"
    payload_ref: str | None = None
    ts: float
    attrs: dict[str, Any] = Field(default_factory=dict)


def new_event(*, event_type: str, session_id: str, source: Source, ts: float, **kw: Any) -> SecurityEvent:
    return SecurityEvent(event_id=uuid4().hex, event_type=event_type, session_id=session_id, source=source, ts=ts, **kw)


def content_hash(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_events.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/agentwall/events.py tests/test_events.py
git commit -m "feat: versioned SecurityEvent schema and content hashing"
```

---

## Task 4: SQLite event store

**Files:**
- Create: `src/agentwall/storage.py`
- Test: `tests/test_storage.py`

**Interfaces:**
- Consumes: `SecurityEvent` (Task 3).
- Produces:
  - `class EventStore` constructed as `EventStore(path: str | Path)`; opens SQLite in WAL mode, creates schema on init.
  - `.append(event: SecurityEvent) -> None` — persists to `events` table with `processed=0`.
  - `.mark_processed(event_id: str) -> None`.
  - `.unprocessed() -> list[SecurityEvent]` — events with `processed=0`, oldest first (for restart replay).
  - `.all_events() -> list[SecurityEvent]` — oldest first.
  - `.dead_letter(raw: str, error: str) -> None` — stores un-parseable payloads.
  - `.dead_letters() -> list[tuple[str, str]]` — `(raw, error)` rows.
  - `.put_blob(data: bytes) -> str` / `.get_blob(ref: str) -> bytes` — payload store; ref is `"blob:<rowid>"`.
  - `.close() -> None`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_storage.py
from agentwall.events import new_event
from agentwall.storage import EventStore


def test_append_and_replay_unprocessed(tmp_path):
    store = EventStore(tmp_path / "ev.db")
    e = new_event(event_type="file_write", session_id="s1", source="workspace", ts=1.0)
    store.append(e)
    assert [x.event_id for x in store.unprocessed()] == [e.event_id]
    store.mark_processed(e.event_id)
    assert store.unprocessed() == []
    store.close()


def test_blob_roundtrip(tmp_path):
    store = EventStore(tmp_path / "ev.db")
    ref = store.put_blob(b"secret-bytes")
    assert ref.startswith("blob:")
    assert store.get_blob(ref) == b"secret-bytes"
    store.close()


def test_dead_letter(tmp_path):
    store = EventStore(tmp_path / "ev.db")
    store.dead_letter("{bad json", "ValidationError")
    assert store.dead_letters() == [("{bad json", "ValidationError")]
    store.close()


def test_persists_across_reopen(tmp_path):
    p = tmp_path / "ev.db"
    s1 = EventStore(p)
    e = new_event(event_type="x", session_id="s1", source="workspace", ts=1.0)
    s1.append(e)
    s1.close()
    s2 = EventStore(p)
    assert [x.event_id for x in s2.all_events()] == [e.event_id]
    s2.close()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_storage.py -v`
Expected: FAIL with import error.

- [ ] **Step 3: Write minimal implementation**

```python
# src/agentwall/storage.py
from __future__ import annotations

import sqlite3
from pathlib import Path

from agentwall.events import SecurityEvent

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    rowid INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT UNIQUE NOT NULL,
    ts REAL NOT NULL,
    processed INTEGER NOT NULL DEFAULT 0,
    json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS blobs (
    rowid INTEGER PRIMARY KEY AUTOINCREMENT,
    data BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS dead_letters (
    rowid INTEGER PRIMARY KEY AUTOINCREMENT,
    raw TEXT NOT NULL,
    error TEXT NOT NULL
);
"""


class EventStore:
    def __init__(self, path: str | Path) -> None:
        self._conn = sqlite3.connect(str(path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def append(self, event: SecurityEvent) -> None:
        self._conn.execute(
            "INSERT INTO events (event_id, ts, processed, json) VALUES (?, ?, 0, ?)",
            (event.event_id, event.ts, event.model_dump_json()),
        )
        self._conn.commit()

    def mark_processed(self, event_id: str) -> None:
        self._conn.execute("UPDATE events SET processed=1 WHERE event_id=?", (event_id,))
        self._conn.commit()

    def _rows_to_events(self, rows: list[tuple[str]]) -> list[SecurityEvent]:
        return [SecurityEvent.model_validate_json(r[0]) for r in rows]

    def unprocessed(self) -> list[SecurityEvent]:
        rows = self._conn.execute(
            "SELECT json FROM events WHERE processed=0 ORDER BY rowid"
        ).fetchall()
        return self._rows_to_events(rows)

    def all_events(self) -> list[SecurityEvent]:
        rows = self._conn.execute("SELECT json FROM events ORDER BY rowid").fetchall()
        return self._rows_to_events(rows)

    def put_blob(self, data: bytes) -> str:
        cur = self._conn.execute("INSERT INTO blobs (data) VALUES (?)", (data,))
        self._conn.commit()
        return f"blob:{cur.lastrowid}"

    def get_blob(self, ref: str) -> bytes:
        rowid = int(ref.split(":", 1)[1])
        row = self._conn.execute("SELECT data FROM blobs WHERE rowid=?", (rowid,)).fetchone()
        return bytes(row[0])

    def dead_letter(self, raw: str, error: str) -> None:
        self._conn.execute("INSERT INTO dead_letters (raw, error) VALUES (?, ?)", (raw, error))
        self._conn.commit()

    def dead_letters(self) -> list[tuple[str, str]]:
        return self._conn.execute("SELECT raw, error FROM dead_letters ORDER BY rowid").fetchall()

    def close(self) -> None:
        self._conn.close()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_storage.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/agentwall/storage.py tests/test_storage.py
git commit -m "feat: SQLite WAL event store with blobs, dead-letter, replay"
```

---

## Task 5: Event bus

**Files:**
- Create: `src/agentwall/bus.py`
- Test: `tests/test_bus.py`

**Interfaces:**
- Consumes: `SecurityEvent` (Task 3), `EventStore` (Task 4).
- Produces:
  - `Handler = Callable[[SecurityEvent], Awaitable[None]]`.
  - `class EventBus(store: EventStore)`.
  - `.subscribe(handler: Handler) -> None`.
  - `async .publish(event: SecurityEvent) -> None` — persists via store, then dispatches to every handler. A handler exception is caught, routed to `store.dead_letter(event.model_dump_json(), repr(exc))`, and does not stop other handlers (fail-safe). After all handlers succeed without raising, `store.mark_processed(event.event_id)`.
  - `async .replay_unprocessed() -> int` — re-publishes `store.unprocessed()`, returns count.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bus.py
import pytest

from agentwall.bus import EventBus
from agentwall.events import new_event
from agentwall.storage import EventStore


def _evt():
    return new_event(event_type="x", session_id="s1", source="workspace", ts=1.0)


async def test_publish_dispatches_to_handlers(tmp_path):
    bus = EventBus(EventStore(tmp_path / "ev.db"))
    seen = []
    bus.subscribe(lambda e: _collect(seen, e))
    await bus.publish(_evt())
    assert len(seen) == 1


async def _collect(sink, e):
    sink.append(e)


async def test_failing_handler_is_isolated_and_dead_lettered(tmp_path):
    store = EventStore(tmp_path / "ev.db")
    bus = EventBus(store)
    good = []

    async def boom(e):
        raise RuntimeError("kaboom")

    bus.subscribe(boom)
    bus.subscribe(lambda e: _collect(good, e))
    await bus.publish(_evt())
    assert len(good) == 1               # other handler still ran
    assert len(store.dead_letters()) == 1


async def test_replay_unprocessed(tmp_path):
    store = EventStore(tmp_path / "ev.db")
    store.append(_evt())
    bus = EventBus(store)
    seen = []
    bus.subscribe(lambda e: _collect(seen, e))
    n = await bus.replay_unprocessed()
    assert n == 1 and len(seen) == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_bus.py -v`
Expected: FAIL with import error.

- [ ] **Step 3: Write minimal implementation**

```python
# src/agentwall/bus.py
from __future__ import annotations

from typing import Awaitable, Callable

from agentwall.events import SecurityEvent
from agentwall.storage import EventStore

Handler = Callable[[SecurityEvent], Awaitable[None]]


class EventBus:
    def __init__(self, store: EventStore) -> None:
        self._store = store
        self._handlers: list[Handler] = []

    def subscribe(self, handler: Handler) -> None:
        self._handlers.append(handler)

    async def publish(self, event: SecurityEvent) -> None:
        self._store.append(event)
        failed = False
        for handler in self._handlers:
            try:
                await handler(event)
            except Exception as exc:  # fail-safe: isolate handler failures
                failed = True
                self._store.dead_letter(event.model_dump_json(), repr(exc))
        if not failed:
            self._store.mark_processed(event.event_id)

    async def replay_unprocessed(self) -> int:
        pending = self._store.unprocessed()
        for event in pending:
            await self.publish(event)
        return len(pending)
```

Note: `replay_unprocessed` re-`append`s during `publish`. For v0 that produces a duplicate row; acceptable because `event_id` is UNIQUE — wrap the append insert with `INSERT OR IGNORE`. Update `EventStore.append` to use `INSERT OR IGNORE INTO events ...` and re-run Task 4 tests to confirm still green.

- [ ] **Step 4: Apply the `INSERT OR IGNORE` fix and run both test files**

Run: `uv run pytest tests/test_storage.py tests/test_bus.py -v`
Expected: PASS (all)

- [ ] **Step 5: Commit**

```bash
git add src/agentwall/bus.py src/agentwall/storage.py tests/test_bus.py
git commit -m "feat: fail-safe asyncio event bus with replay"
```

---

## Task 6: Detection model and protocols

**Files:**
- Create: `src/agentwall/detect/__init__.py`, `src/agentwall/detect/model.py`
- Test: `tests/detect/test_model.py`, `tests/detect/__init__.py`

**Interfaces:**
- Consumes: `SecurityEvent` (Task 3).
- Produces:
  - `class Verdict(IntEnum)`: `ALLOW=0, WARN=1, REQUIRE_APPROVAL=2, BLOCK=3, QUARANTINE=4` (IntEnum so severity comparisons work).
  - `class Detection(BaseModel)`: `tier: int`, `classification: str`, `confidence: float`, `evidence: list[str] = []`.
  - `class Detector(Protocol)`: `def inspect(self, event: SecurityEvent, payload: bytes | None) -> list[Detection]: ...`
  - `class SecurityClassifier(Protocol)`: `async def classify(self, event: SecurityEvent, payload: bytes | None) -> Detection | None: ...`
  - `class NullClassifier`: implements `SecurityClassifier`, always returns `None`.

- [ ] **Step 1: Write the failing test**

```python
# tests/detect/test_model.py
from agentwall.detect.model import Detection, NullClassifier, Verdict
from agentwall.events import new_event


def test_verdict_severity_ordering():
    assert Verdict.ALLOW < Verdict.WARN < Verdict.BLOCK < Verdict.QUARANTINE
    assert max(Verdict.WARN, Verdict.QUARANTINE) is Verdict.QUARANTINE


def test_detection_fields():
    d = Detection(tier=0, classification="secret", confidence=0.9, evidence=["aws key"])
    assert d.tier == 0 and d.evidence == ["aws key"]


async def test_null_classifier_returns_none():
    e = new_event(event_type="x", session_id="s", source="workspace", ts=1.0)
    assert await NullClassifier().classify(e, None) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/detect/test_model.py -v`
Expected: FAIL with import error.

- [ ] **Step 3: Write minimal implementation**

```python
# src/agentwall/detect/model.py
from __future__ import annotations

from enum import IntEnum
from typing import Protocol

from pydantic import BaseModel, Field

from agentwall.events import SecurityEvent


class Verdict(IntEnum):
    ALLOW = 0
    WARN = 1
    REQUIRE_APPROVAL = 2
    BLOCK = 3
    QUARANTINE = 4


class Detection(BaseModel):
    tier: int
    classification: str
    confidence: float
    evidence: list[str] = Field(default_factory=list)


class Detector(Protocol):
    def inspect(self, event: SecurityEvent, payload: bytes | None) -> list[Detection]: ...


class SecurityClassifier(Protocol):
    async def classify(self, event: SecurityEvent, payload: bytes | None) -> Detection | None: ...


class NullClassifier:
    async def classify(self, event: SecurityEvent, payload: bytes | None) -> Detection | None:
        return None
```

Create empty `src/agentwall/detect/__init__.py` and `tests/detect/__init__.py`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/detect/test_model.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/agentwall/detect tests/detect
git commit -m "feat: Verdict/Detection model and detector protocols"
```

---

## Task 7: Tier 0 rules detector

**Files:**
- Create: `src/agentwall/detect/tier0_rules.py`
- Test: `tests/detect/test_tier0.py`

**Interfaces:**
- Consumes: `SecurityEvent` (Task 3), `Detection` (Task 6).
- Produces:
  - `class RulesConfig(BaseModel)`: `sensitive_path_globs: list[str]`, `denied_dest_domains: list[str]`, `max_upload_bytes: int`, `entropy_threshold: float`.
  - `class RulesDetector(config: RulesConfig)` implementing `Detector`.
  - Behavior — emits `Detection(tier=0, ...)` for: workspace events whose `attrs["path"]` matches a sensitive glob (`classification="sensitive_path_access"`); egress events whose `attrs["destination"]` matches a denied domain (`classification="denied_destination"`) or whose `attrs["size"]` exceeds `max_upload_bytes` (`classification="oversize_upload"`); any payload whose Shannon entropy ≥ threshold (`classification="high_entropy"`).
  - `def shannon_entropy(data: bytes) -> float` (module-level helper).

- [ ] **Step 1: Write the failing test**

```python
# tests/detect/test_tier0.py
from agentwall.detect.tier0_rules import RulesConfig, RulesDetector, shannon_entropy
from agentwall.events import new_event


def _cfg():
    return RulesConfig(
        sensitive_path_globs=["**/.env", "**/.ssh/*", "**/.aws/*"],
        denied_dest_domains=["evil.example"],
        max_upload_bytes=1_000_000,
        entropy_threshold=7.5,
    )


def test_sensitive_path_access_flagged():
    det = RulesDetector(_cfg())
    e = new_event(event_type="file_read", session_id="s", source="workspace", ts=1.0,
                  attrs={"path": "/work/project/.env"})
    out = det.inspect(e, None)
    assert any(d.classification == "sensitive_path_access" for d in out)


def test_denied_destination_and_oversize():
    det = RulesDetector(_cfg())
    e = new_event(event_type="network_upload", session_id="s", source="egress", ts=1.0,
                  attrs={"destination": "evil.example", "size": 5_000_000})
    cls = {d.classification for d in det.inspect(e, None)}
    assert "denied_destination" in cls and "oversize_upload" in cls


def test_high_entropy_payload():
    det = RulesDetector(_cfg())
    import os
    e = new_event(event_type="network_upload", session_id="s", source="egress", ts=1.0, attrs={})
    out = det.inspect(e, os.urandom(4096))
    assert any(d.classification == "high_entropy" for d in out)


def test_benign_event_is_silent():
    det = RulesDetector(_cfg())
    e = new_event(event_type="file_read", session_id="s", source="workspace", ts=1.0,
                  attrs={"path": "/work/project/README.md"})
    assert det.inspect(e, b"hello world") == []


def test_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"aaaa") < 1.0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/detect/test_tier0.py -v`
Expected: FAIL with import error.

- [ ] **Step 3: Write minimal implementation**

```python
# src/agentwall/detect/tier0_rules.py
from __future__ import annotations

import math
from fnmatch import fnmatch

from pydantic import BaseModel

from agentwall.detect.model import Detection
from agentwall.events import SecurityEvent


class RulesConfig(BaseModel):
    sensitive_path_globs: list[str]
    denied_dest_domains: list[str]
    max_upload_bytes: int
    entropy_threshold: float


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


class RulesDetector:
    def __init__(self, config: RulesConfig) -> None:
        self._c = config

    def inspect(self, event: SecurityEvent, payload: bytes | None) -> list[Detection]:
        out: list[Detection] = []
        path = event.attrs.get("path")
        if path and any(fnmatch(path, g) for g in self._c.sensitive_path_globs):
            out.append(Detection(tier=0, classification="sensitive_path_access",
                                  confidence=1.0, evidence=[path]))
        dest = event.attrs.get("destination")
        if dest and any(dest == d or dest.endswith("." + d) for d in self._c.denied_dest_domains):
            out.append(Detection(tier=0, classification="denied_destination",
                                 confidence=1.0, evidence=[dest]))
        size = event.attrs.get("size")
        if isinstance(size, int) and size > self._c.max_upload_bytes:
            out.append(Detection(tier=0, classification="oversize_upload",
                                 confidence=1.0, evidence=[f"{size} bytes"]))
        if payload is not None and shannon_entropy(payload) >= self._c.entropy_threshold:
            out.append(Detection(tier=0, classification="high_entropy",
                                 confidence=0.7, evidence=[f"entropy>={self._c.entropy_threshold}"]))
        return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/detect/test_tier0.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/agentwall/detect/tier0_rules.py tests/detect/test_tier0.py
git commit -m "feat: Tier 0 deterministic rules detector"
```

---

## Task 8: Tier 1 Gitleaks scanner

**Files:**
- Create: `src/agentwall/detect/tier1_gitleaks.py`
- Test: `tests/detect/test_gitleaks.py`

**Interfaces:**
- Consumes: `SecurityEvent` (Task 3), `Detection` (Task 6).
- Produces:
  - `class GitleaksScanner(binary: str = "gitleaks", timeout_s: float = 2.0)` implementing `Detector`.
  - `.inspect(event, payload)` — writes `payload` to a temp file, runs `gitleaks detect --no-git --report-format json --report-path <tmp> --source <file>`, parses findings into `Detection(tier=1, classification="secret:<RuleID>", confidence=0.95, evidence=[Description])`. Returns `[]` if payload is None. On timeout or missing binary, returns `[]` and sets `self.degraded = True` (fail-safe — never raises).

- [ ] **Step 1: Install the gitleaks binary**

Run: `brew install gitleaks` (dev machine has no gitleaks per toolchain check). Verify: `gitleaks version`.

- [ ] **Step 2: Write the failing test**

```python
# tests/detect/test_gitleaks.py
import shutil

import pytest

from agentwall.detect.tier1_gitleaks import GitleaksScanner
from agentwall.events import new_event

pytestmark = pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks not installed")


def _evt():
    return new_event(event_type="network_upload", session_id="s", source="egress", ts=1.0)


def test_detects_aws_key():
    scanner = GitleaksScanner()
    payload = b"AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    out = scanner.inspect(_evt(), payload)
    assert any(d.classification.startswith("secret:") for d in out)


def test_clean_payload_is_silent():
    scanner = GitleaksScanner()
    assert scanner.inspect(_evt(), b"just some normal text\n") == []


def test_missing_binary_is_fail_safe():
    scanner = GitleaksScanner(binary="definitely-not-a-real-binary-xyz")
    assert scanner.inspect(_evt(), b"AKIAIOSFODNN7EXAMPLE") == []
    assert scanner.degraded is True
```

- [ ] **Step 3: Run test to verify it fails**

Run: `uv run pytest tests/detect/test_gitleaks.py -v`
Expected: FAIL with import error.

- [ ] **Step 4: Write minimal implementation**

```python
# src/agentwall/detect/tier1_gitleaks.py
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from agentwall.detect.model import Detection
from agentwall.events import SecurityEvent


class GitleaksScanner:
    def __init__(self, binary: str = "gitleaks", timeout_s: float = 2.0) -> None:
        self._bin = binary
        self._timeout = timeout_s
        self.degraded = False

    def inspect(self, event: SecurityEvent, payload: bytes | None) -> list[Detection]:
        if payload is None:
            return []
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "payload"
            report = Path(d) / "report.json"
            src.write_bytes(payload)
            try:
                subprocess.run(
                    [self._bin, "detect", "--no-git", "--report-format", "json",
                     "--report-path", str(report), "--source", str(src)],
                    capture_output=True, timeout=self._timeout, check=False,
                )
            except (FileNotFoundError, subprocess.TimeoutExpired):
                self.degraded = True
                return []
            if not report.exists():
                return []
            findings = json.loads(report.read_text() or "[]")
        return [
            Detection(tier=1, classification=f"secret:{f.get('RuleID', 'unknown')}",
                      confidence=0.95, evidence=[f.get("Description", "")])
            for f in findings
        ]
```

- [ ] **Step 5: Run test to verify it passes**

Run: `uv run pytest tests/detect/test_gitleaks.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/agentwall/detect/tier1_gitleaks.py tests/detect/test_gitleaks.py
git commit -m "feat: Tier 1 Gitleaks secret scanner (fail-safe)"
```

---

## Task 9: Tier 1 Presidio scanner

**Files:**
- Create: `src/agentwall/detect/tier1_presidio.py`
- Test: `tests/detect/test_presidio.py`

**Interfaces:**
- Consumes: `SecurityEvent` (Task 3), `Detection` (Task 6).
- Produces:
  - `class PresidioScanner(min_score: float = 0.6, entities: list[str] | None = None)` implementing `Detector`. Lazily constructs an `AnalyzerEngine` on first use.
  - `.inspect(event, payload)` — decodes payload as UTF-8 (errors ignored), runs Presidio analyze, emits `Detection(tier=1, classification="pii:<ENTITY_TYPE>", confidence=<score>, evidence=[<entity_type>])` for results ≥ `min_score`. Returns `[]` if payload None or empty. Any exception → `[]`, `self.degraded=True` (fail-safe).

- [ ] **Step 1: Add the dependency**

Run: `uv add presidio-analyzer && uv run python -m spacy download en_core_web_lg`. (Presidio needs a spaCy model; `en_core_web_lg` is Presidio's default.)

- [ ] **Step 2: Write the failing test**

```python
# tests/detect/test_presidio.py
import pytest

from agentwall.detect.tier1_presidio import PresidioScanner
from agentwall.events import new_event

analyzer_available = True
try:
    from presidio_analyzer import AnalyzerEngine  # noqa: F401
except Exception:
    analyzer_available = False

pytestmark = pytest.mark.skipif(not analyzer_available, reason="presidio not installed")


def _evt():
    return new_event(event_type="network_upload", session_id="s", source="egress", ts=1.0)


def test_detects_email_and_ssn():
    scanner = PresidioScanner()
    out = scanner.inspect(_evt(), b"contact john@example.com, SSN 123-45-6789")
    cls = {d.classification for d in out}
    assert any(c.startswith("pii:") for c in cls)


def test_clean_text_silent():
    scanner = PresidioScanner()
    assert scanner.inspect(_evt(), b"the quick brown fox") == []


def test_none_payload():
    assert PresidioScanner().inspect(_evt(), None) == []
```

- [ ] **Step 3: Run test to verify it fails**

Run: `uv run pytest tests/detect/test_presidio.py -v`
Expected: FAIL with import error.

- [ ] **Step 4: Write minimal implementation**

```python
# src/agentwall/detect/tier1_presidio.py
from __future__ import annotations

from agentwall.detect.model import Detection
from agentwall.events import SecurityEvent


class PresidioScanner:
    def __init__(self, min_score: float = 0.6, entities: list[str] | None = None) -> None:
        self._min = min_score
        self._entities = entities
        self._engine = None
        self.degraded = False

    def _analyzer(self):
        if self._engine is None:
            from presidio_analyzer import AnalyzerEngine
            self._engine = AnalyzerEngine()
        return self._engine

    def inspect(self, event: SecurityEvent, payload: bytes | None) -> list[Detection]:
        if not payload:
            return []
        text = payload.decode("utf-8", errors="ignore")
        try:
            results = self._analyzer().analyze(text=text, entities=self._entities, language="en")
        except Exception:
            self.degraded = True
            return []
        return [
            Detection(tier=1, classification=f"pii:{r.entity_type}",
                      confidence=r.score, evidence=[r.entity_type])
            for r in results if r.score >= self._min
        ]
```

- [ ] **Step 5: Run test to verify it passes**

Run: `uv run pytest tests/detect/test_presidio.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/agentwall/detect/tier1_presidio.py tests/detect/test_presidio.py pyproject.toml
git commit -m "feat: Tier 1 Presidio PII scanner (fail-safe, lazy load)"
```

---

## Task 10: Cascade orchestrator

**Files:**
- Create: `src/agentwall/detect/cascade.py`
- Test: `tests/detect/test_cascade.py`

**Interfaces:**
- Consumes: `SecurityEvent` (3), `Detection`/`Detector`/`SecurityClassifier` (6).
- Produces:
  - `class CascadeStats(BaseModel)`: `total: int = 0`, `tier2_invocations: int = 0`; property `tier2_rate` → `tier2_invocations / total` (0.0 if total 0).
  - `class CascadeResult(BaseModel)`: `detections: list[Detection]`, `escalated: bool`.
  - `class Cascade(tier0: list[Detector], tier1: list[Detector], classifier: SecurityClassifier, escalate_when: Callable[[list[Detection]], bool])`.
  - `async .run(event, payload) -> CascadeResult` — runs all Tier 0 detectors; then all Tier 1 detectors; if `escalate_when(all_detections_so_far)` is True, invokes `classifier.classify` (counts a tier2 invocation) and appends any returned `Detection`; sets `escalated` accordingly. Updates `self.stats`.
  - Default escalation predicate `escalate_on_any(dets) -> bool` (module-level): escalate when there is at least one detection (v0 uses `NullClassifier` so this is cheap and observable).

- [ ] **Step 1: Write the failing test**

```python
# tests/detect/test_cascade.py
from agentwall.detect.cascade import Cascade, escalate_on_any
from agentwall.detect.model import Detection, NullClassifier
from agentwall.events import new_event


class FakeDetector:
    def __init__(self, dets):
        self._dets = dets

    def inspect(self, event, payload):
        return list(self._dets)


class RecordingClassifier:
    def __init__(self):
        self.calls = 0

    async def classify(self, event, payload):
        self.calls += 1
        return Detection(tier=2, classification="semantic", confidence=0.5)


def _evt():
    return new_event(event_type="x", session_id="s", source="workspace", ts=1.0)


async def test_runs_all_tiers_and_collects():
    t0 = FakeDetector([Detection(tier=0, classification="a", confidence=1.0)])
    t1 = FakeDetector([Detection(tier=1, classification="b", confidence=1.0)])
    c = Cascade([t0], [t1], NullClassifier(), escalate_on_any)
    res = await c.run(_evt(), None)
    assert {d.classification for d in res.detections} >= {"a", "b"}


async def test_escalation_invokes_classifier_and_counts():
    t0 = FakeDetector([Detection(tier=0, classification="a", confidence=1.0)])
    rc = RecordingClassifier()
    c = Cascade([t0], [], rc, escalate_on_any)
    res = await c.run(_evt(), None)
    assert rc.calls == 1 and res.escalated
    assert c.stats.tier2_invocations == 1 and c.stats.total == 1


async def test_no_detection_no_escalation():
    c = Cascade([FakeDetector([])], [], NullClassifier(), escalate_on_any)
    res = await c.run(_evt(), None)
    assert res.escalated is False and c.stats.tier2_rate == 0.0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/detect/test_cascade.py -v`
Expected: FAIL with import error.

- [ ] **Step 3: Write minimal implementation**

```python
# src/agentwall/detect/cascade.py
from __future__ import annotations

from typing import Callable

from pydantic import BaseModel

from agentwall.detect.model import Detection, Detector, SecurityClassifier
from agentwall.events import SecurityEvent


class CascadeStats(BaseModel):
    total: int = 0
    tier2_invocations: int = 0

    @property
    def tier2_rate(self) -> float:
        return self.tier2_invocations / self.total if self.total else 0.0


class CascadeResult(BaseModel):
    detections: list[Detection]
    escalated: bool


def escalate_on_any(dets: list[Detection]) -> bool:
    return len(dets) > 0


class Cascade:
    def __init__(self, tier0: list[Detector], tier1: list[Detector],
                 classifier: SecurityClassifier,
                 escalate_when: Callable[[list[Detection]], bool]) -> None:
        self._t0 = tier0
        self._t1 = tier1
        self._clf = classifier
        self._escalate = escalate_when
        self.stats = CascadeStats()

    async def run(self, event: SecurityEvent, payload: bytes | None) -> CascadeResult:
        self.stats.total += 1
        dets: list[Detection] = []
        for d in self._t0:
            dets.extend(d.inspect(event, payload))
        for d in self._t1:
            dets.extend(d.inspect(event, payload))
        escalated = False
        if self._escalate(dets):
            self.stats.tier2_invocations += 1
            extra = await self._clf.classify(event, payload)
            escalated = True
            if extra is not None:
                dets.append(extra)
        return CascadeResult(detections=dets, escalated=escalated)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/detect/test_cascade.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/agentwall/detect/cascade.py tests/detect/test_cascade.py
git commit -m "feat: detection cascade orchestrator with tier-2 accounting"
```

---

## Task 11: Policy engine

**Files:**
- Create: `src/agentwall/policy/__init__.py`, `src/agentwall/policy/engine.py`, `src/agentwall/policy/default_policy.yaml`
- Test: `tests/policy/__init__.py`, `tests/policy/test_engine.py`

**Interfaces:**
- Consumes: `SecurityEvent` (3), `Detection`/`Verdict` (6).
- Produces:
  - `class Decision(BaseModel)`: `verdict: Verdict`, `matched_rule: str | None`, `explanation: str`, `downgraded: bool = False`.
  - `class PolicyEngine(rules: list[dict], capabilities: set[str])`; classmethod `.from_yaml(path, capabilities) -> PolicyEngine`.
  - `.evaluate(event, detections, in_chain: bool) -> Decision` — first matching rule wins. A rule matches when every present matcher matches: `match.classification_prefix` (any detection's classification startswith it), `match.source` (equals `event.source`), `match.in_chain` (bool equals `in_chain`). Rule's `action` maps to a `Verdict`. If the resulting verdict needs a capability the adapter lacks (`BLOCK`→`"block"`, `QUARANTINE`→`"quarantine"`), downgrade to `WARN`, set `downgraded=True`, and note it in `explanation`. No rule matches → `Decision(ALLOW, None, "no rule matched")`.

- [ ] **Step 1: Author the default policy**

```yaml
# src/agentwall/policy/default_policy.yaml
rules:
  - name: block-secret-egress
    match: { classification_prefix: "secret:", source: "egress" }
    action: BLOCK
  - name: quarantine-exfil-chain
    match: { in_chain: true }
    action: QUARANTINE
  - name: warn-sensitive-access
    match: { classification_prefix: "sensitive_path_access" }
    action: WARN
  - name: warn-pii-egress
    match: { classification_prefix: "pii:", source: "egress" }
    action: WARN
```

- [ ] **Step 2: Write the failing test**

```python
# tests/policy/test_engine.py
from pathlib import Path

from agentwall.detect.model import Detection, Verdict
from agentwall.events import new_event
from agentwall.policy.engine import PolicyEngine

POLICY = Path("src/agentwall/policy/default_policy.yaml")


def _egress():
    return new_event(event_type="network_upload", session_id="s", source="egress", ts=1.0)


def test_secret_egress_blocks_when_capable():
    pe = PolicyEngine.from_yaml(POLICY, capabilities={"block", "quarantine"})
    d = pe.evaluate(_egress(), [Detection(tier=1, classification="secret:aws", confidence=0.9)], in_chain=False)
    assert d.verdict is Verdict.BLOCK and d.matched_rule == "block-secret-egress"


def test_block_downgrades_without_capability():
    pe = PolicyEngine.from_yaml(POLICY, capabilities=set())
    d = pe.evaluate(_egress(), [Detection(tier=1, classification="secret:aws", confidence=0.9)], in_chain=False)
    assert d.verdict is Verdict.WARN and d.downgraded is True


def test_chain_quarantines():
    pe = PolicyEngine.from_yaml(POLICY, capabilities={"quarantine"})
    d = pe.evaluate(_egress(), [], in_chain=True)
    assert d.verdict is Verdict.QUARANTINE


def test_no_match_allows():
    pe = PolicyEngine.from_yaml(POLICY, capabilities={"block"})
    d = pe.evaluate(_egress(), [], in_chain=False)
    assert d.verdict is Verdict.ALLOW and d.matched_rule is None
```

- [ ] **Step 3: Run test to verify it fails**

Run: `uv run pytest tests/policy/test_engine.py -v`
Expected: FAIL with import error.

- [ ] **Step 4: Add pyyaml and write the implementation**

Run: `uv add pyyaml`

```python
# src/agentwall/policy/engine.py
from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel

from agentwall.detect.model import Detection, Verdict
from agentwall.events import SecurityEvent

_CAP_FOR = {Verdict.BLOCK: "block", Verdict.QUARANTINE: "quarantine"}


class Decision(BaseModel):
    verdict: Verdict
    matched_rule: str | None
    explanation: str
    downgraded: bool = False


class PolicyEngine:
    def __init__(self, rules: list[dict], capabilities: set[str]) -> None:
        self._rules = rules
        self._caps = capabilities

    @classmethod
    def from_yaml(cls, path: str | Path, capabilities: set[str]) -> "PolicyEngine":
        doc = yaml.safe_load(Path(path).read_text()) or {}
        return cls(doc.get("rules", []), capabilities)

    def _matches(self, match: dict, event: SecurityEvent, detections: list[Detection], in_chain: bool) -> bool:
        if "classification_prefix" in match:
            pref = match["classification_prefix"]
            if not any(d.classification.startswith(pref) for d in detections):
                return False
        if "source" in match and match["source"] != event.source:
            return False
        if "in_chain" in match and bool(match["in_chain"]) != in_chain:
            return False
        return True

    def evaluate(self, event: SecurityEvent, detections: list[Detection], in_chain: bool) -> Decision:
        for rule in self._rules:
            if self._matches(rule.get("match", {}), event, detections, in_chain):
                verdict = Verdict[rule["action"]]
                need = _CAP_FOR.get(verdict)
                if need and need not in self._caps:
                    return Decision(verdict=Verdict.WARN, matched_rule=rule["name"],
                                    explanation=f"{verdict.name} downgraded to WARN: adapter lacks '{need}'",
                                    downgraded=True)
                return Decision(verdict=verdict, matched_rule=rule["name"],
                                explanation=f"matched rule '{rule['name']}'")
        return Decision(verdict=Verdict.ALLOW, matched_rule=None, explanation="no rule matched")
```

Create empty `src/agentwall/policy/__init__.py` and `tests/policy/__init__.py`.

- [ ] **Step 5: Run test to verify it passes**

Run: `uv run pytest tests/policy/test_engine.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/agentwall/policy tests/policy pyproject.toml
git commit -m "feat: capability-gated YAML policy engine"
```

---

## Task 12: Provenance — taint store and chain correlator

**Files:**
- Create: `src/agentwall/provenance.py`
- Test: `tests/test_provenance.py`

**Interfaces:**
- Consumes: `SecurityEvent` (3).
- Produces:
  - `class Chain(BaseModel)`: `session_id: str`, `steps: list[str]` (human-readable), `event_ids: list[str]`.
  - `class ChainCorrelator(window_s: float = 120.0)`.
  - `.observe(event: SecurityEvent) -> Chain | None` — maintains per-session state. Recognizes the ordered pattern within `window_s`:
    1. **untrusted-source**: an event with `trust == "tainted"` OR `attrs.get("untrusted_source")` truthy (records source label);
    2. **sensitive-access**: a `workspace` event with `attrs.get("sensitive")` truthy OR `event_type in {"file_read","file_write"}` and `attrs.get("path")` present after step 1;
    3. **egress**: a `source == "egress"` event.
    When step 3 completes a sequence whose step-1 timestamp is within `window_s` of step 3, returns a `Chain`; otherwise `None`. State resets after emitting a chain.
  - Helper `def is_untrusted(event) -> bool` (module-level).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_provenance.py
from agentwall.events import new_event
from agentwall.provenance import ChainCorrelator


def _e(source, ts, **attrs):
    trust = attrs.pop("trust", "trusted")
    et = attrs.pop("event_type", "x")
    return new_event(event_type=et, session_id="s", source=source, ts=ts, trust=trust, attrs=attrs)


def test_full_chain_detected():
    c = ChainCorrelator(window_s=120)
    assert c.observe(_e("workspace", 1.0, untrusted_source="evil.example/README")) is None
    assert c.observe(_e("workspace", 2.0, event_type="file_read", path="/w/.env", sensitive=True)) is None
    chain = c.observe(_e("egress", 3.0, destination="first-seen.xyz", size=4_000_000))
    assert chain is not None
    assert len(chain.steps) == 3 and chain.session_id == "s"


def test_no_chain_when_egress_without_precursors():
    c = ChainCorrelator()
    assert c.observe(_e("egress", 1.0, destination="x")) is None


def test_window_expiry_breaks_chain():
    c = ChainCorrelator(window_s=10)
    c.observe(_e("workspace", 1.0, untrusted_source="evil"))
    c.observe(_e("workspace", 2.0, event_type="file_read", path="/w/.env", sensitive=True))
    assert c.observe(_e("egress", 100.0, destination="x")) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_provenance.py -v`
Expected: FAIL with import error.

- [ ] **Step 3: Write minimal implementation**

```python
# src/agentwall/provenance.py
from __future__ import annotations

from dataclasses import dataclass, field

from pydantic import BaseModel

from agentwall.events import SecurityEvent


class Chain(BaseModel):
    session_id: str
    steps: list[str]
    event_ids: list[str]


def is_untrusted(event: SecurityEvent) -> bool:
    return event.trust == "tainted" or bool(event.attrs.get("untrusted_source"))


@dataclass
class _State:
    tainted_at: float | None = None
    steps: list[str] = field(default_factory=list)
    ids: list[str] = field(default_factory=list)
    sensitive_seen: bool = False


class ChainCorrelator:
    def __init__(self, window_s: float = 120.0) -> None:
        self._w = window_s
        self._states: dict[str, _State] = {}

    def observe(self, event: SecurityEvent) -> Chain | None:
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
                or (event.event_type in {"file_read", "file_write"}
                    and event.attrs.get("path"))
            )
            if sensitive:
                st.sensitive_seen = True
                st.steps.append(f"sensitive-access: {event.attrs.get('path', '?')}")
                st.ids.append(event.event_id)
                return None

        if event.source == "egress" and st.tainted_at is not None and st.sensitive_seen:
            if event.ts - st.tainted_at <= self._w:
                st.steps.append(f"egress: {event.attrs.get('destination', '?')}")
                st.ids.append(event.event_id)
                chain = Chain(session_id=event.session_id, steps=list(st.steps), event_ids=list(st.ids))
                self._states[event.session_id] = _State()
                return chain
            self._states[event.session_id] = _State()
        return None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_provenance.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/agentwall/provenance.py tests/test_provenance.py
git commit -m "feat: source-scoped taint chain correlator"
```

---

## Task 13: Runtime adapter interface + Docker Sandbox adapter

**Files:**
- Create: `src/agentwall/adapters/__init__.py`, `src/agentwall/adapters/base.py`, `src/agentwall/adapters/docker_sandbox.py`
- Test: `tests/adapters/__init__.py`, `tests/adapters/test_docker_sandbox.py`

**Interfaces:**
- Consumes: nothing from earlier tasks (pure interface + subprocess).
- Produces:
  - `class RuntimeAdapter(Protocol)`: `def capabilities(self) -> set[str]`; `def resolve_workspace_path(self) -> Path`; `def quarantine(self, session_id: str) -> bool`.
  - `class DockerSandboxAdapter(workspace: Path, sbx_binary: str = "sbx")`.
    - `.capabilities()` → `{"observe", "quarantine"}` in v0 (no inline `"block"` until the TLS spike + egress land). This is the honest v0 capability set.
    - `.resolve_workspace_path()` → the configured workspace path (passthrough mount is identical host/VM).
    - `.quarantine(session_id)` → runs `sbx stop <session_id>` via subprocess; returns True on exit 0, False otherwise (fail-safe, never raises).

- [ ] **Step 1: Write the failing test**

```python
# tests/adapters/test_docker_sandbox.py
from pathlib import Path

from agentwall.adapters.docker_sandbox import DockerSandboxAdapter


def test_capabilities_are_honest_for_v0(tmp_path):
    a = DockerSandboxAdapter(workspace=tmp_path)
    caps = a.capabilities()
    assert "quarantine" in caps and "observe" in caps
    assert "block" not in caps  # no inline egress block until v1


def test_resolve_workspace(tmp_path):
    a = DockerSandboxAdapter(workspace=tmp_path)
    assert a.resolve_workspace_path() == Path(tmp_path)


def test_quarantine_missing_binary_is_fail_safe(tmp_path):
    a = DockerSandboxAdapter(workspace=tmp_path, sbx_binary="not-a-real-sbx-xyz")
    assert a.quarantine("session-1") is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/adapters/test_docker_sandbox.py -v`
Expected: FAIL with import error.

- [ ] **Step 3: Write minimal implementation**

```python
# src/agentwall/adapters/base.py
from __future__ import annotations

from pathlib import Path
from typing import Protocol


class RuntimeAdapter(Protocol):
    def capabilities(self) -> set[str]: ...
    def resolve_workspace_path(self) -> Path: ...
    def quarantine(self, session_id: str) -> bool: ...
```

```python
# src/agentwall/adapters/docker_sandbox.py
from __future__ import annotations

import subprocess
from pathlib import Path


class DockerSandboxAdapter:
    def __init__(self, workspace: Path, sbx_binary: str = "sbx") -> None:
        self._workspace = Path(workspace)
        self._sbx = sbx_binary

    def capabilities(self) -> set[str]:
        return {"observe", "quarantine"}

    def resolve_workspace_path(self) -> Path:
        return self._workspace

    def quarantine(self, session_id: str) -> bool:
        try:
            r = subprocess.run([self._sbx, "stop", session_id], capture_output=True, timeout=10, check=False)
            return r.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
```

Create empty `src/agentwall/adapters/__init__.py` and `tests/adapters/__init__.py`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/adapters/test_docker_sandbox.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/agentwall/adapters tests/adapters
git commit -m "feat: RuntimeAdapter interface and Docker Sandbox adapter (v0 caps)"
```

---

## Task 14: WorkspaceSensor

**Files:**
- Create: `src/agentwall/sensors/__init__.py`, `src/agentwall/sensors/base.py`, `src/agentwall/sensors/workspace.py`
- Test: `tests/sensors/__init__.py`, `tests/sensors/test_workspace.py`

**Interfaces:**
- Consumes: `SecurityEvent`/`new_event` (3), `EventBus` (5).
- Produces:
  - `class RuntimeSensor(Protocol)`: `async def run(self, bus) -> None`; `def stop(self) -> None`.
  - `IMPLICIT_EXEC_PATTERNS: list[str]` (module constant): git hooks, `**/package.json`, `**/Makefile`, CI configs, `**/.claude/**`, IDE task configs.
  - `def classify_path(path: str) -> dict` — returns `attrs` additions: `{"implicit_exec": bool, "sensitive": bool, "skills_store": bool}`.
  - `class WorkspaceSensor(workspace: Path, session_id: str, skills_store: Path | None = None, clock: Callable[[], float] = time.time)`.
    - `def make_event(self, kind: str, path: str) -> SecurityEvent` — builds a `workspace`-source event, `event_type=kind` (`"file_write"`/`"file_read"`), merges `classify_path` into `attrs`, sets `trust="tainted"` when path is inside `skills_store` (cross-sandbox writable store is treated as untrusted), and `content_hash` when the file is readable.
    - `async def run(bus)` — starts a watchdog observer translating filesystem events into `bus.publish(self.make_event(...))`. `stop()` halts it.

The v0 tests exercise `classify_path` and `make_event` directly (deterministic); the live watchdog loop is smoke-tested with a real temp-dir write.

- [ ] **Step 1: Write the failing test**

```python
# tests/sensors/test_workspace.py
import asyncio
from pathlib import Path

from agentwall.bus import EventBus
from agentwall.sensors.workspace import WorkspaceSensor, classify_path
from agentwall.storage import EventStore


def test_classify_path_flags():
    assert classify_path("/w/.git/hooks/post-commit")["implicit_exec"] is True
    assert classify_path("/w/package.json")["implicit_exec"] is True
    assert classify_path("/w/.env")["sensitive"] is True
    assert classify_path("/w/src/main.py")["implicit_exec"] is False


def test_make_event_taints_skills_store(tmp_path):
    skills = tmp_path / "skills"
    skills.mkdir()
    sensor = WorkspaceSensor(workspace=tmp_path, session_id="s", skills_store=skills)
    e = sensor.make_event("file_write", str(skills / "evil.sh"))
    assert e.trust == "tainted" and e.source == "workspace"


def test_make_event_normal_file_trusted(tmp_path):
    sensor = WorkspaceSensor(workspace=tmp_path, session_id="s")
    f = tmp_path / "README.md"
    f.write_text("hi")
    e = sensor.make_event("file_write", str(f))
    assert e.trust == "trusted" and e.content_hash is not None


async def test_live_watch_emits_event(tmp_path):
    store = EventStore(tmp_path / "ev.db")
    bus = EventBus(store)
    seen = []
    bus.subscribe(lambda ev: _collect(seen, ev))
    sensor = WorkspaceSensor(workspace=tmp_path, session_id="s")
    task = asyncio.create_task(sensor.run(bus))
    await asyncio.sleep(0.3)
    (tmp_path / "touched.txt").write_text("x")
    await asyncio.sleep(0.5)
    sensor.stop()
    await task
    assert any(e.source == "workspace" for e in seen)


async def _collect(sink, e):
    sink.append(e)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/sensors/test_workspace.py -v`
Expected: FAIL with import error.

- [ ] **Step 3: Write minimal implementation**

```python
# src/agentwall/sensors/base.py
from __future__ import annotations

from typing import Protocol


class RuntimeSensor(Protocol):
    async def run(self, bus) -> None: ...
    def stop(self) -> None: ...
```

```python
# src/agentwall/sensors/workspace.py
from __future__ import annotations

import asyncio
import time
from fnmatch import fnmatch
from pathlib import Path
from typing import Callable

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from agentwall.events import SecurityEvent, content_hash, new_event

IMPLICIT_EXEC_PATTERNS = [
    "**/.git/hooks/*", "**/package.json", "**/Makefile",
    "**/.github/workflows/*", "**/.claude/**", "**/.vscode/tasks.json",
]
SENSITIVE_PATTERNS = ["**/.env", "**/.env.*", "**/.ssh/*", "**/.aws/*", "**/.npmrc"]


def _match_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch(path, p) for p in patterns)


def classify_path(path: str) -> dict:
    return {
        "implicit_exec": _match_any(path, IMPLICIT_EXEC_PATTERNS),
        "sensitive": _match_any(path, SENSITIVE_PATTERNS),
        "skills_store": False,
    }


class _Handler(FileSystemEventHandler):
    def __init__(self, sensor: "WorkspaceSensor", bus, loop) -> None:
        self._s = sensor
        self._bus = bus
        self._loop = loop

    def on_modified(self, event):
        if event.is_directory:
            return
        ev = self._s.make_event("file_write", event.src_path)
        asyncio.run_coroutine_threadsafe(self._bus.publish(ev), self._loop)

    on_created = on_modified


class WorkspaceSensor:
    def __init__(self, workspace: Path, session_id: str, skills_store: Path | None = None,
                 clock: Callable[[], float] = time.time) -> None:
        self._workspace = Path(workspace)
        self._session = session_id
        self._skills = Path(skills_store) if skills_store else None
        self._clock = clock
        self._observer: Observer | None = None

    def make_event(self, kind: str, path: str) -> SecurityEvent:
        attrs = {"path": path, **classify_path(path)}
        trust = "trusted"
        skills = self._skills.resolve() if self._skills else None
        if skills is not None and Path(path).resolve().is_relative_to(skills):
            trust = "tainted"
            attrs["skills_store"] = True
        chash = None
        p = Path(path)
        if p.is_file():
            try:
                chash = content_hash(p.read_bytes())
            except OSError:
                chash = None
        return new_event(event_type=kind, session_id=self._session, source="workspace",
                         ts=self._clock(), trust=trust, content_hash=chash, attrs=attrs)

    async def run(self, bus) -> None:
        loop = asyncio.get_running_loop()
        self._observer = Observer()
        self._observer.schedule(_Handler(self, bus, loop), str(self._workspace), recursive=True)
        self._observer.start()
        while self._observer.is_alive():
            await asyncio.sleep(0.1)

    def stop(self) -> None:
        if self._observer:
            self._observer.stop()
            self._observer.join()
```

Create empty `src/agentwall/sensors/__init__.py` and `tests/sensors/__init__.py`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/sensors/test_workspace.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/agentwall/sensors tests/sensors
git commit -m "feat: WorkspaceSensor with implicit-exec + skills-store tainting"
```

---

## Task 15: Daemon wiring

**Files:**
- Create: `src/agentwall/daemon.py`
- Test: `tests/test_daemon.py`

**Interfaces:**
- Consumes: everything from Tasks 3–14.
- Produces:
  - `class DaemonConfig(BaseModel)`: `workspace: Path`, `session_id: str`, `db_path: Path`, `policy_path: Path`, `rules: RulesConfig`, `skills_store: Path | None = None`.
  - `class Daemon(config, adapter: RuntimeAdapter, classifier: SecurityClassifier | None = None)`.
    - Builds `EventStore`, `EventBus`, `Cascade` (Tier0 = `RulesDetector`, Tier1 = `GitleaksScanner` + `PresidioScanner`, classifier = provided or `NullClassifier`), `ChainCorrelator`, `PolicyEngine.from_yaml(policy_path, adapter.capabilities())`, `WorkspaceSensor`.
    - Subscribes an async `_on_event` handler that: loads payload via `store.get_blob(event.payload_ref)` if set else None; runs cascade; runs correlator; evaluates policy with `in_chain = chain is not None`; if `decision.verdict == QUARANTINE` calls `adapter.quarantine(session_id)`; records a `Decision` + optional `Chain` into an in-memory `self.decisions: list[tuple[SecurityEvent, Decision, Chain | None]]`.
    - `async def start() -> None` — replays unprocessed, launches sensor task.
    - `async def stop() -> None`.
    - `def health() -> dict` — `{"degraded": bool, "events": int, "tier2_rate": float, "capabilities": sorted(list)}`; `degraded` True if any Tier-1 scanner set `.degraded`.
    - `async def submit(event) -> None` — publish an event directly (used by corpus/tests to inject synthetic egress/mcp events).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_daemon.py
from pathlib import Path

from agentwall.adapters.docker_sandbox import DockerSandboxAdapter
from agentwall.daemon import Daemon, DaemonConfig
from agentwall.detect.model import Verdict
from agentwall.detect.tier0_rules import RulesConfig
from agentwall.events import new_event

POLICY = Path("src/agentwall/policy/default_policy.yaml")


def _config(tmp_path):
    return DaemonConfig(
        workspace=tmp_path, session_id="s", db_path=tmp_path / "ev.db", policy_path=POLICY,
        rules=RulesConfig(sensitive_path_globs=["**/.env"], denied_dest_domains=["evil.example"],
                          max_upload_bytes=1_000_000, entropy_threshold=7.5),
    )


async def test_daemon_processes_injected_chain(tmp_path):
    d = Daemon(_config(tmp_path), adapter=DockerSandboxAdapter(workspace=tmp_path))
    await d.submit(new_event(event_type="file_read", session_id="s", source="workspace", ts=1.0,
                             trust="tainted", attrs={"untrusted_source": "evil/README"}))
    await d.submit(new_event(event_type="file_read", session_id="s", source="workspace", ts=2.0,
                             attrs={"path": "/w/.env", "sensitive": True}))
    await d.submit(new_event(event_type="network_upload", session_id="s", source="egress", ts=3.0,
                             attrs={"destination": "first-seen.xyz", "size": 4_000_000}))
    verdicts = [dec.verdict for _, dec, _ in d.decisions]
    assert Verdict.QUARANTINE in verdicts


async def test_health_reports_capabilities(tmp_path):
    d = Daemon(_config(tmp_path), adapter=DockerSandboxAdapter(workspace=tmp_path))
    h = d.health()
    assert "quarantine" in h["capabilities"] and h["tier2_rate"] == 0.0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_daemon.py -v`
Expected: FAIL with import error.

- [ ] **Step 3: Write minimal implementation**

```python
# src/agentwall/daemon.py
from __future__ import annotations

import asyncio
from pathlib import Path

from pydantic import BaseModel

from agentwall.adapters.base import RuntimeAdapter
from agentwall.bus import EventBus
from agentwall.detect.cascade import Cascade, escalate_on_any
from agentwall.detect.model import NullClassifier, SecurityClassifier, Verdict
from agentwall.detect.tier0_rules import RulesConfig, RulesDetector
from agentwall.detect.tier1_gitleaks import GitleaksScanner
from agentwall.detect.tier1_presidio import PresidioScanner
from agentwall.events import SecurityEvent
from agentwall.policy.engine import Decision, PolicyEngine
from agentwall.provenance import Chain, ChainCorrelator
from agentwall.sensors.workspace import WorkspaceSensor
from agentwall.storage import EventStore


class DaemonConfig(BaseModel):
    workspace: Path
    session_id: str
    db_path: Path
    policy_path: Path
    rules: RulesConfig
    skills_store: Path | None = None


class Daemon:
    def __init__(self, config: DaemonConfig, adapter: RuntimeAdapter,
                 classifier: SecurityClassifier | None = None) -> None:
        self._cfg = config
        self._adapter = adapter
        self._store = EventStore(config.db_path)
        self._bus = EventBus(self._store)
        self._gitleaks = GitleaksScanner()
        self._presidio = PresidioScanner()
        self._cascade = Cascade(
            tier0=[RulesDetector(config.rules)],
            tier1=[self._gitleaks, self._presidio],
            classifier=classifier or NullClassifier(),
            escalate_when=escalate_on_any,
        )
        self._correlator = ChainCorrelator()
        self._policy = PolicyEngine.from_yaml(config.policy_path, adapter.capabilities())
        self._sensor = WorkspaceSensor(config.workspace, config.session_id, config.skills_store)
        self._sensor_task: asyncio.Task | None = None
        self.decisions: list[tuple[SecurityEvent, Decision, Chain | None]] = []
        self._bus.subscribe(self._on_event)

    async def _on_event(self, event: SecurityEvent) -> None:
        payload = self._store.get_blob(event.payload_ref) if event.payload_ref else None
        result = await self._cascade.run(event, payload)
        chain = self._correlator.observe(event)
        decision = self._policy.evaluate(event, result.detections, in_chain=chain is not None)
        if decision.verdict == Verdict.QUARANTINE and "quarantine" in self._adapter.capabilities():
            self._adapter.quarantine(self._cfg.session_id)
        self.decisions.append((event, decision, chain))

    async def submit(self, event: SecurityEvent) -> None:
        await self._bus.publish(event)

    async def start(self) -> None:
        await self._bus.replay_unprocessed()
        self._sensor_task = asyncio.create_task(self._sensor.run(self._bus))

    async def stop(self) -> None:
        self._sensor.stop()
        if self._sensor_task:
            await self._sensor_task
        self._store.close()

    def health(self) -> dict:
        return {
            "degraded": self._gitleaks.degraded or self._presidio.degraded,
            "events": self._cascade.stats.total,
            "tier2_rate": self._cascade.stats.tier2_rate,
            "capabilities": sorted(self._adapter.capabilities()),
        }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_daemon.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/agentwall/daemon.py tests/test_daemon.py
git commit -m "feat: daemon wiring — cascade, policy, provenance, enforcement"
```

---

## Task 16: CLI

**Files:**
- Create: `src/agentwall/cli.py`
- Modify: `pyproject.toml` (add `[project.scripts]` entry `agentwall = "agentwall.cli:app"`)
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `Daemon`/`DaemonConfig` (15), `DockerSandboxAdapter` (13), `RulesConfig` (7), `EventStore` (4).
- Produces a Typer `app` with:
  - `agentwall status --db <path>` — prints event count and dead-letter count from the store.
  - `agentwall replay --db <path> --session <id>` — prints reconstructed chains from stored events by re-running `ChainCorrelator` over `store.all_events()` filtered by session; each chain printed as arrowed steps.
  - `agentwall policy --policy <path>` — prints the loaded rule names and actions.
  - `agentwall run --workspace <path> --session <id> --db <path> --policy <path>` — builds a `Daemon` and runs until Ctrl-C (smoke-only; tested via `--check` flag that builds the daemon, prints health, and exits 0 without entering the watch loop).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cli.py
from pathlib import Path

from typer.testing import CliRunner

from agentwall.cli import app

runner = CliRunner()
POLICY = Path("src/agentwall/policy/default_policy.yaml")


def test_policy_lists_rules():
    r = runner.invoke(app, ["policy", "--policy", str(POLICY)])
    assert r.exit_code == 0 and "block-secret-egress" in r.stdout


def test_status_on_empty_db(tmp_path):
    r = runner.invoke(app, ["status", "--db", str(tmp_path / "ev.db")])
    assert r.exit_code == 0 and "events: 0" in r.stdout


def test_run_check_prints_health(tmp_path):
    r = runner.invoke(app, ["run", "--workspace", str(tmp_path), "--session", "s",
                            "--db", str(tmp_path / "ev.db"), "--policy", str(POLICY), "--check"])
    assert r.exit_code == 0 and "capabilities" in r.stdout
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cli.py -v`
Expected: FAIL with import error.

- [ ] **Step 3: Write minimal implementation**

```python
# src/agentwall/cli.py
from __future__ import annotations

from pathlib import Path

import typer
import yaml

from agentwall.adapters.docker_sandbox import DockerSandboxAdapter
from agentwall.daemon import Daemon, DaemonConfig
from agentwall.detect.tier0_rules import RulesConfig
from agentwall.provenance import ChainCorrelator
from agentwall.storage import EventStore

app = typer.Typer(help="AgentWall — runtime security plane for AI coding agents")

_DEFAULT_RULES = RulesConfig(
    sensitive_path_globs=["**/.env", "**/.env.*", "**/.ssh/*", "**/.aws/*"],
    denied_dest_domains=[], max_upload_bytes=5_000_000, entropy_threshold=7.5,
)


@app.command()
def status(db: Path = typer.Option(...)) -> None:
    store = EventStore(db)
    typer.echo(f"events: {len(store.all_events())}")
    typer.echo(f"dead_letters: {len(store.dead_letters())}")
    store.close()


@app.command()
def replay(db: Path = typer.Option(...), session: str = typer.Option(...)) -> None:
    store = EventStore(db)
    corr = ChainCorrelator()
    for e in store.all_events():
        if e.session_id != session:
            continue
        chain = corr.observe(e)
        if chain:
            typer.echo(" -> ".join(chain.steps))
    store.close()


@app.command()
def policy(policy: Path = typer.Option(...)) -> None:
    doc = yaml.safe_load(Path(policy).read_text()) or {}
    for rule in doc.get("rules", []):
        typer.echo(f"{rule['name']}: {rule['action']}")


@app.command()
def run(workspace: Path = typer.Option(...), session: str = typer.Option(...),
        db: Path = typer.Option(...), policy: Path = typer.Option(...),
        check: bool = typer.Option(False, "--check")) -> None:
    cfg = DaemonConfig(workspace=workspace, session_id=session, db_path=db,
                       policy_path=policy, rules=_DEFAULT_RULES)
    daemon = Daemon(cfg, adapter=DockerSandboxAdapter(workspace=workspace))
    if check:
        typer.echo(str(daemon.health()))
        return
    import asyncio

    async def _serve():
        await daemon.start()
        try:
            while True:
                await asyncio.sleep(1)
        finally:
            await daemon.stop()

    asyncio.run(_serve())


if __name__ == "__main__":
    app()
```

- [ ] **Step 4: Add the console script and run tests**

Add to `pyproject.toml`:
```toml
[project.scripts]
agentwall = "agentwall.cli:app"
```

Run: `uv run pytest tests/test_cli.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/agentwall/cli.py pyproject.toml tests/test_cli.py
git commit -m "feat: Typer CLI — status/replay/policy/run"
```

---

## Task 17: Attack corpus harness + rows 1–3, 9

**Files:**
- Create: `corpus/__init__.py`, `corpus/runner.py`, `corpus/scenario_01_readme_env_post.py`, `corpus/scenario_02_git_hook.py`, `corpus/scenario_03_package_json.py`, `corpus/scenario_09_benign_suite.py`
- Test: `tests/corpus/__init__.py`, `tests/corpus/test_scenarios.py`

**Interfaces:**
- Consumes: `Daemon`/`DaemonConfig` (15), `DockerSandboxAdapter` (13), `RulesConfig` (7), `new_event` (3), `Verdict` (6).
- Produces:
  - `class ScenarioResult(BaseModel)`: `name: str`, `verdicts: list[str]`, `chains: list[list[str]]`, `warned_or_worse: int`.
  - `async def run_scenario(events: list[SecurityEvent], tmp_path, rules) -> ScenarioResult` in `runner.py` — spins a `Daemon`, submits each event, collects verdicts + chains.
  - Each `scenario_XX` module exposes `def events() -> list[SecurityEvent]` and `EXPECT` dict describing the assertion (`{"min_verdict": "...", "expect_chain": bool}`).

- [ ] **Step 1: Write the failing test**

```python
# tests/corpus/test_scenarios.py
from pathlib import Path

import pytest

from corpus import runner, scenario_01_readme_env_post as s1
from corpus import scenario_02_git_hook as s2
from corpus import scenario_03_package_json as s3
from corpus import scenario_09_benign_suite as s9
from agentwall.detect.tier0_rules import RulesConfig

RULES = RulesConfig(sensitive_path_globs=["**/.env", "**/.ssh/*"],
                    denied_dest_domains=["evil.example"], max_upload_bytes=1_000_000,
                    entropy_threshold=7.5)


async def test_row1_readme_env_post_quarantines(tmp_path):
    res = await runner.run_scenario(s1.events(), tmp_path, RULES)
    assert "QUARANTINE" in res.verdicts and res.chains


async def test_row2_git_hook_flagged(tmp_path):
    res = await runner.run_scenario(s2.events(), tmp_path, RULES)
    assert res.warned_or_worse >= 1


async def test_row3_package_json_flagged(tmp_path):
    res = await runner.run_scenario(s3.events(), tmp_path, RULES)
    assert res.warned_or_worse >= 1


async def test_row9_benign_is_silent(tmp_path):
    res = await runner.run_scenario(s9.events(), tmp_path, RULES)
    assert res.warned_or_worse == 0  # FP budget: benign session stays quiet
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/corpus/test_scenarios.py -v`
Expected: FAIL with import error.

- [ ] **Step 3: Write the runner and scenarios**

```python
# corpus/runner.py
from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel

from agentwall.adapters.docker_sandbox import DockerSandboxAdapter
from agentwall.daemon import Daemon, DaemonConfig
from agentwall.detect.model import Verdict
from agentwall.detect.tier0_rules import RulesConfig
from agentwall.events import SecurityEvent

_POLICY = Path("src/agentwall/policy/default_policy.yaml")


class ScenarioResult(BaseModel):
    name: str
    verdicts: list[str]
    chains: list[list[str]]
    warned_or_worse: int


async def run_scenario(events: list[SecurityEvent], tmp_path: Path, rules: RulesConfig,
                       name: str = "scenario") -> ScenarioResult:
    cfg = DaemonConfig(workspace=tmp_path, session_id=events[0].session_id if events else "s",
                       db_path=tmp_path / "ev.db", policy_path=_POLICY, rules=rules)
    d = Daemon(cfg, adapter=DockerSandboxAdapter(workspace=tmp_path))
    for e in events:
        await d.submit(e)
    verdicts = [dec.verdict.name for _, dec, _ in d.decisions]
    chains = [c.steps for _, _, c in d.decisions if c is not None]
    warned = sum(1 for _, dec, _ in d.decisions if dec.verdict >= Verdict.WARN)
    await d.stop()
    return ScenarioResult(name=name, verdicts=verdicts, chains=chains, warned_or_worse=warned)
```

```python
# corpus/scenario_01_readme_env_post.py
from agentwall.events import SecurityEvent, new_event

EXPECT = {"min_verdict": "QUARANTINE", "expect_chain": True}


def events() -> list[SecurityEvent]:
    return [
        new_event(event_type="file_read", session_id="s1", source="workspace", ts=1.0,
                  trust="tainted", attrs={"untrusted_source": "evil.example/README.md"}),
        new_event(event_type="file_read", session_id="s1", source="workspace", ts=2.0,
                  attrs={"path": "/w/.env", "sensitive": True}),
        new_event(event_type="network_upload", session_id="s1", source="egress", ts=3.0,
                  attrs={"destination": "first-seen.xyz", "size": 4_000_000}),
    ]
```

```python
# corpus/scenario_02_git_hook.py
from agentwall.events import SecurityEvent, new_event

EXPECT = {"min_verdict": "WARN", "expect_chain": False}


def events() -> list[SecurityEvent]:
    # Injection causes the agent to write an executable git hook (implicit-exec file).
    return [
        new_event(event_type="file_write", session_id="s2", source="workspace", ts=1.0,
                  attrs={"path": "/w/.git/hooks/post-commit", "implicit_exec": True,
                         "sensitive": True}),
    ]
```

```python
# corpus/scenario_03_package_json.py
from agentwall.events import SecurityEvent, new_event

EXPECT = {"min_verdict": "WARN", "expect_chain": False}


def events() -> list[SecurityEvent]:
    # Injected postinstall script added to package.json (implicit-exec file).
    return [
        new_event(event_type="file_write", session_id="s3", source="workspace", ts=1.0,
                  attrs={"path": "/w/package.json", "implicit_exec": True, "sensitive": True}),
    ]
```

```python
# corpus/scenario_09_benign_suite.py
from agentwall.events import SecurityEvent, new_event

EXPECT = {"min_verdict": "ALLOW", "expect_chain": False}


def events() -> list[SecurityEvent]:
    # Ordinary coding session: editing source, reading a normal README, a git push.
    return [
        new_event(event_type="file_write", session_id="s9", source="workspace", ts=1.0,
                  attrs={"path": "/w/src/main.py"}),
        new_event(event_type="file_read", session_id="s9", source="workspace", ts=2.0,
                  attrs={"path": "/w/README.md"}),
        new_event(event_type="network_upload", session_id="s9", source="egress", ts=3.0,
                  attrs={"destination": "github.com", "size": 20_000}),
    ]
```

Note the `sensitive: True` on rows 2 and 3: the git-hook and package.json paths must map to a policy hit. Confirm `default_policy.yaml`'s `warn-sensitive-access` rule fires on `sensitive_path_access`. Because these events set `attrs.sensitive` but not a matching `RulesConfig.sensitive_path_globs` entry, add `**/.git/hooks/*` and `**/package.json` to the scenario's `RULES.sensitive_path_globs` in the test, OR rely on Tier 0 `classify`-style detection. To keep Task 17 self-contained, update the test's `RULES` to include those globs:

```python
RULES = RulesConfig(
    sensitive_path_globs=["**/.env", "**/.ssh/*", "**/.git/hooks/*", "**/package.json"],
    denied_dest_domains=["evil.example"], max_upload_bytes=1_000_000, entropy_threshold=7.5)
```

Create empty `corpus/__init__.py` and `tests/corpus/__init__.py`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/corpus/test_scenarios.py -v`
Expected: PASS (all four rows)

- [ ] **Step 5: Commit**

```bash
git add corpus tests/corpus
git commit -m "feat: attack corpus harness + rows 1-3 and benign row 9"
```

---

## Task 18: Benchmark harness

**Files:**
- Create: `bench/run_bench.py`
- Test: `tests/test_bench.py`

**Interfaces:**
- Consumes: `Daemon`/`DaemonConfig` (15), `DockerSandboxAdapter` (13), `RulesConfig` (7), `new_event` (3).
- Produces:
  - `class BenchResult(BaseModel)`: `events: int`, `p50_ms: float`, `p95_ms: float`, `p99_ms: float`, `tier2_rate: float`.
  - `async def run_bench(n: int, tmp_path) -> BenchResult` — submits `n` benign workspace events, times each `submit`, computes percentiles from per-event latencies, reads `tier2_rate` from health.
  - `def assert_targets(res: BenchResult) -> None` — raises `AssertionError` if `p95_ms >= 10.0` or `tier2_rate >= 0.02` (the §6 non-functional targets). Note: with `NullClassifier` and benign events that produce no detections, tier2_rate is 0 and p95 is dominated by Tier-1 subprocess/spaCy load — so benign events must NOT escalate. The bench uses events with no `path`/`destination`/`payload` so Tier 0/1 stay silent and no escalation occurs, isolating pure pipeline overhead.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bench.py
from bench.run_bench import assert_targets, run_bench


async def test_bench_meets_latency_and_tier2_targets(tmp_path):
    res = await run_bench(n=200, tmp_path=tmp_path)
    assert res.events == 200
    assert res.tier2_rate < 0.02
    assert_targets(res)  # raises if p95 >= 10ms or tier2 >= 2%
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_bench.py -v`
Expected: FAIL with import error.

- [ ] **Step 3: Write minimal implementation**

```python
# bench/run_bench.py
from __future__ import annotations

import time
from pathlib import Path
from statistics import quantiles

from pydantic import BaseModel

from agentwall.adapters.docker_sandbox import DockerSandboxAdapter
from agentwall.daemon import Daemon, DaemonConfig
from agentwall.detect.tier0_rules import RulesConfig
from agentwall.events import new_event

_POLICY = Path("src/agentwall/policy/default_policy.yaml")
_RULES = RulesConfig(sensitive_path_globs=["**/.env"], denied_dest_domains=[],
                     max_upload_bytes=5_000_000, entropy_threshold=7.5)


class BenchResult(BaseModel):
    events: int
    p50_ms: float
    p95_ms: float
    p99_ms: float
    tier2_rate: float


def _pct(latencies_ms: list[float], p: float) -> float:
    if len(latencies_ms) < 2:
        return latencies_ms[0] if latencies_ms else 0.0
    return quantiles(latencies_ms, n=100)[min(int(p) - 1, 98)]


async def run_bench(n: int, tmp_path: Path) -> BenchResult:
    cfg = DaemonConfig(workspace=tmp_path, session_id="bench", db_path=tmp_path / "ev.db",
                       policy_path=_POLICY, rules=_RULES)
    d = Daemon(cfg, adapter=DockerSandboxAdapter(workspace=tmp_path))
    lat: list[float] = []
    for i in range(n):
        # benign, detail-free event → no detections → no escalation → pure overhead
        e = new_event(event_type="noop", session_id="bench", source="workspace", ts=float(i), attrs={})
        t0 = time.perf_counter()
        await d.submit(e)
        lat.append((time.perf_counter() - t0) * 1000)
    health = d.health()
    await d.stop()
    return BenchResult(events=n, p50_ms=_pct(lat, 50), p95_ms=_pct(lat, 95),
                       p99_ms=_pct(lat, 99), tier2_rate=health["tier2_rate"])


def assert_targets(res: BenchResult) -> None:
    assert res.p95_ms < 10.0, f"p95 {res.p95_ms:.2f}ms exceeds 10ms target"
    assert res.tier2_rate < 0.02, f"tier2 rate {res.tier2_rate:.3f} exceeds 2% target"


if __name__ == "__main__":
    import asyncio
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        r = asyncio.run(run_bench(1000, Path(d)))
        print(r.model_dump_json(indent=2))
```

Note: a `noop` event with empty attrs still passes through `RulesDetector` (no match), both Tier-1 scanners (payload is None → both return `[]` immediately without invoking subprocess/spaCy), and `escalate_on_any([])` is False → no classifier call. This isolates pipeline overhead as intended.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_bench.py -v`
Expected: PASS

If p95 exceeds 10ms because of SQLite `commit()` per event, that is a real finding — record it and, if needed, batch commits in `EventStore.append` behind a `commit=True` flag. Do not loosen the assertion.

- [ ] **Step 5: Commit**

```bash
git add bench/run_bench.py tests/test_bench.py
git commit -m "feat: benchmark harness enforcing latency + tier-2 targets"
```

---

## Task 19: Full-suite green + README numbers

**Files:**
- Create/Modify: `README.md`

**Interfaces:**
- Consumes: all prior tasks.
- Produces: a README documenting what v0 does, how to run it, and the measured benchmark numbers (§6 requires numbers published, not claimed).

- [ ] **Step 1: Run the entire suite**

Run: `uv run pytest -v`
Expected: all tests pass (Presidio/gitleaks tests skip only if those tools are unavailable — they should be installed by Tasks 8–9).

- [ ] **Step 2: Capture real benchmark numbers**

Run: `uv run python -m bench.run_bench`
Copy the printed JSON.

- [ ] **Step 3: Write the README**

Replace `README.md` with a description of AgentWall v0: the one-line positioning from the spec, the substrate-vs-competitor framing, a "what v0 detects" list mapping to corpus rows 1–3 & 9, quickstart (`uv run agentwall run --check ...`), and a **Benchmarks** section pasting the real JSON from Step 2 with the host machine described.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: v0 README with measured benchmarks"
```

---

## Self-Review (completed during authoring)

**Spec coverage check** against `2026-08-13-agentwall-design.md`:

- §4 daemon/event bus/SQLite → Tasks 4, 5, 15 ✓
- §4.1 WorkspaceSensor (implicit-exec, skills store, sensitive paths) → Task 14 ✓
- §4.1 EgressSensor / MCPSensor / LifecycleSensor → **deferred to v1** (v0 scope note); corpus injects synthetic egress events (Task 17) ✓ (intentional gap, documented)
- §4.2 Tier 0 → Task 7; Tier 1 Gitleaks+Presidio → Tasks 8, 9; Tier 2 seam (`SecurityClassifier`/`NullClassifier`) → Task 6; cascade → Task 10 ✓
- §4.3 capability-gated YAML policy → Task 11 ✓
- §4.4 RuntimeAdapter + capability table → Task 13 ✓
- §5 event schema + source-scoped taint chains → Tasks 3, 12 ✓
- §6 non-functional targets (p95<10ms, tier2<2%) → Task 18 asserts them ✓
- §7 TLS spike → Task 2 ✓
- §8 corpus rows 1–3, 9 → Task 17 ✓ (rows 4–8 are v1, per §12)
- §9 unit + corpus/integration + benchmark + golden replay → Tasks 3–18; **golden-replay snapshotting deferred to v1** (replay command exists in Task 16; snapshot harness lands with the fuller corpus)
- §10 fail-safe degradation, dead-letter, restart replay → Tasks 5, 8, 9, 15 ✓
- §11 repo structure → matches File Structure above ✓
- §12 v0 roadmap items → all covered ✓

**Placeholder scan:** no TBD/TODO; every code step has real code. ✓

**Type consistency:** `SecurityEvent`, `Detection`, `Verdict`, `Decision`, `Chain`, `RulesConfig`, `Cascade`, `PolicyEngine`, `Daemon`, `DaemonConfig` names and signatures are consistent across Tasks 3–19. `escalate_on_any`, `content_hash`, `classify_path`, `shannon_entropy`, `is_untrusted` helper names consistent. ✓

**Intentional deferrals (documented, not gaps):** EgressSensor/MCPSensor/LifecycleSensor, corpus rows 4–8, golden-replay snapshots, Tier-2 SLM implementation — all v1 per the spec's phased roadmap.
