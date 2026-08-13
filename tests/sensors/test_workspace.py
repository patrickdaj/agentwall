import asyncio
from pathlib import Path

import pytest

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


def test_sibling_prefix_dir_not_tainted(tmp_path):
    skills = tmp_path / "skills"
    skills.mkdir()
    sibling = tmp_path / "skills-evil"
    sibling.mkdir()
    sensor = WorkspaceSensor(workspace=tmp_path, session_id="s", skills_store=skills)
    e = sensor.make_event("file_write", str(sibling / "x.sh"))
    assert e.trust == "trusted"
    assert e.attrs.get("skills_store") in (False, None)


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


async def _collect(sink, e):
    sink.append(e)


@pytest.mark.asyncio
async def test_sensitive_write_stores_payload_via_real_observer(tmp_path):
    from agentwall.storage import EventStore
    from agentwall.bus import EventBus
    store = EventStore(tmp_path / "ev.db")
    bus = EventBus(store)
    events = []
    async def collect(ev):
        events.append(ev)
    bus.subscribe(collect)
    sensor = WorkspaceSensor(workspace=tmp_path, session_id="s", blob_put=store.put_blob)
    task = asyncio.create_task(sensor.run(bus))
    await asyncio.sleep(0.3)  # let the observer start
    (tmp_path / ".env").write_text("SECRET=abc")
    await asyncio.sleep(0.6)  # let the watchdog fire and the coroutine run
    sensor.stop()
    await task
    store.close()
    env_events = [e for e in events if e.attrs.get("path", "").endswith(".env")]
    assert env_events, "no .env write event observed"
    assert any(e.payload_ref is not None for e in env_events), "payload not stored from watchdog thread"
