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


async def _collect(sink, e):
    sink.append(e)
