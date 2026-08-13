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
