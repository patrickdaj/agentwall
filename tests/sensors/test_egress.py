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
