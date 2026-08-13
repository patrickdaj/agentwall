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


def test_put_blob_from_another_thread(tmp_path):
    import threading
    store = EventStore(tmp_path / "ev.db")
    result = {}
    def worker():
        result["ref"] = store.put_blob(b"from-thread")
    t = threading.Thread(target=worker)
    t.start(); t.join()
    assert store.get_blob(result["ref"]) == b"from-thread"
    store.close()
