from __future__ import annotations

import sqlite3
import threading
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
        # check_same_thread=False: the watchdog observer and egress sensor call into
        # this store from worker threads, not just the asyncio event-loop thread. All
        # access is serialized through self._lock, so sharing the connection is safe.
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.Lock()
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def append(self, event: SecurityEvent) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO events (event_id, ts, processed, json) VALUES (?, ?, 0, ?)",
                (event.event_id, event.ts, event.model_dump_json()),
            )
            self._conn.commit()

    def mark_processed(self, event_id: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE events SET processed=1 WHERE event_id=?", (event_id,))
            self._conn.commit()

    def _rows_to_events(self, rows: list[tuple[str]]) -> list[SecurityEvent]:
        return [SecurityEvent.model_validate_json(r[0]) for r in rows]

    def unprocessed(self) -> list[SecurityEvent]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT json FROM events WHERE processed=0 ORDER BY rowid"
            ).fetchall()
        return self._rows_to_events(rows)

    def all_events(self) -> list[SecurityEvent]:
        with self._lock:
            rows = self._conn.execute("SELECT json FROM events ORDER BY rowid").fetchall()
        return self._rows_to_events(rows)

    def put_blob(self, data: bytes) -> str:
        with self._lock:
            cur = self._conn.execute("INSERT INTO blobs (data) VALUES (?)", (data,))
            self._conn.commit()
            return f"blob:{cur.lastrowid}"

    def get_blob(self, ref: str) -> bytes:
        rowid = int(ref.split(":", 1)[1])
        with self._lock:
            row = self._conn.execute("SELECT data FROM blobs WHERE rowid=?", (rowid,)).fetchone()
        return bytes(row[0])

    def dead_letter(self, raw: str, error: str) -> None:
        with self._lock:
            self._conn.execute("INSERT INTO dead_letters (raw, error) VALUES (?, ?)", (raw, error))
            self._conn.commit()

    def dead_letters(self) -> list[tuple[str, str]]:
        with self._lock:
            return self._conn.execute(
                "SELECT raw, error FROM dead_letters ORDER BY rowid"
            ).fetchall()

    def close(self) -> None:
        with self._lock:
            self._conn.close()
