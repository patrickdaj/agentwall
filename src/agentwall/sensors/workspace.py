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
        inside_skills = skills is not None and Path(path).resolve().is_relative_to(skills)
        if inside_skills:
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
