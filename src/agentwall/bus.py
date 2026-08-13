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
