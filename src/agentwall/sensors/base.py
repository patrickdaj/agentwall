from __future__ import annotations

from typing import Protocol


class RuntimeSensor(Protocol):
    async def run(self, bus) -> None: ...
    def stop(self) -> None: ...
