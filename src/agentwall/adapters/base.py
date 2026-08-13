from __future__ import annotations

from pathlib import Path
from typing import Protocol


class RuntimeAdapter(Protocol):
    def capabilities(self) -> set[str]: ...
    def resolve_workspace_path(self) -> Path: ...
    def quarantine(self, session_id: str) -> bool: ...
