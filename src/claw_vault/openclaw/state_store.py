"""Persist processing offsets for OpenClaw session transcript files."""

from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path

import structlog

logger = structlog.get_logger()


@dataclass
class SessionFileState:
    """Tracked processing state for one session transcript file."""

    path: str
    agent_id: str
    inode: int
    last_offset: int
    last_size: int
    last_mtime_ns: int
    updated_at: float
    last_error: str | None = None

    @property
    def file_path(self) -> Path:
        """Return the tracked path as a `Path`."""
        return Path(self.path)


class SessionStateStore:
    """JSON-backed state store for transcript offsets."""

    def __init__(self, state_file: Path) -> None:
        self._state_file = state_file.expanduser()
        self._lock = threading.Lock()
        self._items: dict[str, SessionFileState] = {}
        self._load()

    def get(self, path: Path) -> SessionFileState | None:
        """Return a copy of the current state for the given path."""
        key = str(path.expanduser())
        with self._lock:
            item = self._items.get(key)
            return None if item is None else SessionFileState(**asdict(item))

    def upsert(
        self,
        path: Path,
        agent_id: str,
        *,
        inode: int,
        last_offset: int,
        last_size: int,
        last_mtime_ns: int,
        last_error: str | None = None,
    ) -> SessionFileState:
        """Create or replace the tracked state for a transcript path."""
        item = SessionFileState(
            path=str(path.expanduser()),
            agent_id=agent_id,
            inode=inode,
            last_offset=last_offset,
            last_size=last_size,
            last_mtime_ns=last_mtime_ns,
            updated_at=time.time(),
            last_error=last_error,
        )
        with self._lock:
            self._items[item.path] = item
            self._persist()
            return SessionFileState(**asdict(item))

    def remove(self, path: Path) -> None:
        """Delete the tracked state for a transcript path if present."""
        key = str(path.expanduser())
        with self._lock:
            if key not in self._items:
                return
            del self._items[key]
            self._persist()

    def _load(self) -> None:
        if not self._state_file.exists():
            return

        try:
            payload = json.loads(self._state_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            logger.warning("openclaw_state_invalid", path=str(self._state_file))
            return

        sessions = payload.get("sessions")
        if not isinstance(sessions, list):
            return

        for raw_item in sessions:
            if not isinstance(raw_item, dict):
                continue
            try:
                item = SessionFileState(**raw_item)
            except TypeError:
                continue
            self._items[item.path] = item

    def _persist(self) -> None:
        self._state_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "sessions": [asdict(item) for item in self._items.values()],
        }
        self._state_file.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
