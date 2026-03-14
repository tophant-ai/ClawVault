"""File locking helpers for OpenClaw transcript mutation."""

from __future__ import annotations

import fcntl
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType

import structlog

logger = structlog.get_logger()


class FileLockError(RuntimeError):
    """Raised when a transcript lock cannot be acquired in time."""


@dataclass(frozen=True)
class LockMetadata:
    """Metadata persisted in the sidecar lock file for debugging."""

    agent_id: str
    session_id: str
    acquired_at: float
    pid: int


class FileLock:
    """A sidecar file lock implemented with `fcntl.flock`."""

    def __init__(
        self,
        path: Path,
        timeout_ms: int,
        poll_interval_ms: int = 50,
    ) -> None:
        self._path = path
        self._timeout_ms = timeout_ms
        self._poll_interval_ms = poll_interval_ms
        self._fd: int | None = None

    def acquire(self, metadata: LockMetadata) -> None:
        """Acquire the lock or raise `FileLockError` on timeout."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self._path, os.O_RDWR | os.O_CREAT, 0o600)
        deadline = time.monotonic() + (self._timeout_ms / 1000)

        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self._fd = fd
                self._write_metadata(metadata)
                logger.debug(
                    "openclaw_lock_acquired",
                    path=str(self._path),
                    agent_id=metadata.agent_id,
                    session_id=metadata.session_id,
                )
                return
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    os.close(fd)
                    raise FileLockError(f"Timed out acquiring lock for {self._path}") from exc
                time.sleep(self._poll_interval_ms / 1000)

    def release(self) -> None:
        """Release the lock if it is currently held."""
        if self._fd is None:
            return
        try:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        finally:
            os.close(self._fd)
            logger.debug("openclaw_lock_released", path=str(self._path))
            self._fd = None

    def __enter__(self) -> FileLock:
        raise RuntimeError("Use acquire() with LockMetadata before entering the lock context")

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.release()

    def _write_metadata(self, metadata: LockMetadata) -> None:
        if self._fd is None:
            return
        payload = json.dumps(
            {
                "agent_id": metadata.agent_id,
                "session_id": metadata.session_id,
                "acquired_at": metadata.acquired_at,
                "pid": metadata.pid,
            },
            ensure_ascii=False,
        )
        os.ftruncate(self._fd, 0)
        os.lseek(self._fd, 0, os.SEEK_SET)
        os.write(self._fd, payload.encode("utf-8"))
        os.fsync(self._fd)
