"""Tests for transcript sidecar locking."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from claw_vault.openclaw.file_lock import FileLock, FileLockError, LockMetadata


class TestFileLock:
    """Ensure lock acquisition and release semantics are correct."""

    def test_acquire_after_release_expected_success(self, tmp_path: Path) -> None:
        lock_path = tmp_path / "session.jsonl.clawvault.lock"
        first = FileLock(lock_path, timeout_ms=100)
        second = FileLock(lock_path, timeout_ms=100)
        metadata = LockMetadata(
            agent_id="ops",
            session_id="sess-1",
            acquired_at=time.time(),
            pid=1,
        )

        first.acquire(metadata)
        first.release()
        second.acquire(metadata)
        second.release()

    def test_timeout_when_locked_expected_error(self, tmp_path: Path) -> None:
        lock_path = tmp_path / "session.jsonl.clawvault.lock"
        first = FileLock(lock_path, timeout_ms=100)
        second = FileLock(lock_path, timeout_ms=100)
        metadata = LockMetadata(
            agent_id="ops",
            session_id="sess-1",
            acquired_at=time.time(),
            pid=1,
        )

        first.acquire(metadata)
        with pytest.raises(FileLockError):
            second.acquire(metadata)
        first.release()
