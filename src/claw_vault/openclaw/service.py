"""Background service that watches session files and deletes ClawVault error records."""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from tempfile import NamedTemporaryFile

import structlog
from watchfiles import Change, watch

from claw_vault.config import OpenClawSessionRedactionConfig
from claw_vault.openclaw.file_lock import FileLock, FileLockError, LockMetadata
from claw_vault.openclaw.file_redactor import SessionFileRedactor
from claw_vault.openclaw.state_store import SessionFileState, SessionStateStore

logger = structlog.get_logger()
_INTERNAL_LOCK_SUFFIX = ".clawvault.lock"
_TRANSCRIPT_SUFFIXES = (".jsonl", ".jsonl.lock")


class OpenClawSessionRedactionService:
    """Watch OpenClaw transcript directories and delete matching error blocks."""

    def __init__(
        self,
        settings: OpenClawSessionRedactionConfig,
        global_detection_config: dict[str, bool] | None = None,
    ) -> None:
        self._settings = settings
        self._enabled = settings.enabled
        self._sessions_root = self._normalize_path(settings.sessions_root)
        self._state_store = SessionStateStore(settings.state_file)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._redactor = SessionFileRedactor()

    @property
    def enabled(self) -> bool:
        """Return whether transcript redaction is enabled."""
        return self._enabled

    def start(self) -> None:
        """Start the background watcher thread."""
        if not self._enabled or self._thread is not None:
            return
        self._stop_event = threading.Event()
        self._sessions_root.mkdir(parents=True, exist_ok=True)
        self._register_existing_files()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info("openclaw_redaction_started", sessions_root=str(self._sessions_root))

    def stop(self) -> None:
        """Stop the background watcher thread."""
        if self._thread is None:
            return
        self._stop_event.set()
        if self._thread.is_alive():
            self._thread.join(timeout=5)
        self._thread = None
        logger.info("openclaw_redaction_stopped")

    def set_enabled(self, enabled: bool) -> None:
        """Toggle transcript redaction at runtime."""
        if enabled == self._enabled:
            return
        self._enabled = enabled
        if enabled:
            self.start()
            return
        self.stop()

    def _run(self) -> None:
        for changes in watch(
            self._sessions_root,
            debounce=self._settings.watch_debounce_ms,
            step=self._settings.watch_step_ms,
            stop_event=self._stop_event,
            recursive=True,
            yield_on_timeout=False,
        ):
            self._handle_changes(changes)

    def _register_existing_files(self) -> None:
        tracked_paths: set[Path] = set()
        for suffix in _TRANSCRIPT_SUFFIXES:
            for path in sorted(self._sessions_root.rglob(f"*{suffix}")):
                if path in tracked_paths or not self._is_transcript_file(path):
                    continue
                tracked_paths.add(path)
                self._track_file(path)
                state = self._state_store.get(path)
                if state is not None:
                    self._process_file(path, state)

    def _handle_changes(self, changes: set[tuple[Change, str]]) -> None:
        for change, raw_path in sorted(changes, key=lambda item: (item[0].value, item[1])):
            path = self._normalize_path(Path(raw_path))
            if self._is_internal_lock_file(path) or not self._is_transcript_file(path):
                continue
            if change == Change.deleted:
                self._state_store.remove(path)
                continue
            state = self._state_store.get(path)
            if state is None:
                self._track_file(path)
                state = self._state_store.get(path)
            if state is not None:
                self._process_file(path, state)

    def _process_file(self, path: Path, state: SessionFileState) -> None:
        path = self._normalize_path(path)
        if not path.exists():
            self._state_store.remove(path)
            return

        lock = FileLock(
            path=path.with_name(f"{path.name}{_INTERNAL_LOCK_SUFFIX}"),
            timeout_ms=self._settings.lock_timeout_ms,
        )
        metadata = LockMetadata(
            agent_id=state.agent_id,
            session_id=path.name,
            acquired_at=time.time(),
            pid=os.getpid(),
        )
        try:
            lock.acquire(metadata)
            self._process_file_locked(path, state)
        except FileLockError as exc:
            logger.warning("openclaw_lock_timeout", path=str(path), error=str(exc))
            self._state_store.upsert(
                path,
                state.agent_id,
                inode=state.inode,
                last_offset=state.last_offset,
                last_size=state.last_size,
                last_mtime_ns=state.last_mtime_ns,
                last_error=str(exc),
            )
        except Exception as exc:
            logger.error("openclaw_redaction_failed", path=str(path), error=str(exc))
            self._state_store.upsert(
                path,
                state.agent_id,
                inode=state.inode,
                last_offset=state.last_offset,
                last_size=state.last_size,
                last_mtime_ns=state.last_mtime_ns,
                last_error=str(exc),
            )
        finally:
            lock.release()

    def _process_file_locked(self, path: Path, state: SessionFileState) -> None:
        for _ in range(self._settings.processing_retries):
            if not path.exists():
                self._state_store.remove(path)
                return

            initial_stat = path.stat()
            content = path.read_bytes()
            reread_stat = path.stat()
            if not self._is_same_file(initial_stat, reread_stat, len(content)):
                continue

            result = self._redactor.redact_clawvault_error_pairs(content)
            if not result.changed:
                self._state_store.upsert(
                    path,
                    state.agent_id,
                    inode=reread_stat.st_ino,
                    last_offset=reread_stat.st_size,
                    last_size=reread_stat.st_size,
                    last_mtime_ns=reread_stat.st_mtime_ns,
                    last_error=None,
                )
                return

            current_stat = path.stat()
            if not self._is_same_file(initial_stat, current_stat, len(content)):
                continue

            self._replace_file(path, result.content)
            final_stat = path.stat()
            self._state_store.upsert(
                path,
                state.agent_id,
                inode=final_stat.st_ino,
                last_offset=final_stat.st_size,
                last_size=final_stat.st_size,
                last_mtime_ns=final_stat.st_mtime_ns,
                last_error=None,
            )
            logger.info(
                "openclaw_transcript_redacted",
                path=str(path),
                agent_id=state.agent_id,
                deleted_line_count=result.deleted_line_count,
                scanned_line_count=result.scanned_line_count,
            )
            return

        logger.warning("openclaw_redaction_retry_exhausted", path=str(path))

    def _track_file(self, path: Path) -> None:
        path = self._normalize_path(path)
        if not path.exists():
            return
        agent_id = self._agent_from_path(path)
        if agent_id is None:
            logger.debug("openclaw_session_path_skipped", path=str(path))
            return
        stat_result = path.stat()
        self._state_store.upsert(
            path,
            agent_id,
            inode=stat_result.st_ino,
            last_offset=0,
            last_size=stat_result.st_size,
            last_mtime_ns=stat_result.st_mtime_ns,
            last_error=None,
        )
        logger.debug("openclaw_session_tracked", path=str(path), agent_id=agent_id)

    @staticmethod
    def _replace_file(path: Path, content: bytes) -> None:
        original_mode = path.stat().st_mode
        with NamedTemporaryFile(
            dir=path.parent,
            prefix=f"{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as tmp:
            tmp.write(content)
            tmp.flush()
            os.fsync(tmp.fileno())
            temp_path = Path(tmp.name)
        try:
            os.chmod(temp_path, original_mode)
            os.replace(temp_path, path)
            dir_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        finally:
            temp_path.unlink(missing_ok=True)

    @staticmethod
    def _is_same_file(first: os.stat_result, second: os.stat_result, size: int) -> bool:
        return (
            first.st_ino == second.st_ino
            and first.st_size == second.st_size == size
            and first.st_mtime_ns == second.st_mtime_ns
        )

    @staticmethod
    def _normalize_path(path: Path) -> Path:
        return path.expanduser().resolve(strict=False)

    @staticmethod
    def _is_transcript_file(path: Path) -> bool:
        return path.parent.name == "sessions" and path.name.endswith(_TRANSCRIPT_SUFFIXES)

    @staticmethod
    def _agent_from_path(path: Path) -> str | None:
        parts = list(path.parts)
        for index, part in enumerate(parts[:-2]):
            if part == "agents" and index + 1 < len(parts):
                return parts[index + 1]
        return None

    @staticmethod
    def _is_internal_lock_file(path: Path) -> bool:
        return path.name.endswith(_INTERNAL_LOCK_SUFFIX)
