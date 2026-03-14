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
_WATCH_RESTART_DELAY_SECONDS = 0.5
_WATCH_REFRESH_TIMEOUT_MS = 1000
_DISCOVERY_HOME_DIRS = (Path("/root"), Path("/home"), Path("/Users"))


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
        self._watch_roots: tuple[Path, ...] = ()
        self._last_watch_error: str | None = None

    @property
    def enabled(self) -> bool:
        """Return whether transcript redaction is enabled."""
        return self._enabled

    @property
    def running(self) -> bool:
        """Return whether the background watcher thread is currently alive."""
        return self._thread is not None and self._thread.is_alive()

    @property
    def sessions_root(self) -> Path:
        """Return the normalized transcript root watched by the service."""
        return self._sessions_root

    @property
    def watch_roots(self) -> tuple[Path, ...]:
        """Return the active transcript roots watched by the service."""
        return self._watch_roots

    @property
    def last_watch_error(self) -> str | None:
        """Return the most recent watcher loop failure, if any."""
        return self._last_watch_error

    def start(self) -> None:
        """Start the background watcher thread."""
        if not self._enabled:
            return
        if self._thread is not None and self._thread.is_alive():
            return
        if self._thread is not None and not self._thread.is_alive():
            self._thread = None
        self._stop_event = threading.Event()
        self._refresh_watch_roots(create_primary=True)
        self._register_existing_files()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info(
            "openclaw_redaction_started",
            sessions_root=str(self._sessions_root),
            watch_roots=[str(root) for root in self._watch_roots],
        )

    def stop(self) -> None:
        """Stop the background watcher thread."""
        if self._thread is None:
            return
        self._stop_event.set()
        if self._thread.is_alive():
            self._thread.join(timeout=5)
        self._thread = None
        self._last_watch_error = None
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
        while not self._stop_event.is_set():
            try:
                self._watch_once()
                self._last_watch_error = None
            except Exception as exc:
                self._last_watch_error = str(exc)
                logger.exception("openclaw_watch_loop_failed", error=str(exc))
                if self._stop_event.wait(_WATCH_RESTART_DELAY_SECONDS):
                    return

    def _watch_once(self) -> None:
        watch_roots = self._refresh_watch_roots()
        if not watch_roots:
            self._stop_event.wait(_WATCH_RESTART_DELAY_SECONDS)
            return

        for changes in watch(
            *watch_roots,
            debounce=self._settings.watch_debounce_ms,
            step=self._settings.watch_step_ms,
            stop_event=self._stop_event,
            recursive=True,
            yield_on_timeout=True,
            rust_timeout=_WATCH_REFRESH_TIMEOUT_MS,
            ignore_permission_denied=True,
        ):
            if self._stop_event.is_set():
                return
            refreshed_roots = self._refresh_watch_roots()
            if refreshed_roots != watch_roots:
                self._register_existing_files()
                return
            if changes:
                self._handle_changes(changes)

    def _register_existing_files(self) -> None:
        if not self._watch_roots:
            self._refresh_watch_roots(create_primary=True)
        tracked_paths: set[Path] = set()
        for root in self._watch_roots:
            for suffix in _TRANSCRIPT_SUFFIXES:
                for path in sorted(root.rglob(f"*{suffix}")):
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
            is_new_path = state is None
            if state is None:
                self._track_file(path)
                state = self._state_store.get(path)
            if state is not None and (is_new_path or self._state_requires_processing(path, state)):
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
                    last_offset=result.next_offset,
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
                last_offset=result.next_offset,
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

    def _refresh_watch_roots(self, create_primary: bool = False) -> tuple[Path, ...]:
        watch_roots = self._resolve_watch_roots(create_primary=create_primary)
        if watch_roots != self._watch_roots:
            self._watch_roots = watch_roots
            logger.info(
                "openclaw_watch_roots_updated",
                watch_roots=[str(root) for root in watch_roots],
            )
        return self._watch_roots

    def _resolve_watch_roots(self, create_primary: bool = False) -> tuple[Path, ...]:
        roots: list[Path] = []
        seen: set[Path] = set()

        for candidate in self._candidate_session_roots():
            normalized = self._normalize_path(candidate)
            if normalized in seen:
                continue
            if normalized == self._sessions_root and create_primary:
                normalized.mkdir(parents=True, exist_ok=True)
            if not self._is_watchable_directory(normalized):
                continue
            roots.append(normalized)
            seen.add(normalized)

        return tuple(roots)

    def _candidate_session_roots(self) -> list[Path]:
        roots = [self._sessions_root]
        roots.extend(
            self._normalize_path(path) for path in self._settings.additional_sessions_roots
        )
        if self._settings.auto_discover_sessions_roots:
            roots.extend(self._discover_existing_session_roots())
        return roots

    def _discover_existing_session_roots(self) -> list[Path]:
        roots: list[Path] = []
        seen: set[Path] = set()
        for home_dir in self._candidate_home_directories():
            candidate = self._normalize_path(home_dir / ".openclaw" / "agents")
            if candidate in seen or not self._is_watchable_directory(candidate):
                continue
            roots.append(candidate)
            seen.add(candidate)
        return roots

    def _candidate_home_directories(self) -> list[Path]:
        home_dirs: list[Path] = []
        seen: set[Path] = set()

        def add_home(path: Path) -> None:
            normalized = self._normalize_path(path)
            if normalized in seen:
                return
            seen.add(normalized)
            home_dirs.append(normalized)

        add_home(Path.home())
        for base_dir in _DISCOVERY_HOME_DIRS:
            if base_dir == Path("/root"):
                add_home(base_dir)
                continue
            try:
                children = sorted(base_dir.iterdir())
            except OSError:
                continue
            for child in children:
                if child.is_dir():
                    add_home(child)

        return home_dirs

    def _state_requires_processing(self, path: Path, state: SessionFileState) -> bool:
        if state.last_error is not None:
            return True
        try:
            stat_result = path.stat()
        except FileNotFoundError:
            return False
        return not self._state_matches_stat(state, stat_result)

    @staticmethod
    def _state_matches_stat(state: SessionFileState, stat_result: os.stat_result) -> bool:
        return (
            state.inode == stat_result.st_ino
            and state.last_size == stat_result.st_size
            and state.last_mtime_ns == stat_result.st_mtime_ns
        )

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
    def _is_watchable_directory(path: Path) -> bool:
        try:
            return path.exists() and path.is_dir()
        except OSError:
            return False

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
