"""Core file monitoring service using watchfiles."""

from __future__ import annotations

import fnmatch
import os
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import structlog

from claw_vault.config import FileMonitorConfig
from claw_vault.detector.engine import ScanResult
from claw_vault.file_monitor.events import FileChangeEvent, FileChangeType

logger = structlog.get_logger()

# Map watchfiles Change enum values to our FileChangeType
_CHANGE_MAP = {
    1: FileChangeType.CREATED,   # Change.added
    2: FileChangeType.MODIFIED,  # Change.modified
    3: FileChangeType.DELETED,   # Change.deleted
}


class FileMonitorService:
    """Watches the filesystem for sensitive file changes and generates security events.

    Runs in a daemon thread using watchfiles (Rust-backed, cross-platform).
    Pattern matches file changes against configurable glob patterns and optionally
    scans file content using DetectionEngine.
    """

    def __init__(
        self,
        config: FileMonitorConfig,
        detection_engine: Any | None = None,
        file_manager: Any | None = None,
        guard_mode: str = "permissive",
    ) -> None:
        self._config = config
        self._detection_engine = detection_engine
        self._file_manager = file_manager
        self._guard_mode = guard_mode
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._event_callback: Callable[[FileChangeEvent], None] | None = None
        self._enforcement_callback: Callable[[str, ScanResult], None] | None = None
        self._recent_events: list[FileChangeEvent] = []
        self._lock = threading.Lock()
        self._last_watch_error: str | None = None
        self._access_thread: threading.Thread | None = None
        self._access_last_seen: dict[str, float] = {}
        # Paths acknowledged by user (resume) — keyed by path, value is file mtime at ack time.
        # Enforcement is suppressed until the file is modified (mtime changes).
        self._acknowledged_paths: dict[str, float] = {}
        # Permanently exempted paths — enforcement never fires for these
        self._exempted_paths: set[str] = set()

    # ── Properties ──

    @property
    def enabled(self) -> bool:
        return self._config.enabled

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def watch_roots(self) -> tuple[Path, ...]:
        return self._resolve_watch_roots()

    @property
    def last_watch_error(self) -> str | None:
        return self._last_watch_error

    @property
    def recent_events(self) -> list[FileChangeEvent]:
        with self._lock:
            return list(self._recent_events)

    # ── Lifecycle ──

    def start(self) -> None:
        if not self._config.enabled:
            logger.info("file_monitor_disabled")
            return
        if self.running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="file-monitor")
        self._thread.start()
        logger.info("file_monitor_started", watch_roots=[str(r) for r in self.watch_roots])
        if self._config.alert_on_access:
            self._start_access_monitor()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        self._thread = None
        if self._access_thread and self._access_thread.is_alive():
            self._access_thread.join(timeout=5)
        self._access_thread = None
        logger.info("file_monitor_stopped")

    def set_enabled(self, enabled: bool) -> None:
        self._config.enabled = enabled
        if enabled and not self.running:
            self.start()
        elif not enabled and self.running:
            self.stop()

    def set_event_callback(self, callback: Callable[[FileChangeEvent], None]) -> None:
        self._event_callback = callback

    def set_enforcement_callback(self, callback: Callable[[str, ScanResult], None]) -> None:
        """Set callback for proxy-layer enforcement when file threats are detected."""
        self._enforcement_callback = callback

    def acknowledge_all(self) -> None:
        """Mark all currently flagged paths as acknowledged.

        Called when the user resumes the proxy.  Records each file's current
        mtime so that enforcement is suppressed only while the file remains
        unchanged.  If the file is later modified (mtime changes), the
        acknowledgement becomes invalid and enforcement kicks in again.
        """
        with self._lock:
            for event in self._recent_events:
                if event.has_threats and event.enforcement_applied:
                    try:
                        mtime = os.path.getmtime(event.file_path)
                    except OSError:
                        continue
                    self._acknowledged_paths[event.file_path] = mtime
        logger.info(
            "file_monitor.acknowledged_all",
            paths=len(self._acknowledged_paths),
        )

    def _is_acknowledged(self, file_path: str) -> bool:
        """Check if a file was acknowledged and has NOT been modified since."""
        ack_mtime = self._acknowledged_paths.get(file_path)
        if ack_mtime is None:
            return False
        try:
            current_mtime = os.path.getmtime(file_path)
        except OSError:
            # File gone — no longer acknowledged
            self._acknowledged_paths.pop(file_path, None)
            return False
        if current_mtime != ack_mtime:
            # File was modified after acknowledge — re-enforce
            self._acknowledged_paths.pop(file_path, None)
            return False
        return True

    def exempt_all(self) -> None:
        """Permanently exempt all currently flagged file paths from enforcement.

        Unlike acknowledge (mtime-based, invalidated on modify), exempted paths
        are never re-enforced regardless of file changes.
        """
        with self._lock:
            for event in self._recent_events:
                if event.has_threats:
                    self._exempted_paths.add(event.file_path)
        logger.info("file_monitor.exempt_all", paths=len(self._exempted_paths))

    def _is_exempted(self, file_path: str) -> bool:
        """Check if a file path is permanently exempted from enforcement."""
        return file_path in self._exempted_paths

    def clear_exemptions(self) -> None:
        """Clear all exemptions and acknowledgements, restoring full enforcement."""
        self._exempted_paths.clear()
        self._acknowledged_paths.clear()
        logger.info("file_monitor.cleared_exemptions")

    @property
    def guard_mode(self) -> str:
        return self._guard_mode

    def set_guard_mode(self, mode: str) -> None:
        self._guard_mode = mode
        logger.info("file_monitor_guard_mode_changed", mode=mode)

    def update_config(self, **kwargs: Any) -> None:
        """Hot-patch config fields. Restarts watch if root-affecting fields change."""
        root_fields = {"watch_home_sensitive", "watch_paths", "alert_on_access"}
        needs_restart = False
        for key, value in kwargs.items():
            if hasattr(self._config, key):
                old = getattr(self._config, key)
                setattr(self._config, key, value)
                if key in root_fields and old != value:
                    needs_restart = True

        if needs_restart and self.running:
            self.stop()
            self.start()

    def _determine_action(self, event: FileChangeEvent) -> tuple[str, bool]:
        """Determine action based on guard mode. Returns (action_taken, needs_user_action)."""
        if not event.has_threats:
            return ("allow", False)
        mode = self._guard_mode
        if mode == "strict":
            return ("block", False)
        elif mode == "interactive":
            return ("ask_user", True)
        else:  # permissive
            return ("log", False)

    # ── Internal: Watch Loop ──

    def _run(self) -> None:
        """Outer loop with auto-restart on error."""
        while not self._stop_event.is_set():
            try:
                self._watch_once()
            except Exception as exc:
                self._last_watch_error = str(exc)
                logger.error("file_monitor_error", error=str(exc))
                # Wait before retrying
                self._stop_event.wait(timeout=5)

    def _watch_once(self) -> None:
        """Single watchfiles session."""
        from watchfiles import Change, watch

        roots = self._resolve_watch_roots()
        if not roots:
            logger.warning("file_monitor_no_roots")
            self._stop_event.wait(timeout=30)
            return

        self._last_watch_error = None
        str_roots = [str(r) for r in roots]
        logger.info("file_monitor_watching", roots=str_roots)

        for changes in watch(
            *str_roots,
            stop_event=self._stop_event,
            debounce=self._config.watch_debounce_ms,
            step=self._config.watch_step_ms,
            recursive=True,
            yield_on_timeout=True,
            ignore_permission_denied=True,
        ):
            if self._stop_event.is_set():
                break
            if changes:
                self._handle_changes(changes)

    def _handle_changes(self, changes: set[tuple[Any, str]]) -> None:
        """Process a batch of filesystem changes."""
        for change_type, path_str in changes:
            path = Path(path_str)
            matched = self._matched_pattern(path)
            is_managed = self._file_manager.is_managed(str(path)) if self._file_manager else False
            if not matched and not is_managed:
                continue

            change = _CHANGE_MAP.get(change_type.value if hasattr(change_type, "value") else change_type)
            if change is None:
                continue

            # Check config flags
            if change == FileChangeType.CREATED and not self._config.alert_on_create:
                continue
            if change == FileChangeType.MODIFIED and not self._config.alert_on_modify:
                continue
            if change == FileChangeType.DELETED and not self._config.alert_on_delete:
                continue
            if change == FileChangeType.ACCESSED and not self._config.alert_on_access:
                continue

            # Get file size
            file_size = None
            try:
                file_size = path.stat().st_size
            except OSError:
                pass

            event = FileChangeEvent(
                change_type=change,
                file_path=str(path),
                file_name=path.name,
                matched_pattern=matched,
                is_managed=is_managed,
                file_size_bytes=file_size,
            )

            # Content scan if applicable
            scan: ScanResult | None = None
            if (
                self._config.scan_content_on_change
                and self._detection_engine
                and change != FileChangeType.DELETED
                and file_size is not None
                and file_size <= self._config.max_file_size_kb * 1024
            ):
                scan = self._scan_file_content(path)
                if scan:
                    event.has_threats = scan.has_threats
                    event.threat_level = scan.threat_level.value
                    event.risk_score = scan.max_risk_score
                    event.sensitive_count = len(scan.sensitive)
                    event.detection_summary = [
                        *[f"sensitive:{s.pattern_type}" for s in scan.sensitive],
                        *[f"command:{c.reason}" for c in scan.commands],
                        *[f"injection:{i.injection_type}" for i in scan.injections],
                    ]

            # Apply guard mode action
            event.action_taken, event.needs_user_action = self._determine_action(event)

            # Enforcement: push flagged values to proxy layer
            # Only in strict/interactive mode — permissive logs only
            if self._enforcement_callback and self._guard_mode != "permissive":
                if (
                    scan
                    and scan.has_threats
                    and not self._is_acknowledged(str(path))
                    and not self._is_exempted(str(path))
                ):
                    self._enforcement_callback(str(path), scan)
                    event.enforcement_applied = True
                    event.flagged_values_count = len(scan.sensitive)
                elif change == FileChangeType.DELETED:
                    # Clear flagged values for deleted files
                    self._enforcement_callback(str(path), ScanResult())

            self._emit_event(event)

    # ── Helpers ──

    def _resolve_watch_roots(self) -> tuple[Path, ...]:
        """Build the set of directories to watch."""
        roots: set[Path] = set()

        # Home sensitive directories
        if self._config.watch_home_sensitive and self._file_manager:
            discovered = self._file_manager.auto_discover()
            for fpath in discovered:
                parent = Path(fpath).parent
                if parent.is_dir():
                    roots.add(parent)

        # Also add common sensitive dirs even without file_manager
        if self._config.watch_home_sensitive:
            home = Path.home()
            for d in [".aws", ".ssh", ".gnupg", ".config"]:
                p = home / d
                if p.is_dir():
                    roots.add(p)

        # Extra watch paths
        for extra in self._config.watch_paths:
            p = Path(extra)
            if p.is_dir():
                roots.add(p)

        return tuple(sorted(roots))

    def _is_sensitive_file(self, path: Path) -> bool:
        """Check if a file matches sensitive patterns or is managed."""
        if self._file_manager and self._file_manager.is_managed(str(path)):
            return True
        return self._matched_pattern(path) is not None

    def _matched_pattern(self, path: Path) -> str | None:
        """Return the first matching pattern, or None."""
        name = path.name
        for pattern in self._config.watch_patterns:
            if fnmatch.fnmatch(name, pattern):
                return pattern
        return None

    def _scan_file_content(self, path: Path) -> Any | None:
        """Read file and run through DetectionEngine."""
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            return self._detection_engine.scan_full(content)
        except Exception as exc:
            logger.warning("file_monitor_scan_error", path=str(path), error=str(exc))
            return None

    # ── Access Monitor (inotify_simple) ──

    def _start_access_monitor(self) -> None:
        """Start the file access monitoring thread."""
        if self._access_thread and self._access_thread.is_alive():
            return
        self._access_thread = threading.Thread(
            target=self._run_access_monitor, daemon=True, name="file-access-monitor",
        )
        self._access_thread.start()
        logger.info("file_access_monitor_started")

    def _run_access_monitor(self) -> None:
        """Outer loop for access monitoring with auto-restart."""
        while not self._stop_event.is_set():
            try:
                self._watch_access_once()
            except Exception as exc:
                logger.error("file_access_monitor_error", error=str(exc))
                self._stop_event.wait(timeout=5)

    def _watch_access_once(self) -> None:
        """Single inotify session monitoring file reads."""
        from inotify_simple import INotify, flags as iflags

        inotify = INotify()
        wd_map: dict[int, Path] = {}

        try:
            roots = self._resolve_watch_roots()
            if not roots:
                self._stop_event.wait(timeout=30)
                return

            watch_mask = iflags.ACCESS
            for root in roots:
                try:
                    wd = inotify.add_watch(str(root), watch_mask)
                    wd_map[wd] = root
                except OSError:
                    pass
                # Add subdirectories recursively
                try:
                    for dirpath in root.rglob("*"):
                        if dirpath.is_dir():
                            try:
                                wd = inotify.add_watch(str(dirpath), watch_mask)
                                wd_map[wd] = dirpath
                            except OSError:
                                pass
                except OSError:
                    pass

            logger.info(
                "file_access_monitor_watching",
                watch_count=len(wd_map),
            )

            while not self._stop_event.is_set():
                events = inotify.read(timeout=1000)
                for event in events:
                    if self._stop_event.is_set():
                        return
                    # Skip directory events (no filename)
                    if not event.name:
                        continue
                    dir_path = wd_map.get(event.wd)
                    if not dir_path:
                        continue
                    file_path = dir_path / event.name
                    if self._should_emit_access(file_path):
                        self._emit_access_event(file_path)
        finally:
            inotify.close()

    def _should_emit_access(self, path: Path) -> bool:
        """Check if an access event should be emitted (pattern match + debounce)."""
        matched = self._matched_pattern(path)
        is_managed = self._file_manager.is_managed(str(path)) if self._file_manager else False
        if not matched and not is_managed:
            return False

        # Debounce
        now = time.monotonic()
        key = str(path)
        last = self._access_last_seen.get(key, 0)
        if now - last < self._config.access_debounce_seconds:
            return False
        self._access_last_seen[key] = now
        return True

    def _emit_access_event(self, path: Path) -> None:
        """Create and emit an ACCESSED event, with content scan and enforcement."""
        file_size = None
        try:
            file_size = path.stat().st_size
        except OSError:
            pass

        event = FileChangeEvent(
            change_type=FileChangeType.ACCESSED,
            file_path=str(path),
            file_name=path.name,
            matched_pattern=self._matched_pattern(path),
            is_managed=(
                self._file_manager.is_managed(str(path)) if self._file_manager else False
            ),
            file_size_bytes=file_size,
        )

        # Content scan: detect sensitive data in the accessed file
        scan: ScanResult | None = None
        if (
            self._config.scan_content_on_change
            and self._detection_engine
            and file_size is not None
            and file_size <= self._config.max_file_size_kb * 1024
        ):
            scan = self._scan_file_content(path)
            if scan:
                event.has_threats = scan.has_threats
                event.threat_level = scan.threat_level.value
                event.risk_score = scan.max_risk_score
                event.sensitive_count = len(scan.sensitive)
                event.detection_summary = [
                    *[f"sensitive:{s.pattern_type}" for s in scan.sensitive],
                    *[f"command:{c.reason}" for c in scan.commands],
                    *[f"injection:{i.injection_type}" for i in scan.injections],
                ]

        # Apply guard mode action
        event.action_taken, event.needs_user_action = self._determine_action(event)

        # Enforcement: push flagged values to proxy layer
        # Only in strict/interactive mode — permissive logs only
        if (
            self._enforcement_callback
            and self._guard_mode != "permissive"
            and scan
            and scan.has_threats
            and not self._is_acknowledged(str(path))
            and not self._is_exempted(str(path))
        ):
            self._enforcement_callback(str(path), scan)
            event.enforcement_applied = True
            event.flagged_values_count = len(scan.sensitive)

        self._emit_event(event)

    def _emit_event(self, event: FileChangeEvent) -> None:
        """Store event and call callback."""
        with self._lock:
            self._recent_events.insert(0, event)
            if len(self._recent_events) > 200:
                self._recent_events.pop()

        logger.info(
            "file_change_detected",
            change_type=event.change_type.value,
            file_path=event.file_path,
            has_threats=event.has_threats,
            risk_score=event.risk_score,
            action=event.action_taken,
        )

        if self._event_callback:
            try:
                self._event_callback(event)
            except Exception as exc:
                logger.error("file_monitor_callback_error", error=str(exc))
