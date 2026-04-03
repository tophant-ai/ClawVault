"""Cron-based scheduler for local filesystem scans."""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import structlog
from croniter import croniter

from claw_vault.config import LocalScanConfig
from claw_vault.local_scan.models import (
    LocalScanResult,
    ScanSchedule,
    ScanStatus,
    ScanType,
)
from claw_vault.local_scan.scanner import LocalScanner

logger = structlog.get_logger()

_POLL_INTERVAL_SECONDS = 30


class ScanScheduler:
    """Background scheduler that runs local scans on cron schedules."""

    def __init__(
        self,
        scanner: LocalScanner,
        config: LocalScanConfig,
        event_callback: Callable[[LocalScanResult], None] | None = None,
        history_file: Path | None = None,
    ) -> None:
        self._scanner = scanner
        self._config = config
        self._event_callback = event_callback
        self._history_file = history_file
        self._schedules: list[ScanSchedule] = []
        self._last_run: dict[str, float] = {}
        self._history: list[LocalScanResult] = []
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        # Load schedules from config
        for s in config.schedules:
            try:
                self._schedules.append(ScanSchedule(**s))
            except Exception as exc:
                logger.warning("local_scan.schedule_load_error", error=str(exc))

        # Load history from file
        if self._history_file and self._history_file.exists():
            self._load_history()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        """Start the scheduler background thread."""
        if self.running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info(
            "local_scan.scheduler_started",
            schedules=len(self._schedules),
        )

    def stop(self) -> None:
        """Stop the scheduler."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        self._thread = None
        logger.info("local_scan.scheduler_stopped")

    def add_schedule(self, schedule: ScanSchedule) -> None:
        """Add a schedule and persist to config."""
        # Validate cron expression
        if not croniter.is_valid(schedule.cron):
            raise ValueError(f"Invalid cron expression: {schedule.cron}")
        with self._lock:
            self._schedules.append(schedule)
            self._sync_config()

    def remove_schedule(self, schedule_id: str) -> bool:
        """Remove a schedule by ID."""
        with self._lock:
            before = len(self._schedules)
            self._schedules = [s for s in self._schedules if s.id != schedule_id]
            if len(self._schedules) < before:
                self._sync_config()
                return True
        return False

    def list_schedules(self) -> list[ScanSchedule]:
        with self._lock:
            return list(self._schedules)

    def get_history(self, limit: int = 50) -> list[LocalScanResult]:
        with self._lock:
            return list(self._history[:limit])

    def run_now(
        self,
        scan_type: ScanType,
        path: str,
        max_files: int | None = None,
    ) -> LocalScanResult:
        """Execute a scan immediately (called from any thread)."""
        result = self._scanner.run_scan(scan_type, path, max_files)
        self._record_result(result)
        return result

    def _run(self) -> None:
        """Main scheduler loop."""
        while not self._stop_event.is_set():
            try:
                self._check_schedules()
            except Exception as exc:
                logger.error("local_scan.scheduler_error", error=str(exc))
            self._stop_event.wait(_POLL_INTERVAL_SECONDS)

    def _check_schedules(self) -> None:
        """Check all enabled schedules and run any that are due."""
        now = datetime.now(timezone.utc)
        now_ts = now.timestamp()

        with self._lock:
            schedules = list(self._schedules)

        for sched in schedules:
            if not sched.enabled:
                continue
            if not croniter.is_valid(sched.cron):
                continue

            # Check if the current minute matches the cron expression
            cron = croniter(sched.cron, now)
            prev_fire = cron.get_prev(datetime)
            # If the previous fire time is within the last poll interval and we haven't
            # run it in this interval, execute the scan
            seconds_since_fire = (now - prev_fire).total_seconds()
            last_run = self._last_run.get(sched.id, 0)

            if seconds_since_fire < _POLL_INTERVAL_SECONDS and (now_ts - last_run) > _POLL_INTERVAL_SECONDS:
                self._last_run[sched.id] = now_ts
                logger.info(
                    "local_scan.schedule_triggered",
                    schedule_id=sched.id,
                    scan_type=sched.scan_type,
                    path=sched.path,
                )
                try:
                    result = self._scanner.run_scan(
                        ScanType(sched.scan_type),
                        sched.path,
                        sched.max_files,
                    )
                    result.schedule_id = sched.id
                    self._record_result(result)
                except Exception as exc:
                    logger.error(
                        "local_scan.schedule_run_error",
                        schedule_id=sched.id,
                        error=str(exc),
                    )

    def _record_result(self, result: LocalScanResult) -> None:
        """Save result to history and call event callback."""
        with self._lock:
            self._history.insert(0, result)
            if len(self._history) > self._config.history_max:
                self._history = self._history[: self._config.history_max]
        self._save_history()
        if self._event_callback:
            try:
                self._event_callback(result)
            except Exception as exc:
                logger.warning("local_scan.callback_error", error=str(exc))

    def _sync_config(self) -> None:
        """Persist schedules back to config (caller holds _lock)."""
        self._config.schedules = [s.model_dump(mode="json") for s in self._schedules]

    def _save_history(self) -> None:
        """Append latest result to history JSONL file."""
        if not self._history_file:
            return
        try:
            self._history_file.parent.mkdir(parents=True, exist_ok=True)
            with self._lock:
                if self._history:
                    latest = self._history[0]
                    with open(self._history_file, "a", encoding="utf-8") as f:
                        f.write(latest.model_dump_json() + "\n")
        except Exception as exc:
            logger.warning("local_scan.history_save_error", error=str(exc))

    def _load_history(self) -> None:
        """Load history from JSONL file."""
        if not self._history_file or not self._history_file.exists():
            return
        try:
            entries: list[LocalScanResult] = []
            for line in self._history_file.read_text(encoding="utf-8").strip().splitlines():
                if line.strip():
                    entries.append(LocalScanResult.model_validate_json(line))
            # Keep most recent first, limit to history_max
            entries.reverse()
            self._history = entries[: self._config.history_max]
        except Exception as exc:
            logger.warning("local_scan.history_load_error", error=str(exc))
