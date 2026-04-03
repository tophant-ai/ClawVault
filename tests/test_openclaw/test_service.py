from __future__ import annotations

import os
import threading
import time
from pathlib import Path

from watchfiles import Change

from claw_vault.config import OpenClawSessionRedactionConfig
from claw_vault.openclaw.service import OpenClawSessionRedactionService


def _wait_until_redacted(
    transcript: Path,
    secret_fragment: str,
    timeout_seconds: float = 3.0,
) -> str:
    deadline = time.monotonic() + timeout_seconds
    last_content = ""
    while time.monotonic() < deadline:
        if transcript.exists():
            last_content = transcript.read_text(encoding="utf-8")
            if secret_fragment not in last_content:
                return last_content
        time.sleep(0.05)
    return last_content


def test_register_existing_files_deletes_error_line_and_previous_line(tmp_path: Path) -> None:
    sessions_root = tmp_path / ".openclaw" / "agents"
    transcript = sessions_root / "main" / "sessions" / "sess-1.jsonl"
    transcript.parent.mkdir(parents=True)
    transcript.write_text(
        "\n".join(
            [
                '{"type":"user","content":"keep"}',
                '{"type":"assistant","content":"drop-prev"}',
                '{"errorMessage":"403 [ClawVault] blocked"}',
                '{"type":"assistant","content":"keep-after"}',
                "",
            ]
        ),
        encoding="utf-8",
    )
    service = OpenClawSessionRedactionService(
        OpenClawSessionRedactionConfig(
            enabled=True,
            sessions_root=sessions_root,
            state_file=tmp_path / "state.json",
        )
    )

    service._register_existing_files()

    assert transcript.read_text(encoding="utf-8") == (
        '{"type":"user","content":"keep"}\n{"type":"assistant","content":"keep-after"}\n'
    )


def test_handle_changes_new_final_file_expected_process_from_start(tmp_path: Path) -> None:
    sessions_root = tmp_path / ".openclaw" / "agents"
    transcript = sessions_root / "main" / "sessions" / "sess-1.jsonl"
    transcript.parent.mkdir(parents=True)
    service = OpenClawSessionRedactionService(
        OpenClawSessionRedactionConfig(
            enabled=True,
            sessions_root=sessions_root,
            state_file=tmp_path / "state.json",
        )
    )

    transcript.write_text(
        '{"type":"assistant","content":"drop-prev"}\n{"errorMessage":"403 [ClawVault] blocked"}\n',
        encoding="utf-8",
    )
    service._handle_changes({(Change.added, str(transcript))})

    assert transcript.read_text(encoding="utf-8") == ""


def test_handle_changes_lock_file_expected_process_in_place(tmp_path: Path) -> None:
    sessions_root = tmp_path / ".openclaw" / "agents"
    staged_path = sessions_root / "main" / "sessions" / "sess-1.jsonl.lock"
    staged_path.parent.mkdir(parents=True)
    service = OpenClawSessionRedactionService(
        OpenClawSessionRedactionConfig(
            enabled=True,
            sessions_root=sessions_root,
            state_file=tmp_path / "state.json",
        )
    )

    staged_path.write_text(
        '{"type":"assistant","content":"drop-prev"}\n'
        '{"errorMessage":"403 [ClawVault] blocked"}\n'
        '{"type":"assistant","content":"keep"}\n',
        encoding="utf-8",
    )
    service._handle_changes({(Change.modified, str(staged_path))})

    assert staged_path.read_text(encoding="utf-8") == '{"type":"assistant","content":"keep"}\n'


def test_refresh_watch_roots_includes_auto_discovered_root(tmp_path: Path) -> None:
    sessions_root = tmp_path / ".openclaw" / "agents"
    discovered_root = tmp_path / "root-home" / ".openclaw" / "agents"
    discovered_root.mkdir(parents=True)
    service = OpenClawSessionRedactionService(
        OpenClawSessionRedactionConfig(
            enabled=True,
            sessions_root=sessions_root,
            state_file=tmp_path / "state.json",
        )
    )
    service._discover_existing_session_roots = lambda: [discovered_root]

    watch_roots = service._refresh_watch_roots(create_primary=True)

    assert watch_roots == (sessions_root.resolve(), discovered_root.resolve())


def test_handle_changes_skips_processing_when_state_matches_current_file(tmp_path: Path) -> None:
    sessions_root = tmp_path / ".openclaw" / "agents"
    transcript = sessions_root / "main" / "sessions" / "sess-1.jsonl"
    transcript.parent.mkdir(parents=True)
    transcript.write_text('{"type":"assistant","content":"keep"}\n', encoding="utf-8")
    service = OpenClawSessionRedactionService(
        OpenClawSessionRedactionConfig(
            enabled=True,
            sessions_root=sessions_root,
            state_file=tmp_path / "state.json",
        )
    )
    service._track_file(transcript)
    called = False

    def fail_if_called(path: Path, state) -> None:
        nonlocal called
        called = True

    service._process_file = fail_if_called  # type: ignore[method-assign]

    service._handle_changes({(Change.modified, str(transcript))})

    assert called is False


def test_handle_changes_reprocesses_file_replaced_via_rename(tmp_path: Path) -> None:
    sessions_root = tmp_path / ".openclaw" / "agents"
    transcript = sessions_root / "main" / "sessions" / "sess-1.jsonl"
    transcript.parent.mkdir(parents=True)
    transcript.write_text('{"type":"assistant","content":"keep"}\n', encoding="utf-8")
    service = OpenClawSessionRedactionService(
        OpenClawSessionRedactionConfig(
            enabled=True,
            sessions_root=sessions_root,
            state_file=tmp_path / "state.json",
        )
    )
    service._handle_changes({(Change.added, str(transcript))})

    replacement = transcript.with_name("sess-1.jsonl.tmp")
    replacement.write_text(
        '{"type":"assistant","content":"drop-prev"}\n{"errorMessage":"403 [ClawVault] blocked"}\n',
        encoding="utf-8",
    )
    os.replace(replacement, transcript)

    service._handle_changes({(Change.modified, str(transcript))})

    assert transcript.read_text(encoding="utf-8") == ""


def test_run_recovers_after_watch_failure(tmp_path: Path) -> None:
    sessions_root = tmp_path / ".openclaw" / "agents"
    service = OpenClawSessionRedactionService(
        OpenClawSessionRedactionConfig(
            enabled=True,
            sessions_root=sessions_root,
            state_file=tmp_path / "state.json",
        )
    )
    service._stop_event = threading.Event()
    call_count = 0

    def flaky_watch_once() -> None:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("boom")
        service._stop_event.set()

    service._watch_once = flaky_watch_once  # type: ignore[method-assign]

    service._run()

    assert call_count == 2
    assert service.last_watch_error is None


def test_start_realtime_redacts_new_file_under_openclaw_root(tmp_path: Path) -> None:
    sessions_root = tmp_path / ".openclaw" / "agents"
    transcript = sessions_root / "main" / "sessions" / "sess-1.jsonl"
    transcript.parent.mkdir(parents=True)
    service = OpenClawSessionRedactionService(
        OpenClawSessionRedactionConfig(
            enabled=True,
            sessions_root=sessions_root,
            state_file=tmp_path / "state.json",
            auto_discover_sessions_roots=False,
            watch_debounce_ms=10,
            watch_step_ms=10,
        )
    )

    service.start()
    try:
        time.sleep(0.2)  # let watcher thread register inotify watches
        transcript.write_text(
            '{"type":"assistant","content":"drop-prev"}\n'
            '{"errorMessage":"403 [ClawVault] blocked"}\n',
            encoding="utf-8",
        )

        assert _wait_until_redacted(transcript, "403 [ClawVault]") == ""
    finally:
        service.stop()


def test_start_realtime_redacts_appended_pair_under_openclaw_root(tmp_path: Path) -> None:
    sessions_root = tmp_path / ".openclaw" / "agents"
    transcript = sessions_root / "main" / "sessions" / "sess-1.jsonl"
    transcript.parent.mkdir(parents=True)
    transcript.write_text('{"type":"assistant","content":"keep"}\n', encoding="utf-8")
    service = OpenClawSessionRedactionService(
        OpenClawSessionRedactionConfig(
            enabled=True,
            sessions_root=sessions_root,
            state_file=tmp_path / "state.json",
            auto_discover_sessions_roots=False,
            watch_debounce_ms=10,
            watch_step_ms=10,
        )
    )

    service.start()
    try:
        with transcript.open("a", encoding="utf-8") as handle:
            handle.write('{"type":"assistant","content":"drop-prev"}\n')
            handle.write('{"errorMessage":"403 [ClawVault] blocked"}\n')
            handle.flush()

        assert _wait_until_redacted(transcript, "403 [ClawVault]") == (
            '{"type":"assistant","content":"keep"}\n'
        )
    finally:
        service.stop()


def test_start_realtime_waits_for_complete_newline_before_delete(tmp_path: Path) -> None:
    sessions_root = tmp_path / ".openclaw" / "agents"
    transcript = sessions_root / "main" / "sessions" / "sess-1.jsonl"
    transcript.parent.mkdir(parents=True)
    transcript.write_text('{"type":"assistant","content":"drop-prev"}\n', encoding="utf-8")
    service = OpenClawSessionRedactionService(
        OpenClawSessionRedactionConfig(
            enabled=True,
            sessions_root=sessions_root,
            state_file=tmp_path / "state.json",
            watch_debounce_ms=10,
            watch_step_ms=10,
        )
    )

    service.start()
    try:
        with transcript.open("a", encoding="utf-8") as handle:
            handle.write('{"errorMessage":"403 [ClawVault] blocked"}')
            handle.flush()
            time.sleep(0.3)
            assert "drop-prev" in transcript.read_text(encoding="utf-8")
            handle.write("\n")
            handle.flush()

        assert _wait_until_redacted(transcript, "403 [ClawVault]") == ""
    finally:
        service.stop()


def test_start_realtime_redacts_file_promoted_from_lock_via_rename(tmp_path: Path) -> None:
    sessions_root = tmp_path / ".openclaw" / "agents"
    transcript = sessions_root / "main" / "sessions" / "sess-1.jsonl"
    staged_path = transcript.with_suffix(".jsonl.lock")
    staged_path.parent.mkdir(parents=True)
    service = OpenClawSessionRedactionService(
        OpenClawSessionRedactionConfig(
            enabled=True,
            sessions_root=sessions_root,
            state_file=tmp_path / "state.json",
            auto_discover_sessions_roots=False,
            watch_debounce_ms=10,
            watch_step_ms=10,
        )
    )

    service.start()
    try:
        time.sleep(0.2)  # let watcher thread register inotify watches
        staged_path.write_text(
            '{"type":"assistant","content":"drop-prev"}\n'
            '{"errorMessage":"403 [ClawVault] blocked"}\n',
            encoding="utf-8",
        )
        os.replace(staged_path, transcript)

        assert _wait_until_redacted(transcript, "403 [ClawVault]") == ""
    finally:
        service.stop()
