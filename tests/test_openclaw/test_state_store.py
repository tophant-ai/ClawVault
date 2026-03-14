"""Tests for transcript state persistence."""

from __future__ import annotations

from pathlib import Path

from claw_vault.openclaw.state_store import SessionStateStore


def test_upsert_persists_offset_expected_reloadable(tmp_path: Path) -> None:
    state_file = tmp_path / "state.json"
    store = SessionStateStore(state_file)
    transcript = tmp_path / "agents" / "ops" / "sessions" / "sess-1.jsonl"

    store.upsert(
        transcript,
        "ops",
        inode=11,
        last_offset=42,
        last_size=64,
        last_mtime_ns=99,
    )

    reloaded = SessionStateStore(state_file).get(transcript)

    assert reloaded is not None
    assert reloaded.agent_id == "ops"
    assert reloaded.last_offset == 42
