# ruff: noqa: S101

"""Tests for Claude Code Runtime Action Guard hook."""

from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Any

import pytest

from claw_vault.claude_code.runtime_action_client import RuntimeActionClientDecision
from claw_vault.claude_code.runtime_action_hook import evaluate_hook_payload, run_hook

API_KEY_FIXTURE = "sk-proj-abc123xyz456def789ghi012jkl345"
PROJECT_ROOT = Path(__file__).resolve().parents[1]


@dataclass
class _FakeRuntimeActionClient:
    decision: RuntimeActionClientDecision | None = None
    exc: Exception | None = None
    last_request: dict[str, object] | None = None

    async def evaluate(
        self,
        *,
        tool_name: str,
        params: dict[str, Any],
        agent_id: str | None = None,
        session_id: str | None = None,
    ) -> RuntimeActionClientDecision:
        self.last_request = {
            "tool_name": tool_name,
            "params": params,
            "agent_id": agent_id,
            "session_id": session_id,
        }
        if self.exc:
            raise self.exc
        if self.decision is None:
            raise AssertionError("missing fake decision")
        return self.decision


def _decision(**overrides: object) -> RuntimeActionClientDecision:
    values = {
        "decision": "allow",
        "risk_level": "low",
        "reasons": ["Low-risk shell command"],
        "categories": ["shell"],
        "action_type": "shell.execute",
        "target_summary": "shell.execute",
        "redacted_summary": "shell.execute",
        "should_block": False,
        "block_reason": None,
        "audit_recorded": True,
    }
    values.update(overrides)
    return RuntimeActionClientDecision(**values)


def test_pyproject_exposes_claude_code_hook_console_script() -> None:
    pyproject = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert pyproject["project"]["scripts"]["clawvault-claude-code-hook"] == (
        "claw_vault.claude_code.runtime_action_hook:main"
    )


@pytest.mark.asyncio
async def test_evaluate_hook_payload_allows_safe_decision() -> None:
    client = _FakeRuntimeActionClient(_decision())

    exit_code, message = await evaluate_hook_payload(
        {
            "session_id": "session-1",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "pwd"},
        },
        client=client,
    )

    assert exit_code == 0
    assert message == ""
    assert client.last_request == {
        "tool_name": "Bash",
        "params": {"command": "pwd"},
        "agent_id": "claude-code-hook",
        "session_id": "session-1",
    }


@pytest.mark.asyncio
async def test_evaluate_hook_payload_blocks_block_decision_without_raw_command() -> None:
    client = _FakeRuntimeActionClient(
        _decision(
            decision="block",
            risk_level="critical",
            categories=["destructive_delete"],
            should_block=True,
        )
    )

    exit_code, message = await evaluate_hook_payload(
        {
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
        },
        client=client,
    )

    assert exit_code == 2
    assert "blocked Bash (critical)" in message
    assert "rm -rf" not in message


@pytest.mark.asyncio
async def test_evaluate_hook_payload_blocks_ask_user_decision() -> None:
    client = _FakeRuntimeActionClient(
        _decision(
            decision="ask-user",
            risk_level="medium",
            action_type="file.write",
            should_block=True,
        )
    )

    exit_code, message = await evaluate_hook_payload(
        {
            "tool_name": "Write",
            "tool_input": {"file_path": "~/.bashrc", "content": "alias ll='ls -la'"},
        },
        client=client,
    )

    assert exit_code == 2
    assert "requires confirmation for Write (medium)" in message


@pytest.mark.asyncio
async def test_evaluate_hook_payload_fails_closed_when_client_raises() -> None:
    client = _FakeRuntimeActionClient(exc=RuntimeError("offline"))

    exit_code, message = await evaluate_hook_payload(
        {"tool_name": "Read", "tool_input": {"file_path": "README.md"}},
        client=client,
    )

    assert exit_code == 2
    assert "guard is unavailable" in message


@pytest.mark.asyncio
async def test_evaluate_hook_payload_blocks_malformed_tool_name() -> None:
    client = _FakeRuntimeActionClient(_decision())

    exit_code, message = await evaluate_hook_payload({"tool_input": {}}, client=client)

    assert exit_code == 2
    assert "malformed tool call" in message
    assert client.last_request is None


@pytest.mark.asyncio
async def test_evaluate_hook_payload_treats_non_object_tool_input_as_empty() -> None:
    client = _FakeRuntimeActionClient(_decision())

    exit_code, message = await evaluate_hook_payload(
        {"tool_name": "Bash", "tool_input": "pwd"},
        client=client,
    )

    assert exit_code == 0
    assert message == ""
    assert client.last_request is not None
    assert client.last_request["params"] == {}


def test_run_hook_blocks_malformed_json_without_leaking_input() -> None:
    stderr = StringIO()
    secret_input = f'{{"tool_name":"Write","tool_input":"{API_KEY_FIXTURE}"'

    exit_code = run_hook(stdin=StringIO(secret_input), stderr=stderr)

    assert exit_code == 2
    assert "malformed hook input" in stderr.getvalue()
    assert API_KEY_FIXTURE not in stderr.getvalue()


def test_run_hook_blocks_decision_without_leaking_secret_content() -> None:
    stderr = StringIO()
    client = _FakeRuntimeActionClient(
        _decision(
            decision="block",
            risk_level="critical",
            action_type="file.write",
            should_block=True,
        )
    )

    exit_code = run_hook(
        stdin=StringIO(
            json.dumps(
                {
                    "tool_name": "Write",
                    "tool_input": {
                        "file_path": "notes.txt",
                        "content": f"token={API_KEY_FIXTURE}",
                    },
                }
            )
        ),
        stderr=stderr,
        client=client,
    )

    assert exit_code == 2
    assert "blocked Write (critical)" in stderr.getvalue()
    assert API_KEY_FIXTURE not in stderr.getvalue()


def test_run_hook_sanitizes_tool_name_in_stderr() -> None:
    stderr = StringIO()
    client = _FakeRuntimeActionClient(
        _decision(decision="block", risk_level="high", should_block=True)
    )

    exit_code = run_hook(
        stdin=StringIO('{"tool_name":"Bad Tool!! token=secret","tool_input":{}}'),
        stderr=stderr,
        client=client,
    )

    assert exit_code == 2
    assert "BadTooltokensecret" in stderr.getvalue()
    assert "Bad Tool!! token=secret" not in stderr.getvalue()
