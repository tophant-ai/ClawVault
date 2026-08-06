# ruff: noqa: S101

"""Tests for Claude Code UserPromptSubmit Guard hook."""

from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass
from io import StringIO
from pathlib import Path

import pytest

from claw_vault.claude_code.user_prompt_client import UserPromptClientDecision
from claw_vault.claude_code.user_prompt_hook import evaluate_user_prompt_payload, run_hook

SAMPLE_SECRET = "sk" + "-proj-" + "abc123xyz456def789ghi012jkl345"
PROJECT_ROOT = Path(__file__).resolve().parents[1]


@dataclass
class _FakeUserPromptClient:
    decision: UserPromptClientDecision | None = None
    exc: Exception | None = None
    last_request: dict[str, object] | None = None

    async def evaluate(
        self,
        *,
        prompt: str,
        agent_id: str | None = None,
        session_id: str | None = None,
        cwd: str | None = None,
        transcript_path: str | None = None,
    ) -> UserPromptClientDecision:
        self.last_request = {
            "prompt": prompt,
            "agent_id": agent_id,
            "session_id": session_id,
            "cwd": cwd,
            "transcript_path": transcript_path,
        }
        if self.exc:
            raise self.exc
        if self.decision is None:
            raise AssertionError("missing fake decision")
        return self.decision


def _decision(**overrides: object) -> UserPromptClientDecision:
    values = {
        "decision": "allow",
        "risk_level": "low",
        "risk_score": 0.0,
        "reasons": ["No threats detected"],
        "categories": [],
        "redacted_summary": "hello",
        "should_block": False,
        "block_reason": None,
        "audit_recorded": True,
    }
    values.update(overrides)
    return UserPromptClientDecision(**values)


def test_pyproject_exposes_user_prompt_hook_console_script() -> None:
    pyproject = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert pyproject["project"]["scripts"]["clawvault-claude-code-user-prompt-hook"] == (
        "claw_vault.claude_code.user_prompt_hook:main"
    )


@pytest.mark.asyncio
async def test_evaluate_user_prompt_payload_allows_safe_decision() -> None:
    client = _FakeUserPromptClient(_decision())

    exit_code, message = await evaluate_user_prompt_payload(
        {
            "session_id": "session-1",
            "cwd": "/tmp/project",
            "transcript_path": "/tmp/session.jsonl",
            "hook_event_name": "UserPromptSubmit",
            "prompt": "hello",
        },
        client=client,
    )

    assert exit_code == 0
    assert message == ""
    assert client.last_request == {
        "prompt": "hello",
        "agent_id": "claude-code-hook",
        "session_id": "session-1",
        "cwd": "/tmp/project",
        "transcript_path": "/tmp/session.jsonl",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("decision", ["block", "ask_user", "sanitize"])
async def test_evaluate_user_prompt_payload_blocks_non_allow_decisions(decision: str) -> None:
    client = _FakeUserPromptClient(
        _decision(
            decision=decision,
            risk_level="high",
            risk_score=8.0,
            categories=["api_key"],
            should_block=True,
        )
    )

    exit_code, message = await evaluate_user_prompt_payload(
        {"prompt": "Use token " + SAMPLE_SECRET},
        client=client,
    )

    assert exit_code == 2
    assert "User Prompt Guard" in message
    assert "high" in message
    assert SAMPLE_SECRET not in message


@pytest.mark.asyncio
async def test_evaluate_user_prompt_payload_fails_closed_when_client_raises() -> None:
    client = _FakeUserPromptClient(exc=RuntimeError("offline"))

    exit_code, message = await evaluate_user_prompt_payload({"prompt": "hello"}, client=client)

    assert exit_code == 2
    assert "guard is unavailable" in message


@pytest.mark.asyncio
async def test_evaluate_user_prompt_payload_blocks_missing_prompt() -> None:
    client = _FakeUserPromptClient(_decision())

    exit_code, message = await evaluate_user_prompt_payload({"prompt": None}, client=client)

    assert exit_code == 2
    assert "malformed prompt" in message
    assert client.last_request is None


def test_run_hook_blocks_malformed_json_without_leaking_input() -> None:
    stderr = StringIO()
    malformed = '{"prompt":"Use token ' + SAMPLE_SECRET + '"'

    exit_code = run_hook(stdin=StringIO(malformed), stderr=stderr)

    assert exit_code == 2
    assert "malformed hook input" in stderr.getvalue()
    assert SAMPLE_SECRET not in stderr.getvalue()


def test_run_hook_blocks_decision_without_leaking_prompt() -> None:
    stderr = StringIO()
    client = _FakeUserPromptClient(
        _decision(decision="block", risk_level="critical", should_block=True)
    )

    exit_code = run_hook(
        stdin=StringIO(json.dumps({"prompt": "Use token " + SAMPLE_SECRET})),
        stderr=stderr,
        client=client,
    )

    assert exit_code == 2
    assert "blocked prompt (critical" in stderr.getvalue()
    assert SAMPLE_SECRET not in stderr.getvalue()


def test_run_hook_blocks_non_object_payload() -> None:
    stderr = StringIO()

    exit_code = run_hook(stdin=StringIO("[]"), stderr=stderr)

    assert exit_code == 2
    assert "malformed hook input" in stderr.getvalue()
