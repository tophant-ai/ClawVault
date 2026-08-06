# ruff: noqa: S101

"""Tests for Claude Code Runtime Action Guard client."""

from __future__ import annotations

import httpx
import pytest

from claw_vault.claude_code.runtime_action_client import ClaudeCodeRuntimeActionClient

API_KEY_FIXTURE = "sk-proj-abc123xyz456def789ghi012jkl345"


def _decision_payload(**overrides):
    payload = {
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
    payload.update(overrides)
    return payload


class _FakeAsyncClient:
    def __init__(self, payload=None, exc: Exception | None = None) -> None:
        self.payload = payload if payload is not None else _decision_payload()
        self.exc = exc
        self.last_request: dict[str, object] | None = None

    async def post(self, path: str, *, json: dict[str, object]):
        self.last_request = {"path": path, "json": json}
        if self.exc:
            raise self.exc
        return httpx.Response(200, json=self.payload, request=httpx.Request("POST", path))


@pytest.mark.asyncio
async def test_claude_code_runtime_action_client_allows_safe_decision() -> None:
    fake = _FakeAsyncClient()
    client = ClaudeCodeRuntimeActionClient(_client=fake)

    decision = await client.evaluate(
        tool_name="Bash",
        params={"command": "pwd"},
        agent_id="agent-1",
        session_id="session-1",
    )

    assert decision.decision == "allow"
    assert decision.should_block is False
    assert fake.last_request == {
        "path": "/api/runtime-action",
        "json": {
            "source_agent": "claude-code",
            "tool_name": "Bash",
            "params": {"command": "pwd"},
            "agent_id": "agent-1",
            "session_id": "session-1",
        },
    }


@pytest.mark.asyncio
async def test_claude_code_runtime_action_client_blocks_block_decision() -> None:
    fake = _FakeAsyncClient(
        _decision_payload(
            decision="block",
            risk_level="critical",
            reasons=["Destructive recursive delete targets a protected or broad path"],
            categories=["destructive_delete"],
            should_block=True,
            block_reason="ClawVault Runtime Action Guard: block Bash (critical)",
        )
    )
    client = ClaudeCodeRuntimeActionClient(_client=fake)

    decision = await client.evaluate(tool_name="Bash", params={"command": "rm -rf /"})

    assert decision.decision == "block"
    assert decision.should_block is True
    assert decision.risk_level == "critical"
    assert "destructive_delete" in decision.categories


@pytest.mark.asyncio
async def test_claude_code_runtime_action_client_blocks_ask_user_decision() -> None:
    fake = _FakeAsyncClient(
        _decision_payload(
            decision="ask-user",
            risk_level="medium",
            reasons=["Shell startup file write requires confirmation"],
            categories=["startup_file_write"],
            action_type="file.write",
            target_summary="~/.bashrc",
            redacted_summary="write ~/.bashrc",
            should_block=True,
            block_reason="ClawVault Runtime Action Guard: ask-user Write (medium)",
        )
    )
    client = ClaudeCodeRuntimeActionClient(_client=fake)

    decision = await client.evaluate(
        tool_name="Write",
        params={"file_path": "~/.bashrc", "content": "alias ll='ls -la'"},
    )

    assert decision.decision == "ask-user"
    assert decision.should_block is True
    assert decision.action_type == "file.write"


@pytest.mark.asyncio
async def test_claude_code_runtime_action_client_fails_closed_when_unavailable() -> None:
    fake = _FakeAsyncClient(exc=httpx.ConnectError("offline"))
    client = ClaudeCodeRuntimeActionClient(_client=fake)

    decision = await client.evaluate(tool_name="Bash", params={"command": "pwd"})

    assert decision.decision == "block"
    assert decision.should_block is True
    assert decision.risk_level == "critical"
    assert "runtime_action_guard_unavailable" in decision.categories


@pytest.mark.asyncio
async def test_claude_code_runtime_action_client_fails_closed_on_malformed_response() -> None:
    fake = _FakeAsyncClient({"decision": "allow"})
    client = ClaudeCodeRuntimeActionClient(_client=fake)

    decision = await client.evaluate(tool_name="Read", params={"file_path": "README.md"})

    assert decision.decision == "block"
    assert decision.should_block is True
    assert decision.action_type == "file.read"


@pytest.mark.asyncio
async def test_claude_code_runtime_action_client_fails_closed_on_unsafe_response() -> None:
    fake = _FakeAsyncClient(
        _decision_payload(
            decision="block",
            risk_level="critical",
            should_block=False,
            categories=["destructive_delete"],
        )
    )
    client = ClaudeCodeRuntimeActionClient(_client=fake)

    decision = await client.evaluate(tool_name="Bash", params={"command": "rm -rf /"})

    assert decision.decision == "block"
    assert decision.should_block is True
    assert decision.risk_level == "critical"
    assert "runtime_action_guard_unavailable" in decision.categories


@pytest.mark.asyncio
async def test_claude_code_runtime_action_client_filters_non_string_lists() -> None:
    fake = _FakeAsyncClient(
        _decision_payload(
            reasons=["ok", 123],
            categories=["shell", None],
        )
    )
    client = ClaudeCodeRuntimeActionClient(_client=fake)

    decision = await client.evaluate(tool_name="Bash", params={"command": "pwd"})

    assert decision.reasons == ["ok"]
    assert decision.categories == ["shell"]


@pytest.mark.asyncio
async def test_claude_code_runtime_action_client_does_not_add_secret_to_fail_closed() -> None:
    fake = _FakeAsyncClient(exc=httpx.ConnectError("offline"))
    client = ClaudeCodeRuntimeActionClient(_client=fake)

    decision = await client.evaluate(
        tool_name="Write",
        params={"file_path": "notes.txt", "content": f"token={API_KEY_FIXTURE}"},
    )

    assert API_KEY_FIXTURE not in repr(decision)
    assert decision.target_summary == ""
    assert decision.redacted_summary == ""
    assert decision.action_type == "file.write"
