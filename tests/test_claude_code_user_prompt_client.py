# ruff: noqa: S101

"""Tests for Claude Code UserPromptSubmit Guard client."""

from __future__ import annotations

import httpx
import pytest

from claw_vault.claude_code.user_prompt_client import ClaudeCodeUserPromptClient

SAMPLE_SECRET = "sk" + "-proj-" + "abc123xyz456def789ghi012jkl345"


def _decision_payload(**overrides):
    payload = {
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
async def test_user_prompt_client_allows_safe_decision() -> None:
    fake = _FakeAsyncClient()
    client = ClaudeCodeUserPromptClient(_client=fake)

    decision = await client.evaluate(
        prompt="hello",
        agent_id="agent-1",
        session_id="session-1",
        cwd="/tmp/project",
        transcript_path="/tmp/session.jsonl",
    )

    assert decision.decision == "allow"
    assert decision.should_block is False
    assert fake.last_request == {
        "path": "/api/claude-code/user-prompt",
        "json": {
            "prompt": "hello",
            "agent_id": "agent-1",
            "session_id": "session-1",
            "cwd": "/tmp/project",
            "transcript_path": "/tmp/session.jsonl",
        },
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("decision", ["block", "ask_user", "sanitize"])
async def test_user_prompt_client_blocks_non_allow_decisions(decision: str) -> None:
    fake = _FakeAsyncClient(
        _decision_payload(
            decision=decision,
            risk_level="high",
            risk_score=8.0,
            categories=["api_key"],
            should_block=True,
            block_reason="blocked",
        )
    )
    client = ClaudeCodeUserPromptClient(_client=fake)

    result = await client.evaluate(prompt="secret")

    assert result.decision == decision
    assert result.should_block is True
    assert result.risk_level == "high"


@pytest.mark.asyncio
async def test_user_prompt_client_fails_closed_when_unavailable() -> None:
    fake = _FakeAsyncClient(exc=httpx.ConnectError("offline"))
    client = ClaudeCodeUserPromptClient(_client=fake)

    decision = await client.evaluate(prompt="hello")

    assert decision.decision == "block"
    assert decision.should_block is True
    assert decision.risk_level == "critical"
    assert "user_prompt_guard_unavailable" in decision.categories


@pytest.mark.asyncio
async def test_user_prompt_client_fails_closed_on_malformed_response() -> None:
    fake = _FakeAsyncClient({"decision": "allow"})
    client = ClaudeCodeUserPromptClient(_client=fake)

    decision = await client.evaluate(prompt="hello")

    assert decision.decision == "block"
    assert decision.should_block is True


@pytest.mark.asyncio
async def test_user_prompt_client_fails_closed_on_unsafe_response() -> None:
    fake = _FakeAsyncClient(_decision_payload(decision="block", should_block=False))
    client = ClaudeCodeUserPromptClient(_client=fake)

    decision = await client.evaluate(prompt="hello")

    assert decision.decision == "block"
    assert decision.should_block is True
    assert "user_prompt_guard_unavailable" in decision.categories


@pytest.mark.asyncio
async def test_user_prompt_client_filters_non_string_lists() -> None:
    fake = _FakeAsyncClient(
        _decision_payload(
            reasons=["ok", 123],
            categories=["api_key", None],
        )
    )
    client = ClaudeCodeUserPromptClient(_client=fake)

    decision = await client.evaluate(prompt="hello")

    assert decision.reasons == ["ok"]
    assert decision.categories == ["api_key"]


@pytest.mark.asyncio
async def test_user_prompt_client_does_not_add_secret_to_fail_closed_decision() -> None:
    fake = _FakeAsyncClient(exc=httpx.ConnectError("offline"))
    client = ClaudeCodeUserPromptClient(_client=fake)

    decision = await client.evaluate(prompt="Use token " + SAMPLE_SECRET)

    assert SAMPLE_SECRET not in repr(decision)
    assert decision.redacted_summary == ""
