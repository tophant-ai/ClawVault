"""Claude Code UserPromptSubmit Guard client."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx

from claw_vault.guard.action import Action
from claw_vault.guard.runtime_action import RuntimeRiskLevel


@dataclass(frozen=True)
class UserPromptClientDecision:
    """User prompt guard decision returned to a Claude Code hook."""

    decision: str
    risk_level: str
    risk_score: float
    reasons: list[str]
    categories: list[str]
    redacted_summary: str
    should_block: bool
    block_reason: str | None = None
    audit_recorded: bool = False


@dataclass(frozen=True)
class ClaudeCodeUserPromptClient:
    """Client for the local ClawVault UserPromptSubmit Guard API."""

    clawvault_url: str = "http://127.0.0.1:8766"
    request_timeout_seconds: float = 2.0
    _client: httpx.AsyncClient | None = field(default=None, repr=False, compare=False)

    async def evaluate(
        self,
        *,
        prompt: str,
        agent_id: str | None = None,
        session_id: str | None = None,
        cwd: str | None = None,
        transcript_path: str | None = None,
    ) -> UserPromptClientDecision:
        payload = {
            "prompt": prompt,
            "agent_id": agent_id,
            "session_id": session_id,
            "cwd": cwd,
            "transcript_path": transcript_path,
        }
        try:
            data = await self._post(payload)
            return _parse_decision(data)
        except Exception:
            return _fail_closed("User Prompt Guard unavailable")

    async def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._client is not None:
            response = await self._client.post("/api/claude-code/user-prompt", json=payload)
            response.raise_for_status()
            data = response.json()
            if isinstance(data, dict):
                return data
            raise ValueError("malformed user prompt decision")

        timeout = httpx.Timeout(self.request_timeout_seconds)
        async with httpx.AsyncClient(
            base_url=self.clawvault_url.rstrip("/"),
            timeout=timeout,
        ) as client:
            response = await client.post("/api/claude-code/user-prompt", json=payload)
            response.raise_for_status()
            data = response.json()
            if isinstance(data, dict):
                return data
            raise ValueError("malformed user prompt decision")


def _parse_decision(data: dict[str, Any]) -> UserPromptClientDecision:
    if (
        not _is_decision(data.get("decision"))
        or not _is_risk_level(data.get("risk_level"))
        or not isinstance(data.get("risk_score"), int | float)
        or not isinstance(data.get("reasons"), list)
        or not isinstance(data.get("categories"), list)
        or not isinstance(data.get("redacted_summary"), str)
        or not isinstance(data.get("should_block"), bool)
        or not isinstance(data.get("audit_recorded"), bool)
    ):
        raise ValueError("malformed user prompt decision")

    if data["decision"] != Action.ALLOW.value and data["should_block"] is not True:
        raise ValueError("unsafe user prompt decision")

    block_reason = data.get("block_reason")
    return UserPromptClientDecision(
        decision=data["decision"],
        risk_level=data["risk_level"],
        risk_score=float(data["risk_score"]),
        reasons=[item for item in data["reasons"] if isinstance(item, str)],
        categories=[item for item in data["categories"] if isinstance(item, str)],
        redacted_summary=data["redacted_summary"],
        should_block=data["should_block"],
        block_reason=block_reason if isinstance(block_reason, str) else None,
        audit_recorded=data["audit_recorded"],
    )


def _fail_closed(reason: str) -> UserPromptClientDecision:
    return UserPromptClientDecision(
        decision=Action.BLOCK.value,
        risk_level=RuntimeRiskLevel.CRITICAL.value,
        risk_score=10.0,
        reasons=[reason],
        categories=["user_prompt_guard_unavailable"],
        redacted_summary="",
        should_block=True,
        block_reason="ClawVault User Prompt Guard unavailable",
        audit_recorded=False,
    )


def _is_decision(value: object) -> bool:
    return value in {item.value for item in Action}


def _is_risk_level(value: object) -> bool:
    return value in {item.value for item in RuntimeRiskLevel}
