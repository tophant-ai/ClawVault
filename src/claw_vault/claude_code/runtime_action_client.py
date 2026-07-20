"""Claude Code Runtime Action Guard client."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx

from claw_vault.guard.runtime_action import RuntimeDecision, RuntimeRiskLevel


@dataclass(frozen=True)
class RuntimeActionClientDecision:
    """Runtime Action Guard decision returned to a Claude Code caller."""

    decision: str
    risk_level: str
    reasons: list[str]
    categories: list[str]
    action_type: str
    target_summary: str
    redacted_summary: str
    should_block: bool
    block_reason: str | None = None
    audit_recorded: bool = False


@dataclass(frozen=True)
class ClaudeCodeRuntimeActionClient:
    """Client for the local ClawVault Runtime Action Guard API."""

    clawvault_url: str = "http://127.0.0.1:8766"
    request_timeout_seconds: float = 2.0
    source_agent: str = "claude-code"
    _client: httpx.AsyncClient | None = field(default=None, repr=False, compare=False)

    async def evaluate(
        self,
        *,
        tool_name: str,
        params: dict[str, Any],
        agent_id: str | None = None,
        session_id: str | None = None,
    ) -> RuntimeActionClientDecision:
        payload = {
            "source_agent": self.source_agent,
            "tool_name": tool_name,
            "params": params,
            "agent_id": agent_id,
            "session_id": session_id,
        }
        try:
            data = await self._post(payload)
            return _parse_decision(data, tool_name)
        except Exception:
            return _fail_closed(tool_name, "Runtime Action Guard unavailable")

    async def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._client is not None:
            response = await self._client.post("/api/runtime-action", json=payload)
            response.raise_for_status()
            data = response.json()
            if isinstance(data, dict):
                return data
            raise ValueError("malformed runtime action decision")

        timeout = httpx.Timeout(self.request_timeout_seconds)
        async with httpx.AsyncClient(
            base_url=self.clawvault_url.rstrip("/"),
            timeout=timeout,
        ) as client:
            response = await client.post("/api/runtime-action", json=payload)
            response.raise_for_status()
            data = response.json()
            if isinstance(data, dict):
                return data
            raise ValueError("malformed runtime action decision")


def _parse_decision(data: dict[str, Any], tool_name: str) -> RuntimeActionClientDecision:
    if (
        not _is_decision(data.get("decision"))
        or not _is_risk_level(data.get("risk_level"))
        or not isinstance(data.get("reasons"), list)
        or not isinstance(data.get("categories"), list)
        or not isinstance(data.get("action_type"), str)
        or not isinstance(data.get("target_summary"), str)
        or not isinstance(data.get("redacted_summary"), str)
        or not isinstance(data.get("should_block"), bool)
        or not isinstance(data.get("audit_recorded"), bool)
    ):
        raise ValueError("malformed runtime action decision")

    if data["decision"] != RuntimeDecision.ALLOW.value and data["should_block"] is not True:
        raise ValueError("unsafe runtime action decision")

    block_reason = data.get("block_reason")
    return RuntimeActionClientDecision(
        decision=data["decision"],
        risk_level=data["risk_level"],
        reasons=[item for item in data["reasons"] if isinstance(item, str)],
        categories=[item for item in data["categories"] if isinstance(item, str)],
        action_type=data["action_type"],
        target_summary=data["target_summary"],
        redacted_summary=data["redacted_summary"],
        should_block=data["should_block"],
        block_reason=block_reason if isinstance(block_reason, str) else None,
        audit_recorded=data["audit_recorded"],
    )


def _fail_closed(tool_name: str, reason: str) -> RuntimeActionClientDecision:
    return RuntimeActionClientDecision(
        decision=RuntimeDecision.BLOCK.value,
        risk_level=RuntimeRiskLevel.CRITICAL.value,
        reasons=[reason],
        categories=["runtime_action_guard_unavailable"],
        action_type=_fallback_action_type(tool_name),
        target_summary="",
        redacted_summary="",
        should_block=True,
        block_reason=f"ClawVault Runtime Action Guard unavailable for {tool_name}",
        audit_recorded=False,
    )


def _fallback_action_type(tool_name: str) -> str:
    lowered = tool_name.lower()
    if lowered == "bash":
        return "shell.execute"
    if lowered == "read":
        return "file.read"
    if lowered in {"write", "edit"}:
        return "file.write"
    if lowered in {"webfetch", "websearch"}:
        return "network.request"
    return "tool.call"


def _is_decision(value: object) -> bool:
    return value in {item.value for item in RuntimeDecision}


def _is_risk_level(value: object) -> bool:
    return value in {item.value for item in RuntimeRiskLevel}
