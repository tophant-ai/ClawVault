"""OpenClaw Runtime Action Guard API."""

from __future__ import annotations

from ipaddress import ip_address
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from claw_vault.audit.store import AuditStore
from claw_vault.claude_code.runtime_action_adapter import runtime_action_from_claude_code
from claw_vault.guard.runtime_action import (
    InitiatorType,
    RuntimeAction,
    RuntimeActionType,
    SourceAgent,
    evaluate_runtime_action,
    runtime_action_audit_record,
)
from claw_vault.openclaw.runtime_action_adapter import runtime_action_from_openclaw

router = APIRouter(tags=["openclaw"])
_audit_store: AuditStore | None = None
_MAX_RUNTIME_ACTION_PAYLOAD_BYTES = 64 * 1024


class OpenClawRuntimeActionRequest(BaseModel):
    """OpenClaw tool action payload for execution-time evaluation."""

    tool_name: str = Field(default="custom")
    params: dict[str, Any] = Field(default_factory=dict)
    agent_id: str | None = None
    session_id: str | None = None


class RuntimeActionRequest(BaseModel):
    """Generic tool action payload for execution-time evaluation."""

    source_agent: str = Field(default=SourceAgent.UNKNOWN.value)
    tool_name: str = Field(default="custom")
    params: dict[str, Any] = Field(default_factory=dict)
    agent_id: str | None = None
    session_id: str | None = None


class OpenClawRuntimeActionResponse(BaseModel):
    """Runtime action decision returned to the OpenClaw hook."""

    decision: str
    risk_level: str
    reasons: list[str]
    categories: list[str]
    action_type: str
    target_summary: str
    redacted_summary: str
    should_block: bool
    block_reason: str | None = None
    audit_recorded: bool


def set_audit_store(audit_store: AuditStore | None) -> None:
    global _audit_store
    _audit_store = audit_store


@router.post("/runtime-action", response_model=OpenClawRuntimeActionResponse)
async def evaluate_generic_runtime_action(
    payload: RuntimeActionRequest,
    request: Request,
) -> OpenClawRuntimeActionResponse:
    _validate_local_request(request)
    _validate_payload_size(payload)
    return await _evaluate_runtime_action(_runtime_action_from_payload(payload))


@router.post("/openclaw/runtime-action", response_model=OpenClawRuntimeActionResponse)
async def evaluate_openclaw_runtime_action(
    payload: OpenClawRuntimeActionRequest,
    request: Request,
) -> OpenClawRuntimeActionResponse:
    _validate_local_request(request)
    _validate_payload_size(payload)
    action = runtime_action_from_openclaw(
        tool_name=payload.tool_name,
        params=payload.params,
        agent_id=payload.agent_id,
        session_id=payload.session_id,
    )
    return await _evaluate_runtime_action(action)


async def _evaluate_runtime_action(action: RuntimeAction) -> OpenClawRuntimeActionResponse:
    decision = evaluate_runtime_action(action)
    audit_recorded = False

    if _audit_store:
        record = runtime_action_audit_record(action, decision)
        await _audit_store.log(record)
        audit_recorded = True

    should_block = decision.decision.value != "allow"
    block_reason = None
    if should_block:
        block_reason = (
            "ClawVault Runtime Action Guard: "
            f"{decision.decision.value} {action.tool_name} ({decision.risk_level.value})"
        )

    return OpenClawRuntimeActionResponse(
        decision=decision.decision.value,
        risk_level=decision.risk_level.value,
        reasons=decision.reasons,
        categories=decision.categories,
        action_type=decision.action_type.value,
        target_summary=decision.target_summary,
        redacted_summary=decision.redacted_summary,
        should_block=should_block,
        block_reason=block_reason,
        audit_recorded=audit_recorded,
    )


def _runtime_action_from_payload(payload: RuntimeActionRequest) -> RuntimeAction:
    source_agent = _source_agent(payload.source_agent)
    if source_agent == SourceAgent.OPENCLAW:
        return runtime_action_from_openclaw(
            tool_name=payload.tool_name,
            params=payload.params,
            agent_id=payload.agent_id,
            session_id=payload.session_id,
        )
    if source_agent == SourceAgent.CLAUDE_CODE:
        return runtime_action_from_claude_code(
            tool_name=payload.tool_name,
            params=payload.params,
            agent_id=payload.agent_id,
            session_id=payload.session_id,
        )
    return _runtime_action_from_unknown(payload)


def _runtime_action_from_unknown(payload: RuntimeActionRequest) -> RuntimeAction:
    raw_text = str(payload.params) if payload.params else ""
    return RuntimeAction(
        source_agent=SourceAgent.UNKNOWN,
        tool_name=payload.tool_name,
        action_type=RuntimeActionType.TOOL_CALL,
        input_summary=raw_text[:120],
        raw_input_for_local_detection=raw_text,
        target=raw_text[:120],
        initiator_type=InitiatorType.AGENT,
        initiator_id=payload.agent_id,
        session_id=payload.session_id,
    )


def _source_agent(value: str) -> SourceAgent:
    try:
        return SourceAgent(value)
    except ValueError:
        return SourceAgent.UNKNOWN


def _validate_local_request(request: Request) -> None:
    host = request.client.host if request.client else ""
    try:
        address = ip_address(host)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="runtime_action_local_requests_only",
        ) from exc
    if not address.is_loopback:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="runtime_action_local_requests_only",
        )


def _validate_payload_size(payload: OpenClawRuntimeActionRequest) -> None:
    total = len(payload.tool_name)
    for key, value in payload.params.items():
        total += len(str(key))
        if isinstance(value, str):
            total += len(value)
        elif isinstance(value, list):
            total += sum(len(item) for item in value if isinstance(item, str))
    if total > _MAX_RUNTIME_ACTION_PAYLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="runtime_action_payload_too_large",
        )
