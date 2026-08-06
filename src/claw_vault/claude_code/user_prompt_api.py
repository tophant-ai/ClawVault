"""Claude Code UserPromptSubmit Guard API."""

from __future__ import annotations

import json
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel

from claw_vault.audit.models import AuditRecord
from claw_vault.audit.store import AuditStore
from claw_vault.detector.engine import DetectionEngine, ScanResult
from claw_vault.guard.action import Action, ActionResult
from claw_vault.guard.rule_engine import RuleEngine
from claw_vault.guard.runtime_action import redact_runtime_text

router = APIRouter(tags=["claude-code"])
_audit_store: AuditStore | None = None
_detection_engine: DetectionEngine | None = None
_rule_engine: RuleEngine | None = None
_MAX_USER_PROMPT_PAYLOAD_BYTES = 64 * 1024
_SOURCE_AGENT = "claude-code"
_DEFAULT_AGENT_ID = "claude-code-hook"


class ClaudeCodeUserPromptRequest(BaseModel):
    """Claude Code UserPromptSubmit hook payload for input-stage evaluation."""

    prompt: str
    agent_id: str | None = None
    session_id: str | None = None
    cwd: str | None = None
    transcript_path: str | None = None


class ClaudeCodeUserPromptResponse(BaseModel):
    """User prompt decision returned to the Claude Code hook."""

    decision: str
    risk_level: str
    risk_score: float
    reasons: list[str]
    categories: list[str]
    redacted_summary: str
    should_block: bool
    block_reason: str | None = None
    audit_recorded: bool


@dataclass(frozen=True)
class UserPromptEvaluation:
    action_result: ActionResult
    scan: ScanResult
    redacted_summary: str
    categories: list[str]


def set_user_prompt_dependencies(
    *,
    audit_store: AuditStore | None = None,
    detection_engine: DetectionEngine | None = None,
    rule_engine: RuleEngine | None = None,
) -> None:
    global _audit_store, _detection_engine, _rule_engine
    _audit_store = audit_store
    _detection_engine = detection_engine
    _rule_engine = rule_engine


@router.post("/claude-code/user-prompt", response_model=ClaudeCodeUserPromptResponse)
async def evaluate_claude_code_user_prompt(
    payload: ClaudeCodeUserPromptRequest,
    request: Request,
) -> ClaudeCodeUserPromptResponse:
    _validate_local_request(request)
    _validate_payload_size(payload)
    evaluation = _evaluate_user_prompt(payload)
    audit_recorded = False
    if _audit_store:
        await _audit_store.log(_audit_record(payload, evaluation))
        audit_recorded = True

    action = evaluation.action_result.action.value
    should_block = action != Action.ALLOW.value
    return ClaudeCodeUserPromptResponse(
        decision=action,
        risk_level=_risk_level(evaluation.scan),
        risk_score=float(evaluation.scan.max_risk_score),
        reasons=[evaluation.action_result.reason],
        categories=evaluation.categories,
        redacted_summary=evaluation.redacted_summary,
        should_block=should_block,
        block_reason=_block_reason(action, evaluation) if should_block else None,
        audit_recorded=audit_recorded,
    )


def _evaluate_user_prompt(payload: ClaudeCodeUserPromptRequest) -> UserPromptEvaluation:
    agent_config = _get_agent_config(payload.agent_id or _DEFAULT_AGENT_ID)
    engine = _detection_engine or DetectionEngine()
    rules = _rule_engine or RuleEngine()
    scan = engine.scan_full(payload.prompt, detection_config=agent_config.get("detection"))
    action_result = rules.evaluate(
        scan,
        guard_mode=agent_config.get("guard_mode"),
        auto_sanitize=agent_config.get("auto_sanitize"),
    )
    return UserPromptEvaluation(
        action_result=action_result,
        scan=scan,
        redacted_summary=_redacted_summary(payload.prompt),
        categories=_categories(scan),
    )


def _get_agent_config(agent_id: str | None) -> dict[str, Any]:
    from claw_vault.dashboard.api import get_agent_config

    return get_agent_config(agent_id)


def _audit_record(
    payload: ClaudeCodeUserPromptRequest,
    evaluation: UserPromptEvaluation,
) -> AuditRecord:
    action = evaluation.action_result.action.value
    details = {
        "event_type": "claude_code_user_prompt_guard",
        "source_agent": _SOURCE_AGENT,
        "initiator_type": "user",
        "initiator_id": payload.agent_id or _DEFAULT_AGENT_ID,
        "session_id": payload.session_id,
        "decision": action,
        "risk_level": _risk_level(evaluation.scan),
        "risk_score": float(evaluation.scan.max_risk_score),
        "reasons": [evaluation.action_result.reason],
        "categories": evaluation.categories,
        "redacted_summary": evaluation.redacted_summary,
    }
    return AuditRecord(
        agent_id=payload.agent_id or _DEFAULT_AGENT_ID,
        session_id=payload.session_id or "",
        direction="user_prompt",
        api_endpoint="claude_code_user_prompt_guard",
        method="UserPromptSubmit",
        detections=evaluation.categories,
        risk_level=_risk_level(evaluation.scan),
        risk_score=float(evaluation.scan.max_risk_score),
        action_taken=action,
        details=json.dumps(details, sort_keys=True),
        agent_name=_SOURCE_AGENT,
        user_content=evaluation.redacted_summary,
    )


def _categories(scan: ScanResult) -> list[str]:
    categories: list[str] = []
    for sensitive in scan.sensitive:
        _append_unique(categories, sensitive.pattern_type)
    for command in scan.commands:
        _append_unique(categories, "dangerous_command")
        _append_unique(categories, command.reason)
    for injection in scan.injections:
        _append_unique(categories, injection.injection_type)
    return categories


def _append_unique(items: list[str], value: str) -> None:
    if value and value not in items:
        items.append(value)


def _risk_level(scan: ScanResult) -> str:
    if not scan.has_threats:
        return "low"
    return scan.threat_level.value


def _redacted_summary(prompt: str) -> str:
    redacted = redact_runtime_text(prompt)
    if len(redacted) > 200:
        return redacted[:200] + "..."
    return redacted


def _block_reason(action: str, evaluation: UserPromptEvaluation) -> str:
    if action == Action.SANITIZE.value:
        return "ClawVault User Prompt Guard blocked sanitized prompt before model submission"
    if action == Action.ASK_USER.value:
        return "ClawVault User Prompt Guard requires confirmation before model submission"
    return f"ClawVault User Prompt Guard blocked prompt: {evaluation.action_result.reason}"


def _validate_local_request(request: Request) -> None:
    host = request.client.host if request.client else ""
    try:
        address = ip_address(host)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="user_prompt_local_requests_only",
        ) from exc
    if not address.is_loopback:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="user_prompt_local_requests_only",
        )


def _validate_payload_size(payload: ClaudeCodeUserPromptRequest) -> None:
    total = len(payload.prompt)
    for value in [payload.agent_id, payload.session_id, payload.cwd, payload.transcript_path]:
        if isinstance(value, str):
            total += len(value)
    if total > _MAX_USER_PROMPT_PAYLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="user_prompt_payload_too_large",
        )
