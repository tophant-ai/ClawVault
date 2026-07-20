"""Runtime action models and evaluator for tool-use guard decisions."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from claw_vault.audit.models import AuditRecord
from claw_vault.detector.command import CommandDetector
from claw_vault.detector.command import RiskLevel as CommandRiskLevel
from claw_vault.detector.sensitive import SensitiveDetector
from claw_vault.sanitizer.replacer import Sanitizer


class SourceAgent(StrEnum):
    OPENCLAW = "openclaw"
    CLAUDE_CODE = "claude-code"
    CODEX = "codex"
    UNKNOWN = "unknown"


class RuntimeActionType(StrEnum):
    SHELL_EXECUTE = "shell.execute"
    FILE_READ = "file.read"
    FILE_WRITE = "file.write"
    NETWORK_REQUEST = "network.request"
    TOOL_CALL = "tool.call"


class InitiatorType(StrEnum):
    USER = "user"
    AGENT = "agent"
    SKILL = "skill"
    PLUGIN = "plugin"
    UNKNOWN = "unknown"


class RuntimeDecision(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    ASK_USER = "ask-user"


class RuntimeRiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RuntimeAction:
    source_agent: SourceAgent = SourceAgent.UNKNOWN
    tool_name: str = "custom"
    action_type: RuntimeActionType = RuntimeActionType.TOOL_CALL
    input_summary: str = ""
    raw_input_for_local_detection: str = field(default="", repr=False)
    target: str = ""
    initiator_type: InitiatorType = InitiatorType.UNKNOWN
    initiator_id: str | None = None
    session_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        summary = self.input_summary or self.raw_input_for_local_detection
        self.input_summary = redact_runtime_text(summary)
        self.target = redact_runtime_text(self.target)

    @property
    def target_summary(self) -> str:
        return self.target

    def to_safe_dict(self) -> dict[str, Any]:
        return {
            "source_agent": self.source_agent.value,
            "tool_name": self.tool_name,
            "action_type": self.action_type.value,
            "input_summary": self.input_summary,
            "target_summary": self.target_summary,
            "initiator_type": self.initiator_type.value,
            "initiator_id": self.initiator_id,
            "session_id": self.session_id,
        }


@dataclass
class ActionDecision:
    decision: RuntimeDecision
    risk_level: RuntimeRiskLevel
    reasons: list[str]
    categories: list[str]
    redacted_summary: str
    action_type: RuntimeActionType
    target_summary: str

    def to_audit_details(self, action: RuntimeAction) -> dict[str, object]:
        return {
            "event_type": "runtime_action_guard",
            "source_agent": action.source_agent.value,
            "tool_name": action.tool_name,
            "action_type": self.action_type.value,
            "initiator_type": action.initiator_type.value,
            "initiator_id": action.initiator_id,
            "session_id": action.session_id,
            "decision": self.decision.value,
            "risk_level": self.risk_level.value,
            "reasons": self.reasons,
            "categories": self.categories,
            "redacted_summary": self.redacted_summary,
            "target_summary": self.target_summary,
        }

    def to_audit_record(self, action: RuntimeAction) -> AuditRecord:
        details = self.to_audit_details(action)
        skill_name = None
        if action.initiator_type == InitiatorType.SKILL:
            skill_name = action.initiator_id
        return AuditRecord(
            agent_id=action.initiator_id,
            session_id=action.session_id or "",
            direction="runtime_action",
            api_endpoint="runtime_action_guard",
            method=action.tool_name,
            detections=self.categories,
            risk_level=self.risk_level.value,
            risk_score=_risk_score(self.risk_level),
            action_taken=self.decision.value,
            skill_name=skill_name,
            details=json.dumps(details, sort_keys=True),
            agent_name=action.source_agent.value,
        )


_SENSITIVE_DETECTOR = SensitiveDetector()
_COMMAND_DETECTOR = CommandDetector()

_SENSITIVE_PATH_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"(^|/)\.env(?:\.|$|/)?",
        r"(^|/)\.npmrc$",
        r"(^|/)\.pypirc$",
        r"(^|/)\.ssh(?:/|$)",
        r"id_rsa$",
        r"id_ed25519$",
        r"(^|/)\.aws/credentials$",
        r"(^|/)\.aws/config$",
        r"(^|/)\.config/gcloud(?:/|$)",
        r"(^|/)\.azure(?:/|$)",
        r"(^|/)\.ClawVault/config\.yaml$",
    ]
]

_SHELL_STARTUP_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"(^|/)\.bashrc$",
        r"(^|/)\.zshrc$",
        r"(^|/)\.profile$",
        r"(^|/)\.bash_profile$",
    ]
]

_WEBHOOK_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"discord(?:app)?\.com/api/webhooks",
        r"hooks\.slack\.com/services",
        r"api\.telegram\.org/bot",
        r"webhook\.site",
        r"requestbin",
        r"pipedream\.net",
    ]
]

_DESTRUCTIVE_DELETE_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"\brm\s+-[\w-]*r[\w-]*f[\w-]*\s+/(?:\s|$|\*)",
        r"\brm\s+-[\w-]*r[\w-]*f[\w-]*\s+/\*",
        r"\brm\s+-[\w-]*r[\w-]*f[\w-]*\s+~/?(?:\s|$)",
        r"\brm\s+-[\w-]*r[\w-]*f[\w-]*\s+\$HOME(?:\s|$|/)",
        r"\brm\s+-[\w-]*r[\w-]*f[\w-]*\s+~/\.ClawVault(?:\s|$|/)",
    ]
]

_DOWNLOAD_EXECUTE_PATTERN = re.compile(
    r"\b(?:curl|wget)\b.*\|\s*(?:bash|sh|zsh)\b",
    re.IGNORECASE,
)
_SAFE_SHELL_PATTERN = re.compile(
    r"^\s*(?:ls|pwd|echo(?:\s+[^|;&`$()]*)?|git\s+status)\s*$",
    re.IGNORECASE,
)


def redact_runtime_text(text: str) -> str:
    detections = _SENSITIVE_DETECTOR.detect(text)
    if not detections:
        return text
    sanitizer = Sanitizer()
    return sanitizer.sanitize_by_value(text, detections)


def runtime_action_audit_record(action: RuntimeAction, decision: ActionDecision) -> AuditRecord:
    return decision.to_audit_record(action)


def action_from_simulated_payload(payload: dict[str, Any]) -> RuntimeAction:
    tool_name = str(payload.get("tool_name") or payload.get("tool") or "custom")
    raw_input = payload.get("raw_input") or payload.get("input") or payload.get("tool_input") or ""
    if isinstance(raw_input, dict):
        command = raw_input.get("command")
        path = raw_input.get("path")
        url = raw_input.get("url")
        method = raw_input.get("method")
        body = raw_input.get("body") or raw_input.get("payload")
        raw_parts = [str(part) for part in [method, command, path, url, body] if part]
        raw_text = " ".join(raw_parts)
    else:
        raw_text = str(raw_input)
        path = None
        url = None

    action_type = _coerce_action_type(payload.get("action_type"), tool_name, raw_input)
    target = str(payload.get("target") or path or url or raw_text[:120])
    return RuntimeAction(
        source_agent=_coerce_source_agent(payload.get("source_agent")),
        tool_name=tool_name,
        action_type=action_type,
        input_summary=redact_runtime_text(raw_text),
        raw_input_for_local_detection=raw_text,
        target=target,
        initiator_type=_coerce_initiator_type(payload.get("initiator_type")),
        initiator_id=payload.get("initiator_id"),
        session_id=payload.get("session_id"),
    )


def evaluate_runtime_action(action: RuntimeAction) -> ActionDecision:
    if action.action_type == RuntimeActionType.SHELL_EXECUTE:
        return _evaluate_shell(action)
    if action.action_type == RuntimeActionType.FILE_READ:
        return _evaluate_file_read(action)
    if action.action_type == RuntimeActionType.FILE_WRITE:
        return _evaluate_file_write(action)
    if action.action_type == RuntimeActionType.NETWORK_REQUEST:
        return _evaluate_network(action)
    return _evaluate_tool_call(action)


def _evaluate_shell(action: RuntimeAction) -> ActionDecision:
    text = action.raw_input_for_local_detection
    command_risks = _detect_command_risks(text)
    reasons: list[str] = []
    categories: list[str] = []

    if any(pattern.search(text) for pattern in _DESTRUCTIVE_DELETE_PATTERNS):
        reasons.append("Destructive recursive delete targets a protected or broad path")
        categories.append("destructive_delete")
        return _decision(
            RuntimeDecision.BLOCK,
            RuntimeRiskLevel.CRITICAL,
            reasons,
            categories,
            action,
        )

    if _DOWNLOAD_EXECUTE_PATTERN.search(text):
        reasons.append("Download-and-execute shell pipeline")
        categories.append("download_execute")
        return _decision(
            RuntimeDecision.BLOCK,
            RuntimeRiskLevel.CRITICAL,
            reasons,
            categories,
            action,
        )

    if command_risks:
        top = command_risks[0]
        reasons.append(top.reason)
        categories.append("dangerous_command")
        decision = RuntimeDecision.ASK_USER
        if top.risk_level in {CommandRiskLevel.CRITICAL, CommandRiskLevel.HIGH}:
            decision = RuntimeDecision.BLOCK
        return _decision(
            decision,
            _from_command_risk(top.risk_level),
            reasons,
            categories,
            action,
        )

    if _SAFE_SHELL_PATTERN.match(text):
        return _decision(
            RuntimeDecision.ALLOW,
            RuntimeRiskLevel.LOW,
            ["Low-risk shell command"],
            ["shell"],
            action,
        )

    return _decision(
        RuntimeDecision.ALLOW,
        RuntimeRiskLevel.LOW,
        ["No risky shell pattern detected"],
        ["shell"],
        action,
    )


def _evaluate_file_read(action: RuntimeAction) -> ActionDecision:
    text = _action_text(action)
    if _has_sensitive_path(text):
        return _decision(
            RuntimeDecision.BLOCK,
            RuntimeRiskLevel.HIGH,
            ["Sensitive credential or configuration file read"],
            ["sensitive_file_read"],
            action,
        )
    return _decision(
        RuntimeDecision.ALLOW,
        RuntimeRiskLevel.LOW,
        ["No sensitive read target detected"],
        ["file_read"],
        action,
    )


def _evaluate_file_write(action: RuntimeAction) -> ActionDecision:
    text = _action_text(action)
    if _has_sensitive_path(text):
        return _decision(
            RuntimeDecision.BLOCK,
            RuntimeRiskLevel.HIGH,
            ["Sensitive credential or configuration file write"],
            ["sensitive_file_write"],
            action,
        )
    if _has_shell_startup_path(text):
        shell_risks = _detect_command_risks(text)
        if shell_risks:
            return _decision(
                RuntimeDecision.BLOCK,
                _from_command_risk(shell_risks[0].risk_level),
                ["Suspicious shell startup file modification"],
                ["startup_file_write"],
                action,
            )
        return _decision(
            RuntimeDecision.ASK_USER,
            RuntimeRiskLevel.MEDIUM,
            ["Shell startup file write requires confirmation"],
            ["startup_file_write"],
            action,
        )
    return _decision(
        RuntimeDecision.ALLOW,
        RuntimeRiskLevel.LOW,
        ["No sensitive write target detected"],
        ["file_write"],
        action,
    )


def _evaluate_network(action: RuntimeAction) -> ActionDecision:
    text = _action_text(action)
    has_webhook = _has_webhook_target(text)
    has_secret = bool(_SENSITIVE_DETECTOR.detect(text))
    if has_webhook and has_secret:
        return _decision(
            RuntimeDecision.BLOCK,
            RuntimeRiskLevel.CRITICAL,
            ["Possible secret exfiltration to webhook endpoint"],
            ["secret_exfiltration", "webhook"],
            action,
        )
    if has_webhook:
        return _decision(
            RuntimeDecision.ASK_USER,
            RuntimeRiskLevel.MEDIUM,
            ["Webhook request requires confirmation"],
            ["webhook"],
            action,
        )
    return _decision(
        RuntimeDecision.ALLOW,
        RuntimeRiskLevel.LOW,
        ["No risky network target detected"],
        ["network"],
        action,
    )


def _evaluate_tool_call(action: RuntimeAction) -> ActionDecision:
    text = _action_text(action)
    if not text.strip():
        return _decision(
            RuntimeDecision.ASK_USER,
            RuntimeRiskLevel.MEDIUM,
            ["Unknown tool payload is missing fields"],
            ["unknown_tool"],
            action,
        )
    command_risks = _detect_command_risks(text)
    if command_risks:
        return _decision(
            RuntimeDecision.BLOCK,
            _from_command_risk(command_risks[0].risk_level),
            [command_risks[0].reason],
            ["dangerous_tool_payload"],
            action,
        )
    if _has_sensitive_path(text) or _has_webhook_target(text):
        return _decision(
            RuntimeDecision.ASK_USER,
            RuntimeRiskLevel.MEDIUM,
            ["Unknown tool payload targets sensitive or external collection endpoint"],
            ["unknown_tool"],
            action,
        )
    return _decision(
        RuntimeDecision.ASK_USER,
        RuntimeRiskLevel.MEDIUM,
        ["Unknown tool call requires confirmation"],
        ["unknown_tool"],
        action,
    )


def _decision(
    decision: RuntimeDecision,
    risk_level: RuntimeRiskLevel,
    reasons: list[str],
    categories: list[str],
    action: RuntimeAction,
) -> ActionDecision:
    summary = redact_runtime_text(action.input_summary or action.raw_input_for_local_detection)
    target_summary = redact_runtime_text(action.target_summary)
    return ActionDecision(
        decision=decision,
        risk_level=risk_level,
        reasons=reasons,
        categories=categories,
        redacted_summary=summary,
        action_type=action.action_type,
        target_summary=target_summary,
    )


def _detect_command_risks(text: str):
    return _COMMAND_DETECTOR.detect(redact_runtime_text(text))


def _has_sensitive_path(text: str) -> bool:
    normalized = text.replace("\\", "/")
    return any(pattern.search(normalized) for pattern in _SENSITIVE_PATH_PATTERNS)


def _has_shell_startup_path(text: str) -> bool:
    normalized = text.replace("\\", "/")
    return any(pattern.search(normalized) for pattern in _SHELL_STARTUP_PATTERNS)


def _has_webhook_target(text: str) -> bool:
    return any(pattern.search(text) for pattern in _WEBHOOK_PATTERNS)


def _action_text(action: RuntimeAction) -> str:
    return " ".join(part for part in [action.raw_input_for_local_detection, action.target] if part)


def _from_command_risk(risk_level: CommandRiskLevel) -> RuntimeRiskLevel:
    return RuntimeRiskLevel(risk_level.value)


def _risk_score(risk_level: RuntimeRiskLevel) -> float:
    return {
        RuntimeRiskLevel.LOW: 2.0,
        RuntimeRiskLevel.MEDIUM: 5.0,
        RuntimeRiskLevel.HIGH: 8.0,
        RuntimeRiskLevel.CRITICAL: 10.0,
    }[risk_level]


def _coerce_source_agent(value: object) -> SourceAgent:
    try:
        return SourceAgent(str(value))
    except ValueError:
        return SourceAgent.UNKNOWN


def _coerce_initiator_type(value: object) -> InitiatorType:
    try:
        return InitiatorType(str(value))
    except ValueError:
        return InitiatorType.UNKNOWN


def _coerce_action_type(value: object, tool_name: str, raw_input: object) -> RuntimeActionType:
    if value:
        try:
            return RuntimeActionType(str(value))
        except ValueError:
            return RuntimeActionType.TOOL_CALL
    lowered_tool = tool_name.lower()
    if lowered_tool in {"bash", "shell"}:
        return RuntimeActionType.SHELL_EXECUTE
    if lowered_tool in {"read", "file_read"}:
        return RuntimeActionType.FILE_READ
    if lowered_tool in {"write", "file_write"}:
        return RuntimeActionType.FILE_WRITE
    if lowered_tool in {"network", "http", "fetch"}:
        return RuntimeActionType.NETWORK_REQUEST
    if isinstance(raw_input, dict):
        if raw_input.get("command"):
            return RuntimeActionType.SHELL_EXECUTE
        if raw_input.get("url"):
            return RuntimeActionType.NETWORK_REQUEST
    return RuntimeActionType.TOOL_CALL
