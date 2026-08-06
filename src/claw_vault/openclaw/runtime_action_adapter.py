"""OpenClaw RuntimeAction adapter."""

from __future__ import annotations

from typing import Any

from claw_vault.guard.runtime_action import (
    InitiatorType,
    RuntimeAction,
    RuntimeActionType,
    SourceAgent,
)


def runtime_action_from_openclaw(
    *,
    tool_name: str,
    params: dict[str, Any],
    agent_id: str | None = None,
    session_id: str | None = None,
) -> RuntimeAction:
    action_type = _openclaw_action_type(tool_name)
    raw_text = _openclaw_raw_text(action_type, params)
    target = _openclaw_target(action_type, params, raw_text)

    return RuntimeAction(
        source_agent=SourceAgent.OPENCLAW,
        tool_name=tool_name,
        action_type=action_type,
        input_summary=_openclaw_input_summary(action_type, target),
        raw_input_for_local_detection=raw_text,
        target=target,
        initiator_type=InitiatorType.AGENT,
        initiator_id=agent_id,
        session_id=session_id,
    )


def _openclaw_action_type(tool_name: str) -> RuntimeActionType:
    lowered = tool_name.lower()
    if lowered == "bash":
        return RuntimeActionType.SHELL_EXECUTE
    if lowered == "read":
        return RuntimeActionType.FILE_READ
    if lowered == "write":
        return RuntimeActionType.FILE_WRITE
    return RuntimeActionType.TOOL_CALL


def _openclaw_raw_text(action_type: RuntimeActionType, params: dict[str, Any]) -> str:
    if action_type == RuntimeActionType.SHELL_EXECUTE:
        return _first_string(params, "command", "cmd", "script")
    if action_type in {RuntimeActionType.FILE_READ, RuntimeActionType.FILE_WRITE}:
        path = _first_string(params, "path", "file", "file_path", "filename", "filepath")
        content = _first_string(params, "content", "text", "data", "input")
        return " ".join(part for part in [path, content] if part)
    return str(params) if params else ""


def _openclaw_input_summary(action_type: RuntimeActionType, target: str) -> str:
    if action_type == RuntimeActionType.SHELL_EXECUTE:
        return target
    if action_type == RuntimeActionType.FILE_READ:
        return f"read {target}"
    if action_type == RuntimeActionType.FILE_WRITE:
        return f"write {target}"
    return target


def _openclaw_target(
    action_type: RuntimeActionType,
    params: dict[str, Any],
    raw_text: str,
) -> str:
    if action_type == RuntimeActionType.SHELL_EXECUTE:
        return raw_text[:120]
    if action_type in {RuntimeActionType.FILE_READ, RuntimeActionType.FILE_WRITE}:
        return _first_string(params, "path", "file", "file_path", "filename", "filepath")
    return raw_text[:120]


def _first_string(params: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = params.get(key)
        if isinstance(value, str):
            return value
    return ""
