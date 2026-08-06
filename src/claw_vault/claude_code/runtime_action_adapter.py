"""Claude Code RuntimeAction adapter."""

from __future__ import annotations

from typing import Any

from claw_vault.guard.runtime_action import (
    InitiatorType,
    RuntimeAction,
    RuntimeActionType,
    SourceAgent,
)


def runtime_action_from_claude_code(
    *,
    tool_name: str,
    params: dict[str, Any],
    agent_id: str | None = None,
    session_id: str | None = None,
) -> RuntimeAction:
    action_type = _claude_code_action_type(tool_name)
    raw_text = _claude_code_raw_text(action_type, params)
    target = _claude_code_target(action_type, params, raw_text)

    return RuntimeAction(
        source_agent=SourceAgent.CLAUDE_CODE,
        tool_name=tool_name,
        action_type=action_type,
        input_summary=_claude_code_input_summary(action_type, target),
        raw_input_for_local_detection=raw_text,
        target=target,
        initiator_type=InitiatorType.AGENT,
        initiator_id=agent_id,
        session_id=session_id,
    )


def _claude_code_action_type(tool_name: str) -> RuntimeActionType:
    lowered = tool_name.lower()
    if lowered == "bash":
        return RuntimeActionType.SHELL_EXECUTE
    if lowered == "read":
        return RuntimeActionType.FILE_READ
    if lowered in {"write", "edit", "multiedit"}:
        return RuntimeActionType.FILE_WRITE
    if lowered in {"webfetch", "websearch"}:
        return RuntimeActionType.NETWORK_REQUEST
    return RuntimeActionType.TOOL_CALL


def _claude_code_raw_text(action_type: RuntimeActionType, params: dict[str, Any]) -> str:
    if action_type == RuntimeActionType.SHELL_EXECUTE:
        return _first_string(params, "command")
    if action_type == RuntimeActionType.FILE_READ:
        return _first_string(params, "file_path", "path")
    if action_type == RuntimeActionType.FILE_WRITE:
        path = _first_string(params, "file_path", "path")
        content = _first_string(params, "content", "new_string", "old_string")
        edits = _multiedit_raw_text(params)
        return " ".join(part for part in [path, content, edits] if part)
    if action_type == RuntimeActionType.NETWORK_REQUEST:
        return _network_raw_text(params)
    return str(params) if params else ""


def _claude_code_input_summary(action_type: RuntimeActionType, target: str) -> str:
    if action_type == RuntimeActionType.SHELL_EXECUTE:
        return "shell.execute"
    if action_type == RuntimeActionType.FILE_READ:
        return f"read {target}"
    if action_type == RuntimeActionType.FILE_WRITE:
        return f"write {target}"
    if action_type == RuntimeActionType.NETWORK_REQUEST:
        return f"network {target}"
    return target


def _claude_code_target(
    action_type: RuntimeActionType,
    params: dict[str, Any],
    raw_text: str,
) -> str:
    if action_type == RuntimeActionType.SHELL_EXECUTE:
        return "shell.execute"
    if action_type in {RuntimeActionType.FILE_READ, RuntimeActionType.FILE_WRITE}:
        return _first_string(params, "file_path", "path")
    if action_type == RuntimeActionType.NETWORK_REQUEST:
        return _first_string(params, "url", "query")[:120]
    return raw_text[:120]


def _network_raw_text(params: dict[str, Any]) -> str:
    url = _first_string(params, "url")
    query = _first_string(params, "query")
    prompt = _first_string(params, "prompt")
    return " ".join(part for part in [url, query, prompt] if part)


def _multiedit_raw_text(params: dict[str, Any]) -> str:
    edits = params.get("edits")
    if not isinstance(edits, list):
        return ""

    parts: list[str] = []
    for edit in edits:
        if not isinstance(edit, dict):
            continue
        for key in ("old_string", "new_string"):
            value = edit.get(key)
            if isinstance(value, str):
                parts.append(value)
    return " ".join(parts)


def _first_string(params: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = params.get(key)
        if isinstance(value, str):
            return value
    return ""
