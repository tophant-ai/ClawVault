# ruff: noqa: S101, S105

"""Tests for Claude Code RuntimeAction adapter."""

from __future__ import annotations

import json

from claw_vault.claude_code.runtime_action_adapter import runtime_action_from_claude_code
from claw_vault.guard.runtime_action import (
    RuntimeActionType,
    RuntimeDecision,
    SourceAgent,
    evaluate_runtime_action,
    runtime_action_audit_record,
)

SECRET_VALUE = "sk-proj-abc123xyz456def789ghi012jkl345"
EDIT_SECRET = "password=SuperSecretValue"


def test_claude_code_bash_converts_to_shell_execute_without_command_summary() -> None:
    action = runtime_action_from_claude_code(
        tool_name="Bash",
        params={"command": "rm -rf /"},
        agent_id="agent-1",
        session_id="session-1",
    )

    assert action.source_agent == SourceAgent.CLAUDE_CODE
    assert action.action_type == RuntimeActionType.SHELL_EXECUTE
    assert action.raw_input_for_local_detection == "rm -rf /"
    assert action.input_summary == "shell.execute"
    assert action.target_summary == "shell.execute"
    assert action.initiator_id == "agent-1"
    assert action.session_id == "session-1"


def test_claude_code_bash_dangerous_command_blocks() -> None:
    action = runtime_action_from_claude_code(
        tool_name="Bash",
        params={"command": "rm -rf /"},
    )
    decision = evaluate_runtime_action(action)

    assert decision.decision == RuntimeDecision.BLOCK
    assert "destructive_delete" in decision.categories


def test_claude_code_read_converts_to_file_read() -> None:
    action = runtime_action_from_claude_code(
        tool_name="Read",
        params={"file_path": ".env"},
    )

    assert action.action_type == RuntimeActionType.FILE_READ
    assert action.raw_input_for_local_detection == ".env"
    assert action.target_summary == ".env"


def test_claude_code_read_env_blocks() -> None:
    action = runtime_action_from_claude_code(
        tool_name="Read",
        params={"file_path": ".env"},
    )
    decision = evaluate_runtime_action(action)

    assert decision.decision == RuntimeDecision.BLOCK
    assert "sensitive_file_read" in decision.categories


def test_claude_code_write_converts_to_file_write_without_content_summary() -> None:
    action = runtime_action_from_claude_code(
        tool_name="Write",
        params={"file_path": "notes.txt", "content": f"token={SECRET_VALUE}"},
    )

    assert action.action_type == RuntimeActionType.FILE_WRITE
    assert SECRET_VALUE in action.raw_input_for_local_detection
    assert SECRET_VALUE not in action.input_summary
    assert SECRET_VALUE not in action.target_summary
    assert action.input_summary == "write notes.txt"


def test_claude_code_write_secret_content_stays_out_of_audit() -> None:
    action = runtime_action_from_claude_code(
        tool_name="Write",
        params={"file_path": "notes.txt", "content": f"token={SECRET_VALUE}"},
    )
    decision = evaluate_runtime_action(action)
    record = runtime_action_audit_record(action, decision)

    assert SECRET_VALUE not in record.details
    assert "raw_input_for_local_detection" not in record.details


def test_claude_code_edit_converts_to_file_write_without_edit_content_summary() -> None:
    action = runtime_action_from_claude_code(
        tool_name="Edit",
        params={
            "file_path": "settings.py",
            "old_string": "DEBUG = False",
            "new_string": EDIT_SECRET,
        },
    )

    assert action.action_type == RuntimeActionType.FILE_WRITE
    assert EDIT_SECRET in action.raw_input_for_local_detection
    assert EDIT_SECRET not in action.input_summary
    assert EDIT_SECRET not in action.target_summary
    assert action.input_summary == "write settings.py"


def test_claude_code_edit_secret_content_stays_out_of_audit() -> None:
    action = runtime_action_from_claude_code(
        tool_name="Edit",
        params={
            "file_path": "settings.py",
            "old_string": "DEBUG = False",
            "new_string": EDIT_SECRET,
        },
    )
    decision = evaluate_runtime_action(action)
    record = runtime_action_audit_record(action, decision)

    assert EDIT_SECRET not in record.details
    assert "raw_input_for_local_detection" not in record.details


def test_claude_code_webfetch_converts_to_network_request() -> None:
    action = runtime_action_from_claude_code(
        tool_name="WebFetch",
        params={"url": "https://example.com", "prompt": "summarize"},
    )

    assert action.action_type == RuntimeActionType.NETWORK_REQUEST
    assert action.target_summary == "https://example.com"
    assert "summarize" in action.raw_input_for_local_detection


def test_claude_code_websearch_converts_to_network_request() -> None:
    action = runtime_action_from_claude_code(
        tool_name="WebSearch",
        params={"query": "runtime action guard"},
    )

    assert action.action_type == RuntimeActionType.NETWORK_REQUEST
    assert action.target_summary == "runtime action guard"
    assert action.raw_input_for_local_detection == "runtime action guard"


def test_claude_code_unknown_tool_converts_to_tool_call() -> None:
    action = runtime_action_from_claude_code(
        tool_name="CustomTool",
        params={"value": "hello"},
    )

    assert action.action_type == RuntimeActionType.TOOL_CALL
    assert action.target_summary == "{'value': 'hello'}"


def test_claude_code_unknown_tool_payload_audit_is_redacted() -> None:
    action = runtime_action_from_claude_code(
        tool_name="CustomTool",
        params={"value": SECRET_VALUE},
    )
    decision = evaluate_runtime_action(action)
    record = runtime_action_audit_record(action, decision)
    details = json.loads(record.details)

    assert SECRET_VALUE not in record.details
    assert details["source_agent"] == SourceAgent.CLAUDE_CODE.value
    assert details["action_type"] == RuntimeActionType.TOOL_CALL.value
