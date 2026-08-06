"""Claude Code PreToolUse hook for Runtime Action Guard."""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any, TextIO

from claw_vault.claude_code.runtime_action_client import ClaudeCodeRuntimeActionClient

_ALLOW_EXIT_CODE = 0
_BLOCK_EXIT_CODE = 2
_HOOK_AGENT_ID = "claude-code-hook"


async def evaluate_hook_payload(
    payload: dict[str, Any],
    *,
    client: ClaudeCodeRuntimeActionClient | None = None,
) -> tuple[int, str]:
    """Evaluate a Claude Code PreToolUse hook payload."""
    tool_name = payload.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name:
        return _block("ClawVault Runtime Action Guard blocked malformed tool call")

    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}

    runtime_client = client or ClaudeCodeRuntimeActionClient()
    try:
        decision = await runtime_client.evaluate(
            tool_name=tool_name,
            params=tool_input,
            agent_id=_HOOK_AGENT_ID,
            session_id=_optional_string(payload.get("session_id")),
        )
    except Exception:
        return _block(
            "ClawVault Runtime Action Guard blocked tool call "
            "because the guard is unavailable"
        )

    if decision.should_block:
        return _block(_decision_message(tool_name, decision.decision, decision.risk_level))
    return _ALLOW_EXIT_CODE, ""


def run_hook(
    *,
    stdin: TextIO = sys.stdin,
    stderr: TextIO = sys.stderr,
    client: ClaudeCodeRuntimeActionClient | None = None,
) -> int:
    try:
        raw_input = stdin.read()
        payload = json.loads(raw_input)
        if not isinstance(payload, dict):
            raise ValueError("hook payload must be an object")
    except Exception:
        exit_code, message = _block("ClawVault Runtime Action Guard blocked malformed hook input")
    else:
        exit_code, message = asyncio.run(evaluate_hook_payload(payload, client=client))

    if message:
        stderr.write(f"{message}\n")
    return exit_code


def main() -> None:
    raise SystemExit(run_hook())


def _decision_message(tool_name: str, decision: str, risk_level: str) -> str:
    safe_tool_name = _safe_tool_name(tool_name)
    if decision == "ask-user":
        return (
            "ClawVault Runtime Action Guard requires confirmation for "
            f"{safe_tool_name} ({risk_level})"
        )
    return f"ClawVault Runtime Action Guard blocked {safe_tool_name} ({risk_level})"


def _safe_tool_name(tool_name: str) -> str:
    cleaned = "".join(char for char in tool_name if char.isalnum() or char in {"_", "-"})
    return cleaned[:40] or "tool call"


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _block(message: str) -> tuple[int, str]:
    return _BLOCK_EXIT_CODE, message


if __name__ == "__main__":
    main()
