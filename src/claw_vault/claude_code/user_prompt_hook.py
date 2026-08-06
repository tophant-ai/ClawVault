"""Claude Code UserPromptSubmit hook for User Prompt Guard."""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any, TextIO

from claw_vault.claude_code.user_prompt_client import ClaudeCodeUserPromptClient

_ALLOW_EXIT_CODE = 0
_BLOCK_EXIT_CODE = 2
_HOOK_AGENT_ID = "claude-code-hook"


async def evaluate_user_prompt_payload(
    payload: dict[str, Any],
    *,
    client: ClaudeCodeUserPromptClient | None = None,
) -> tuple[int, str]:
    """Evaluate a Claude Code UserPromptSubmit hook payload."""
    prompt = payload.get("prompt")
    if not isinstance(prompt, str):
        return _block("ClawVault User Prompt Guard blocked malformed prompt")

    user_prompt_client = client or ClaudeCodeUserPromptClient()
    try:
        decision = await user_prompt_client.evaluate(
            prompt=prompt,
            agent_id=_HOOK_AGENT_ID,
            session_id=_optional_string(payload.get("session_id")),
            cwd=_optional_string(payload.get("cwd")),
            transcript_path=_optional_string(payload.get("transcript_path")),
        )
    except Exception:
        return _block(
            "ClawVault User Prompt Guard blocked prompt because the guard is unavailable"
        )

    if decision.should_block:
        return _block(
            _decision_message(decision.decision, decision.risk_level, decision.categories)
        )
    return _ALLOW_EXIT_CODE, ""


def run_hook(
    *,
    stdin: TextIO = sys.stdin,
    stderr: TextIO = sys.stderr,
    client: ClaudeCodeUserPromptClient | None = None,
) -> int:
    try:
        raw_input = stdin.read()
        payload = json.loads(raw_input)
        if not isinstance(payload, dict):
            raise ValueError("hook payload must be an object")
    except Exception:
        exit_code, message = _block("ClawVault User Prompt Guard blocked malformed hook input")
    else:
        exit_code, message = asyncio.run(evaluate_user_prompt_payload(payload, client=client))

    if message:
        stderr.write(f"{message}\n")
    return exit_code


def main() -> None:
    raise SystemExit(run_hook())


def _decision_message(decision: str, risk_level: str, categories: list[str]) -> str:
    category_text = _safe_category_text(categories)
    if decision == "ask_user":
        return (
            "ClawVault User Prompt Guard requires confirmation before model submission "
            f"({risk_level}{category_text})"
        )
    if decision == "sanitize":
        return (
            "ClawVault User Prompt Guard blocked sanitized prompt before model submission "
            f"({risk_level}{category_text})"
        )
    return f"ClawVault User Prompt Guard blocked prompt ({risk_level}{category_text})"


def _safe_category_text(categories: list[str]) -> str:
    safe_categories = []
    for category in categories[:3]:
        cleaned = "".join(char for char in category if char.isalnum() or char in {"_", "-"})
        if cleaned:
            safe_categories.append(cleaned[:40])
    if not safe_categories:
        return ""
    return "; " + ", ".join(safe_categories)


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _block(message: str) -> tuple[int, str]:
    return _BLOCK_EXIT_CODE, message


if __name__ == "__main__":
    main()
