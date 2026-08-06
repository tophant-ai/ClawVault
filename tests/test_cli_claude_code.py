# ruff: noqa: S101

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from claw_vault.cli import app

PRE_TOOL_COMMAND = "clawvault-claude-code-hook"
USER_PROMPT_COMMAND = "clawvault-claude-code-user-prompt-hook"


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_claude_code_status_json_for_missing_settings(tmp_path) -> None:
    settings_path = tmp_path / "settings.json"

    result = CliRunner().invoke(
        app,
        ["claude-code", "status", "--json", "--settings", str(settings_path)],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["settings_path"] == str(settings_path)
    assert payload["exists"] is False
    assert payload["valid_json"] is True
    assert payload["installed"] is False
    assert payload["pre_tool_use_installed"] is False
    assert payload["user_prompt_submit_installed"] is False


def test_claude_code_install_dry_run_does_not_write(tmp_path) -> None:
    settings_path = tmp_path / "settings.json"

    result = CliRunner().invoke(
        app,
        ["claude-code", "install", "--dry-run", "--settings", str(settings_path)],
    )

    assert result.exit_code == 0
    assert "ClawVault Claude Code hooks will be added" in result.output
    assert not settings_path.exists()


def test_claude_code_install_yes_writes_and_preserves_existing_config(tmp_path) -> None:
    settings_path = tmp_path / "settings.json"
    settings_path.write_text(
        json.dumps(
            {
                "permissions": {"allow": ["Bash(git status)"]},
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Read",
                            "hooks": [{"type": "command", "command": "existing-hook"}],
                        }
                    ],
                    "UserPromptSubmit": [
                        {"hooks": [{"type": "command", "command": "existing-prompt-hook"}]}
                    ],
                },
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        ["claude-code", "install", "--yes", "--settings", str(settings_path)],
    )
    settings = _load(settings_path)

    assert result.exit_code == 0
    assert "ClawVault Claude Code hooks installed" in result.output
    assert settings["permissions"] == {"allow": ["Bash(git status)"]}
    assert settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "existing-hook"
    assert settings["hooks"]["PreToolUse"][1]["matcher"] == "Bash"
    assert settings["hooks"]["PreToolUse"][1]["hooks"][0]["command"] == PRE_TOOL_COMMAND
    assert settings["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"] == (
        "existing-prompt-hook"
    )
    assert settings["hooks"]["UserPromptSubmit"][1]["hooks"][0]["command"] == (
        USER_PROMPT_COMMAND
    )


def test_claude_code_install_accepts_user_prompt_command_override(tmp_path) -> None:
    settings_path = tmp_path / "settings.json"
    prompt_command = str(tmp_path / "bin" / "user-prompt-hook")

    result = CliRunner().invoke(
        app,
        [
            "claude-code",
            "install",
            "--yes",
            "--settings",
            str(settings_path),
            "--user-prompt-command",
            prompt_command,
        ],
    )
    settings = _load(settings_path)

    assert result.exit_code == 0
    assert settings["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"] == prompt_command


def test_claude_code_install_requires_yes_in_non_interactive_mode(tmp_path) -> None:
    settings_path = tmp_path / "settings.json"

    result = CliRunner().invoke(
        app,
        ["claude-code", "install", "--settings", str(settings_path)],
    )

    assert result.exit_code == 1
    assert "pass --yes" in result.output
    assert not settings_path.exists()


def test_claude_code_uninstall_yes_removes_only_clawvault_hooks(tmp_path) -> None:
    settings_path = tmp_path / "settings.json"
    settings_path.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "*",
                            "hooks": [
                                {"type": "command", "command": "existing-hook"},
                                {"type": "command", "command": PRE_TOOL_COMMAND},
                            ],
                        }
                    ],
                    "UserPromptSubmit": [
                        {
                            "hooks": [
                                {"type": "command", "command": "existing-prompt-hook"},
                                {"type": "command", "command": USER_PROMPT_COMMAND},
                            ]
                        }
                    ],
                }
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        ["claude-code", "uninstall", "--yes", "--settings", str(settings_path)],
    )
    settings = _load(settings_path)

    assert result.exit_code == 0
    assert "ClawVault Claude Code hooks removed" in result.output
    assert settings["hooks"]["PreToolUse"] == [
        {"matcher": "*", "hooks": [{"type": "command", "command": "existing-hook"}]}
    ]
    assert settings["hooks"]["UserPromptSubmit"] == [
        {"hooks": [{"type": "command", "command": "existing-prompt-hook"}]}
    ]


def test_claude_code_uninstall_dry_run_does_not_write(tmp_path) -> None:
    settings_path = tmp_path / "settings.json"
    original = {
        "hooks": {
            "PreToolUse": [
                {"matcher": "*", "hooks": [{"type": "command", "command": PRE_TOOL_COMMAND}]}
            ],
            "UserPromptSubmit": [
                {"hooks": [{"type": "command", "command": USER_PROMPT_COMMAND}]}
            ],
        }
    }
    settings_path.write_text(json.dumps(original), encoding="utf-8")

    result = CliRunner().invoke(
        app,
        ["claude-code", "uninstall", "--dry-run", "--settings", str(settings_path)],
    )

    assert result.exit_code == 0
    assert "ClawVault Claude Code hooks will be removed" in result.output
    assert _load(settings_path) == original
