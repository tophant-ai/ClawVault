# ruff: noqa: S101

from __future__ import annotations

import json

import pytest

from claw_vault.claude_code.hook_installer import (
    ClaudeCodeHookInstaller,
    ClaudeCodeSettingsError,
)

PRE_TOOL_COMMAND = "clawvault-claude-code-hook"
USER_PROMPT_COMMAND = "clawvault-claude-code-user-prompt-hook"


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _pre_tool_hook_count(settings: dict) -> int:
    count = 0
    for group in settings.get("hooks", {}).get("PreToolUse", []):
        if isinstance(group, dict):
            hooks = group.get("hooks", [])
            count += sum(
                1
                for hook in hooks
                if isinstance(hook, dict) and hook.get("command") == PRE_TOOL_COMMAND
            )
    return count


def _user_prompt_hook_count(settings: dict) -> int:
    count = 0
    for group in settings.get("hooks", {}).get("UserPromptSubmit", []):
        if isinstance(group, dict):
            hooks = group.get("hooks", [])
            count += sum(
                1
                for hook in hooks
                if isinstance(hook, dict) and hook.get("command") == USER_PROMPT_COMMAND
            )
    return count


def test_install_creates_missing_settings_with_both_hooks(tmp_path) -> None:
    settings_path = tmp_path / "settings.json"
    installer = ClaudeCodeHookInstaller(settings_path)

    result = installer.install()
    settings = _load(settings_path)

    assert result.changed is True
    assert result.backup_path is None
    assert _pre_tool_hook_count(settings) == 7
    assert _user_prompt_hook_count(settings) == 1
    assert settings["hooks"]["PreToolUse"][0]["matcher"] == "Bash"
    assert settings["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"] == (
        USER_PROMPT_COMMAND
    )


def test_install_preserves_existing_claude_code_settings(tmp_path) -> None:
    settings_path = tmp_path / "settings.json"
    original = {
        "model": "claude-opus-4-7",
        "permissions": {"allow": ["Bash(git status)"]},
        "mcpServers": {"demo": {"command": "demo"}},
        "statusLine": {"type": "command", "command": "status"},
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [{"type": "command", "command": "existing-hook"}],
                }
            ],
            "UserPromptSubmit": [
                {"hooks": [{"type": "command", "command": "existing-prompt-hook"}]}
            ],
            "PostToolUse": [
                {
                    "matcher": "*",
                    "hooks": [{"type": "command", "command": "post-hook"}],
                }
            ],
        },
    }
    settings_path.write_text(json.dumps(original), encoding="utf-8")

    result = ClaudeCodeHookInstaller(settings_path).install()
    settings = _load(settings_path)

    assert result.changed is True
    assert result.backup_path is not None
    assert result.backup_path.exists()
    assert settings["model"] == original["model"]
    assert settings["permissions"] == original["permissions"]
    assert settings["mcpServers"] == original["mcpServers"]
    assert settings["statusLine"] == original["statusLine"]
    assert settings["hooks"]["PostToolUse"] == original["hooks"]["PostToolUse"]
    assert settings["hooks"]["PreToolUse"][0] == original["hooks"]["PreToolUse"][0]
    assert settings["hooks"]["UserPromptSubmit"][0] == original["hooks"]["UserPromptSubmit"][0]
    assert _pre_tool_hook_count(settings) == 7
    assert _user_prompt_hook_count(settings) == 1


def test_install_is_idempotent_without_extra_backup(tmp_path) -> None:
    settings_path = tmp_path / "settings.json"
    installer = ClaudeCodeHookInstaller(settings_path)

    first = installer.install()
    second = installer.install()
    settings = _load(settings_path)

    assert first.changed is True
    assert second.changed is False
    assert second.backup_path is None
    assert _pre_tool_hook_count(settings) == 7
    assert _user_prompt_hook_count(settings) == 1


def test_uninstall_removes_only_clawvault_hooks(tmp_path) -> None:
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
                },
                "permissions": {"deny": ["Read(.env)"]},
            }
        ),
        encoding="utf-8",
    )

    result = ClaudeCodeHookInstaller(settings_path).uninstall()
    settings = _load(settings_path)

    assert result.changed is True
    assert result.backup_path is not None
    assert _pre_tool_hook_count(settings) == 0
    assert _user_prompt_hook_count(settings) == 0
    assert settings["permissions"] == {"deny": ["Read(.env)"]}
    assert settings["hooks"]["PreToolUse"] == [
        {"matcher": "*", "hooks": [{"type": "command", "command": "existing-hook"}]}
    ]
    assert settings["hooks"]["UserPromptSubmit"] == [
        {"hooks": [{"type": "command", "command": "existing-prompt-hook"}]}
    ]


def test_uninstall_removes_empty_clawvault_hook_groups(tmp_path) -> None:
    settings_path = tmp_path / "settings.json"
    installer = ClaudeCodeHookInstaller(settings_path)
    installer.install()

    result = installer.uninstall()
    settings = _load(settings_path)

    assert result.changed is True
    assert "hooks" not in settings


def test_invalid_json_refuses_install_without_rewrite(tmp_path) -> None:
    settings_path = tmp_path / "settings.json"
    settings_path.write_text('{"hooks": ', encoding="utf-8")

    with pytest.raises(ClaudeCodeSettingsError):
        ClaudeCodeHookInstaller(settings_path).install()

    assert settings_path.read_text(encoding="utf-8") == '{"hooks": '


def test_status_reports_invalid_json(tmp_path) -> None:
    settings_path = tmp_path / "settings.json"
    settings_path.write_text('{"hooks": ', encoding="utf-8")

    status = ClaudeCodeHookInstaller(settings_path).status()

    assert status.exists is True
    assert status.valid_json is False
    assert status.installed is False
    assert status.error is not None


def test_install_upgrades_legacy_wildcard_hook(tmp_path) -> None:
    settings_path = tmp_path / "settings.json"
    settings_path.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "*",
                            "hooks": [{"type": "command", "command": PRE_TOOL_COMMAND}],
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    result = ClaudeCodeHookInstaller(settings_path).install()
    settings = _load(settings_path)
    matchers = [group["matcher"] for group in settings["hooks"]["PreToolUse"]]

    assert result.changed is True
    assert "*" not in matchers
    assert matchers == ["Bash", "Read", "Write", "Edit", "MultiEdit", "WebFetch", "WebSearch"]
    assert _user_prompt_hook_count(settings) == 1


def test_status_reports_partial_install_and_available_absolute_commands(tmp_path) -> None:
    settings_path = tmp_path / "settings.json"
    hook_path = tmp_path / "bin" / "clawvault-claude-code-hook"
    prompt_hook_path = tmp_path / "bin" / "clawvault-claude-code-user-prompt-hook"
    hook_path.parent.mkdir()
    hook_path.write_text("#!/bin/sh\n", encoding="utf-8")
    hook_path.chmod(0o755)
    prompt_hook_path.write_text("#!/bin/sh\n", encoding="utf-8")
    prompt_hook_path.chmod(0o755)
    settings_path.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "*",
                            "hooks": [{"type": "command", "command": str(hook_path)}],
                        }
                    ],
                    "UserPromptSubmit": [
                        {"hooks": [{"type": "command", "command": str(prompt_hook_path)}]}
                    ],
                }
            }
        ),
        encoding="utf-8",
    )

    status = ClaudeCodeHookInstaller(settings_path).status()

    assert status.installed is False
    assert status.pre_tool_use_installed is False
    assert status.user_prompt_submit_installed is True
    assert status.command_available is True
    assert status.user_prompt_command_available is True


def test_uninstall_removes_absolute_hook_commands(tmp_path) -> None:
    settings_path = tmp_path / "settings.json"
    hook_path = tmp_path / "bin" / "clawvault-claude-code-hook"
    prompt_hook_path = tmp_path / "bin" / "clawvault-claude-code-user-prompt-hook"
    settings_path.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "*",
                            "hooks": [
                                {"type": "command", "command": str(hook_path)},
                                {"type": "command", "command": "existing-hook"},
                            ],
                        }
                    ],
                    "UserPromptSubmit": [
                        {
                            "hooks": [
                                {"type": "command", "command": str(prompt_hook_path)},
                                {"type": "command", "command": "existing-prompt-hook"},
                            ]
                        }
                    ],
                }
            }
        ),
        encoding="utf-8",
    )

    result = ClaudeCodeHookInstaller(settings_path).uninstall()
    settings = _load(settings_path)

    assert result.changed is True
    assert settings["hooks"]["PreToolUse"] == [
        {"matcher": "*", "hooks": [{"type": "command", "command": "existing-hook"}]}
    ]
    assert settings["hooks"]["UserPromptSubmit"] == [
        {"hooks": [{"type": "command", "command": "existing-prompt-hook"}]}
    ]


def test_install_rejects_non_object_hooks(tmp_path) -> None:
    settings_path = tmp_path / "settings.json"
    settings_path.write_text(json.dumps({"hooks": []}), encoding="utf-8")

    with pytest.raises(ClaudeCodeSettingsError):
        ClaudeCodeHookInstaller(settings_path).install()

    assert _load(settings_path) == {"hooks": []}


def test_install_rejects_non_array_user_prompt_hooks(tmp_path) -> None:
    settings_path = tmp_path / "settings.json"
    settings_path.write_text(json.dumps({"hooks": {"UserPromptSubmit": {}}}), encoding="utf-8")

    with pytest.raises(ClaudeCodeSettingsError):
        ClaudeCodeHookInstaller(settings_path).install()

    assert _load(settings_path) == {"hooks": {"UserPromptSubmit": {}}}
