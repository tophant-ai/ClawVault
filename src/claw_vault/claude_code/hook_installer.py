"""Safe installer for Claude Code Runtime Action Guard hooks."""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

_PRE_TOOL_USE_EVENT = "PreToolUse"
_USER_PROMPT_EVENT = "UserPromptSubmit"
_HOOK_MATCHERS = ("Bash", "Read", "Write", "Edit", "MultiEdit", "WebFetch", "WebSearch")
_DEFAULT_COMMAND = "clawvault-claude-code-hook"
_DEFAULT_USER_PROMPT_COMMAND = "clawvault-claude-code-user-prompt-hook"


@dataclass(frozen=True)
class ClaudeCodeHookStatus:
    settings_path: Path
    exists: bool
    valid_json: bool
    installed: bool
    command: str
    command_available: bool
    pre_tool_use_installed: bool = False
    user_prompt_submit_installed: bool = False
    user_prompt_command: str = _DEFAULT_USER_PROMPT_COMMAND
    user_prompt_command_available: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "settings_path": str(self.settings_path),
            "exists": self.exists,
            "valid_json": self.valid_json,
            "installed": self.installed,
            "command": self.command,
            "command_available": self.command_available,
            "pre_tool_use_installed": self.pre_tool_use_installed,
            "user_prompt_submit_installed": self.user_prompt_submit_installed,
            "user_prompt_command": self.user_prompt_command,
            "user_prompt_command_available": self.user_prompt_command_available,
            "error": self.error,
        }


@dataclass(frozen=True)
class ClaudeCodeHookPlan:
    settings_path: Path
    action: str
    changed: bool
    installed: bool
    backup_required: bool
    message: str

    def to_dict(self) -> dict[str, object]:
        return {
            "settings_path": str(self.settings_path),
            "action": self.action,
            "changed": self.changed,
            "installed": self.installed,
            "backup_required": self.backup_required,
            "message": self.message,
        }


@dataclass(frozen=True)
class ClaudeCodeHookResult:
    settings_path: Path
    action: str
    changed: bool
    installed: bool
    backup_path: Path | None
    message: str

    def to_dict(self) -> dict[str, object]:
        return {
            "settings_path": str(self.settings_path),
            "action": self.action,
            "changed": self.changed,
            "installed": self.installed,
            "backup_path": str(self.backup_path) if self.backup_path else None,
            "message": self.message,
        }


class ClaudeCodeSettingsError(RuntimeError):
    """Raised when Claude Code settings cannot be safely loaded or updated."""


class ClaudeCodeHookInstaller:
    """Install, inspect, and remove the ClawVault Claude Code hooks."""

    def __init__(
        self,
        settings_path: Path | None = None,
        command: str = _DEFAULT_COMMAND,
        user_prompt_command: str = _DEFAULT_USER_PROMPT_COMMAND,
    ) -> None:
        self.settings_path = (settings_path or default_user_settings_path()).expanduser().resolve(
            strict=False
        )
        self.command = command
        self.user_prompt_command = user_prompt_command

    def status(self) -> ClaudeCodeHookStatus:
        try:
            settings = self._load_settings()
        except ClaudeCodeSettingsError as exc:
            return ClaudeCodeHookStatus(
                settings_path=self.settings_path,
                exists=self.settings_path.exists(),
                valid_json=False,
                installed=False,
                command=self.command,
                command_available=self._command_available(),
                user_prompt_command=self.user_prompt_command,
                user_prompt_command_available=self._user_prompt_command_available(),
                error=str(exc),
            )

        pre_tool_installed = self._has_desired_pre_tool_use_hooks(settings)
        user_prompt_installed = self._has_desired_user_prompt_submit_hook(settings)
        return ClaudeCodeHookStatus(
            settings_path=self.settings_path,
            exists=self.settings_path.exists(),
            valid_json=True,
            installed=pre_tool_installed and user_prompt_installed,
            command=self.command,
            command_available=self._command_available(settings),
            pre_tool_use_installed=pre_tool_installed,
            user_prompt_submit_installed=user_prompt_installed,
            user_prompt_command=self.user_prompt_command,
            user_prompt_command_available=self._user_prompt_command_available(settings),
        )

    def plan_install(self, backup: bool = True) -> ClaudeCodeHookPlan:
        settings = self._load_settings()
        installed = self._has_desired_hooks(settings)
        changed = not installed
        return ClaudeCodeHookPlan(
            settings_path=self.settings_path,
            action="install",
            changed=changed,
            installed=True,
            backup_required=backup and changed and self.settings_path.exists(),
            message="ClawVault Claude Code hooks are already installed"
            if installed
            else "ClawVault Claude Code hooks will be added",
        )

    def install(self, backup: bool = True) -> ClaudeCodeHookResult:
        settings = self._load_settings()
        if self._has_desired_hooks(settings):
            return ClaudeCodeHookResult(
                settings_path=self.settings_path,
                action="install",
                changed=False,
                installed=True,
                backup_path=None,
                message="ClawVault Claude Code hooks are already installed",
            )

        updated = self._with_hook(settings)
        backup_path = self._backup() if backup and self.settings_path.exists() else None
        self._write_settings(updated)
        return ClaudeCodeHookResult(
            settings_path=self.settings_path,
            action="install",
            changed=True,
            installed=True,
            backup_path=backup_path,
            message="ClawVault Claude Code hooks installed",
        )

    def plan_uninstall(self, backup: bool = True) -> ClaudeCodeHookPlan:
        settings = self._load_settings()
        installed = bool(self._installed_hook_commands(settings))
        return ClaudeCodeHookPlan(
            settings_path=self.settings_path,
            action="uninstall",
            changed=installed,
            installed=False,
            backup_required=backup and installed and self.settings_path.exists(),
            message="ClawVault Claude Code hooks will be removed"
            if installed
            else "ClawVault Claude Code hooks are not installed",
        )

    def uninstall(self, backup: bool = True) -> ClaudeCodeHookResult:
        settings = self._load_settings()
        if not self._installed_hook_commands(settings):
            return ClaudeCodeHookResult(
                settings_path=self.settings_path,
                action="uninstall",
                changed=False,
                installed=False,
                backup_path=None,
                message="ClawVault Claude Code hooks are not installed",
            )

        updated = self._without_hook(settings)
        backup_path = self._backup() if backup and self.settings_path.exists() else None
        self._write_settings(updated)
        return ClaudeCodeHookResult(
            settings_path=self.settings_path,
            action="uninstall",
            changed=True,
            installed=False,
            backup_path=backup_path,
            message="ClawVault Claude Code hooks removed",
        )

    def desired_hook_groups(self) -> list[dict[str, object]]:
        return [
            {
                "matcher": matcher,
                "hooks": [self.desired_hook_entry()],
            }
            for matcher in _HOOK_MATCHERS
        ]

    def desired_hook_group(self) -> dict[str, object]:
        return self.desired_hook_groups()[0]

    def desired_hook_entry(self) -> dict[str, str]:
        return {"type": "command", "command": self.command}

    def desired_user_prompt_hook_group(self) -> dict[str, object]:
        return {"hooks": [self.desired_user_prompt_hook_entry()]}

    def desired_user_prompt_hook_entry(self) -> dict[str, str]:
        return {"type": "command", "command": self.user_prompt_command}

    def _load_settings(self) -> dict[str, Any]:
        if not self.settings_path.exists():
            return {}
        try:
            with self.settings_path.open(encoding="utf-8") as handle:
                data = json.load(handle)
        except json.JSONDecodeError as exc:
            raise ClaudeCodeSettingsError(
                f"Invalid Claude Code settings JSON: {self.settings_path}"
            ) from exc
        except OSError as exc:
            raise ClaudeCodeSettingsError(
                f"Unable to read Claude Code settings: {self.settings_path}"
            ) from exc
        if not isinstance(data, dict):
            raise ClaudeCodeSettingsError("Claude Code settings must be a JSON object")
        return data

    def _with_hook(self, settings: dict[str, Any]) -> dict[str, Any]:
        updated = self._without_hook(settings)
        hooks = updated.setdefault("hooks", {})
        if not isinstance(hooks, dict):
            raise ClaudeCodeSettingsError("Claude Code settings hooks must be a JSON object")

        pre_tool_use = hooks.setdefault(_PRE_TOOL_USE_EVENT, [])
        if not isinstance(pre_tool_use, list):
            raise ClaudeCodeSettingsError("Claude Code PreToolUse hooks must be a JSON array")
        pre_tool_use.extend(self.desired_hook_groups())

        user_prompt_submit = hooks.setdefault(_USER_PROMPT_EVENT, [])
        if not isinstance(user_prompt_submit, list):
            raise ClaudeCodeSettingsError("Claude Code UserPromptSubmit hooks must be a JSON array")
        user_prompt_submit.append(self.desired_user_prompt_hook_group())
        return updated

    def _without_hook(self, settings: dict[str, Any]) -> dict[str, Any]:
        updated = _json_clone(settings)
        hooks = updated.get("hooks")
        if hooks is None:
            return updated
        if not isinstance(hooks, dict):
            raise ClaudeCodeSettingsError("Claude Code settings hooks must be a JSON object")

        self._remove_hook_entries(hooks, _PRE_TOOL_USE_EVENT, self._is_pre_tool_hook_entry)
        self._remove_hook_entries(hooks, _USER_PROMPT_EVENT, self._is_user_prompt_hook_entry)
        if not hooks:
            updated.pop("hooks", None)
        return updated

    def _remove_hook_entries(self, hooks: dict[str, Any], event: str, predicate) -> None:
        groups = hooks.get(event)
        if groups is None:
            return
        if not isinstance(groups, list):
            raise ClaudeCodeSettingsError(f"Claude Code {event} hooks must be a JSON array")

        filtered_groups: list[object] = []
        for group in groups:
            if not isinstance(group, dict):
                filtered_groups.append(group)
                continue
            group_hooks = group.get("hooks")
            if not isinstance(group_hooks, list):
                filtered_groups.append(group)
                continue
            remaining_hooks = [hook for hook in group_hooks if not predicate(hook)]
            if remaining_hooks:
                new_group = dict(group)
                new_group["hooks"] = remaining_hooks
                filtered_groups.append(new_group)

        if filtered_groups:
            hooks[event] = filtered_groups
        else:
            hooks.pop(event, None)

    def _has_desired_hooks(self, settings: dict[str, Any]) -> bool:
        return self._has_desired_pre_tool_use_hooks(
            settings
        ) and self._has_desired_user_prompt_submit_hook(settings)

    def _has_desired_pre_tool_use_hooks(self, settings: dict[str, Any]) -> bool:
        hooks = settings.get("hooks")
        if not isinstance(hooks, dict):
            return False
        pre_tool_use = hooks.get(_PRE_TOOL_USE_EVENT)
        if not isinstance(pre_tool_use, list):
            return False
        found_matchers: set[str] = set()
        for group in pre_tool_use:
            if not isinstance(group, dict):
                continue
            matcher = group.get("matcher")
            group_hooks = group.get("hooks")
            if not isinstance(matcher, str) or not isinstance(group_hooks, list):
                continue
            if matcher in _HOOK_MATCHERS and any(
                self._is_pre_tool_hook_entry(hook) for hook in group_hooks
            ):
                found_matchers.add(matcher)
        return found_matchers == set(_HOOK_MATCHERS)

    def _has_desired_user_prompt_submit_hook(self, settings: dict[str, Any]) -> bool:
        hooks = settings.get("hooks")
        if not isinstance(hooks, dict):
            return False
        user_prompt_submit = hooks.get(_USER_PROMPT_EVENT)
        if not isinstance(user_prompt_submit, list):
            return False
        for group in user_prompt_submit:
            if not isinstance(group, dict):
                continue
            group_hooks = group.get("hooks")
            if isinstance(group_hooks, list) and any(
                self._is_user_prompt_hook_entry(hook) for hook in group_hooks
            ):
                return True
        return False

    def _is_hook_entry(self, hook: object) -> bool:
        return self._is_pre_tool_hook_entry(hook) or self._is_user_prompt_hook_entry(hook)

    def _is_pre_tool_hook_entry(self, hook: object) -> bool:
        return _is_command_entry(hook, self.command, _DEFAULT_COMMAND)

    def _is_user_prompt_hook_entry(self, hook: object) -> bool:
        return _is_command_entry(hook, self.user_prompt_command, _DEFAULT_USER_PROMPT_COMMAND)

    def _backup(self) -> Path:
        timestamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
        backup_path = self.settings_path.with_name(
            f"{self.settings_path.name}.clawvault-backup-{timestamp}"
        )
        shutil.copy2(self.settings_path, backup_path)
        return backup_path

    def _write_settings(self, settings: dict[str, Any]) -> None:
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        content = json.dumps(settings, indent=2, ensure_ascii=False, sort_keys=False) + "\n"
        _atomic_write_text(self.settings_path, content)

    def _command_available(self, settings: dict[str, Any] | None = None) -> bool:
        commands = [self.command]
        if settings is not None:
            commands.extend(self._installed_pre_tool_commands(settings))
        return any(_command_available(command) for command in commands)

    def _user_prompt_command_available(self, settings: dict[str, Any] | None = None) -> bool:
        commands = [self.user_prompt_command]
        if settings is not None:
            commands.extend(self._installed_user_prompt_commands(settings))
        return any(_command_available(command) for command in commands)

    def _installed_hook_commands(self, settings: dict[str, Any]) -> list[str]:
        return [
            *self._installed_pre_tool_commands(settings),
            *self._installed_user_prompt_commands(settings),
        ]

    def _installed_pre_tool_commands(self, settings: dict[str, Any]) -> list[str]:
        return self._installed_commands(settings, _PRE_TOOL_USE_EVENT, self._is_pre_tool_hook_entry)

    def _installed_user_prompt_commands(self, settings: dict[str, Any]) -> list[str]:
        return self._installed_commands(
            settings,
            _USER_PROMPT_EVENT,
            self._is_user_prompt_hook_entry,
        )

    def _installed_commands(self, settings: dict[str, Any], event: str, predicate) -> list[str]:
        commands: list[str] = []
        hooks = settings.get("hooks")
        if not isinstance(hooks, dict):
            return commands
        groups = hooks.get(event)
        if not isinstance(groups, list):
            return commands
        for group in groups:
            if not isinstance(group, dict):
                continue
            group_hooks = group.get("hooks")
            if not isinstance(group_hooks, list):
                continue
            for hook in group_hooks:
                if predicate(hook) and isinstance(hook, dict):
                    command = hook.get("command")
                    if isinstance(command, str):
                        commands.append(command)
        return commands


def _is_command_entry(hook: object, expected: str, default_name: str) -> bool:
    if not isinstance(hook, dict) or hook.get("type") != "command":
        return False
    command = hook.get("command")
    if not isinstance(command, str):
        return False
    command_name = command.split()[0]
    expected_name = expected.split()[0]
    if command_name == expected_name:
        return True
    return expected == default_name and Path(command_name).name == default_name


def _command_available(command: str) -> bool:
    command_name = command.split()[0]
    path = Path(command_name).expanduser()
    if path.is_absolute() or "/" in command_name:
        return path.exists() and os.access(path, os.X_OK)
    return shutil.which(command_name) is not None


def default_user_settings_path() -> Path:
    return Path.home() / ".claude" / "settings.json"


def project_settings_path(cwd: Path | None = None) -> Path:
    return (cwd or Path.cwd()) / ".claude" / "settings.json"


def _json_clone(value: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(value))


def _atomic_write_text(path: Path, content: str) -> None:
    original_mode = path.stat().st_mode if path.exists() else 0o600
    temp_path: Path | None = None
    with NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f"{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as tmp:
        tmp.write(content)
        tmp.flush()
        os.fsync(tmp.fileno())
        temp_path = Path(tmp.name)
    try:
        os.chmod(temp_path, original_mode)
        os.replace(temp_path, path)
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
