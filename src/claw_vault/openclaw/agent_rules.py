"""Resolve persisted dashboard policy for OpenClaw transcript redaction."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog

from claw_vault.config import DEFAULT_CONFIG_FILE

logger = structlog.get_logger()

DEFAULT_DETECTION_CONFIG: dict[str, bool] = {
    "api_keys": True,
    "aws_credentials": True,
    "blockchain": True,
    "passwords": True,
    "private_ips": True,
    "pii": True,
    "jwt_tokens": True,
    "ssh_keys": True,
    "credit_cards": True,
    "emails": True,
    "generic_secrets": True,
    "dangerous_commands": True,
    "prompt_injection": True,
}


@dataclass(frozen=True)
class AgentRedactionPolicy:
    """Effective persisted policy for one agent."""

    enabled: bool
    guard_mode: str
    auto_sanitize: bool
    detection: dict[str, bool]
    custom_patterns: list[str]


class AgentRuleResolver:
    """Load agent-specific policy from the unified config file."""

    def __init__(
        self,
        global_detection_config: dict[str, bool] | None = None,
        config_file: Path = DEFAULT_CONFIG_FILE,
    ) -> None:
        self._default_detection_config = {
            **DEFAULT_DETECTION_CONFIG,
            **(global_detection_config or {}),
        }
        self._config_file = config_file.expanduser()
        self._lock = threading.Lock()
        self._agents: dict[str, dict[str, Any]] = {}
        self._global_guard_mode = "permissive"
        self._global_auto_sanitize = False
        self._global_enabled = True
        self._global_custom_patterns: list[str] = []
        self._global_detection_overrides: dict[str, bool] = {}
        self._config_loaded_mtime_ns = -1

    def resolve_policy(self, agent_id: str) -> AgentRedactionPolicy:
        """Return the effective persisted policy for the target agent."""
        agent = self._get_agent(agent_id)
        with self._lock:
            detection = dict(self._default_detection_config)
            detection.update(self._load_global_detection())
            enabled = self._global_enabled
            guard_mode = self._global_guard_mode
            auto_sanitize = self._global_auto_sanitize
            custom_patterns = list(self._global_custom_patterns)

        if agent:
            if isinstance(agent.get("enabled"), bool):
                enabled = agent["enabled"]
            if isinstance(agent.get("guard_mode"), str) and agent["guard_mode"]:
                guard_mode = agent["guard_mode"]

            agent_detection = agent.get("detection")
            if isinstance(agent_detection, dict):
                for key, value in agent_detection.items():
                    if isinstance(value, bool):
                        detection[key] = value

        return AgentRedactionPolicy(
            enabled=enabled,
            guard_mode=guard_mode,
            auto_sanitize=auto_sanitize,
            detection=detection,
            custom_patterns=custom_patterns,
        )

    def _get_agent(self, agent_id: str) -> dict[str, Any] | None:
        self._reload_if_needed()
        with self._lock:
            agent = self._agents.get(agent_id)
            if agent is not None:
                return dict(agent)
            for item in self._agents.values():
                if item.get("name") == agent_id:
                    return dict(item)
        return None

    def _reload_if_needed(self) -> None:
        self._reload_config()

    def _reload_config(self) -> None:
        """Reload global config and agents from the unified config file."""
        if not self._config_file.exists():
            with self._lock:
                self._config_loaded_mtime_ns = -1
                self._global_guard_mode = "permissive"
                self._global_auto_sanitize = False
                self._global_enabled = True
                self._global_custom_patterns = []
                self._global_detection_overrides = {}
                self._agents = {}
            return

        try:
            stat_result = self._config_file.stat()
        except OSError as exc:
            logger.warning(
                "openclaw_config_stat_failed", path=str(self._config_file), error=str(exc)
            )
            return

        if stat_result.st_mtime_ns == self._config_loaded_mtime_ns:
            return

        try:
            import yaml  # type: ignore[import-untyped]

            payload = yaml.safe_load(self._config_file.read_text(encoding="utf-8")) or {}
        except Exception as exc:
            logger.warning(
                "openclaw_config_load_failed", path=str(self._config_file), error=str(exc)
            )
            return

        detection = payload.get("detection", {}) if isinstance(payload, dict) else {}
        guard = payload.get("guard", {}) if isinstance(payload, dict) else {}

        # Extract agents from unified config
        agents_section = payload.get("agents", {}) if isinstance(payload, dict) else {}
        entries = agents_section.get("entries", {}) if isinstance(agents_section, dict) else {}

        with self._lock:
            self._global_enabled = bool(detection.get("enabled", True))
            self._global_guard_mode = str(guard.get("mode", "permissive")) or "permissive"
            self._global_auto_sanitize = bool(guard.get("auto_sanitize", False))
            self._global_custom_patterns = self._normalize_custom_patterns(
                detection.get("custom_patterns")
            )
            self._global_detection_overrides = self._extract_detection_overrides(detection)
            self._agents = entries if isinstance(entries, dict) else {}
            self._config_loaded_mtime_ns = stat_result.st_mtime_ns

    def _load_global_detection(self) -> dict[str, bool]:
        overrides = getattr(self, "_global_detection_overrides", {})
        return dict(overrides)

    @staticmethod
    def _extract_detection_overrides(payload: Any) -> dict[str, bool]:
        if not isinstance(payload, dict):
            return {}
        overrides: dict[str, bool] = {}
        for key, value in payload.items():
            if isinstance(value, bool):
                overrides[key] = value
        return overrides

    @staticmethod
    def _normalize_custom_patterns(payload: Any) -> list[str]:
        if not isinstance(payload, list):
            return []
        return [item for item in payload if isinstance(item, str) and item]
