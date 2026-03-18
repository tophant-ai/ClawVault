"""Tests for per-agent transcript redaction rules."""

from __future__ import annotations

from pathlib import Path

from claw_vault.openclaw.agent_rules import AgentRuleResolver


def test_resolve_policy_agent_override_expected_merge(tmp_path: Path) -> None:
    agents_file = tmp_path / "agents.yaml"
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """
detection:
  enabled: true
  passwords: true
  emails: false
guard:
  mode: strict
  auto_sanitize: true
""".strip(),
        encoding="utf-8",
    )
    agents_file.write_text(
        """
version: "1.0"
agents:
  builder:
    name: builder
    guard_mode: permissive
    detection:
      passwords: false
      emails: true
""".strip(),
        encoding="utf-8",
    )
    resolver = AgentRuleResolver(
        global_detection_config={"passwords": True, "emails": False},
        agents_file=agents_file,
        config_file=config_file,
    )

    result = resolver.resolve_policy("builder")

    assert result.detection["passwords"] is False
    assert result.detection["emails"] is True
    assert result.guard_mode == "permissive"
    assert result.auto_sanitize is True


def test_resolve_policy_missing_agent_expected_global_fallback(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """
detection:
  enabled: true
  passwords: true
  emails: false
guard:
  mode: interactive
  auto_sanitize: false
""".strip(),
        encoding="utf-8",
    )
    resolver = AgentRuleResolver(
        global_detection_config={"passwords": True, "emails": False},
        agents_file=tmp_path / "missing.yaml",
        config_file=config_file,
    )

    result = resolver.resolve_policy("unknown")

    assert result.detection["passwords"] is True
    assert result.detection["emails"] is False
    assert result.guard_mode == "interactive"
