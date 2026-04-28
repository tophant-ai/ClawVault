"""Skill registry: discovers, loads, and manages all available Skills."""

from __future__ import annotations

from typing import Optional, cast

import structlog

from claw_vault.skills.base import BaseSkill, SkillContext, SkillResult

logger = structlog.get_logger()


class SkillRegistry:
    """Central registry for all ClawVault Skills.

    Manages Skill lifecycle: register → initialize → invoke → unregister.
    Provides a unified interface for OpenClaw to discover and call tools.
    """

    def __init__(self, ctx: SkillContext | None = None) -> None:
        self._ctx = ctx or SkillContext()
        self._skills: dict[str, BaseSkill] = {}

    def register(self, skill_class: type[BaseSkill]) -> BaseSkill:
        """Instantiate and register a Skill class."""
        skill = skill_class(ctx=self._ctx)
        name = skill.manifest().name
        self._skills[name] = skill
        logger.info("skill_registered", name=name, tools=len(skill.list_tools()))
        return skill

    def unregister(self, name: str) -> bool:
        if name in self._skills:
            del self._skills[name]
            logger.info("skill_unregistered", name=name)
            return True
        return False

    def get_skill(self, name: str) -> Optional[BaseSkill]:
        return self._skills.get(name)

    def list_skills(self) -> list[dict]:
        """List all registered Skills with metadata."""
        return [s.to_skill_json() for s in self._skills.values()]

    def list_all_tools(self) -> list[dict]:
        """List all tools from all registered Skills (OpenAI function format)."""
        tools = []
        for skill in self._skills.values():
            tools.extend(skill.to_openai_tools())
        return tools

    def invoke(self, skill_name: str, tool_name: str, **kwargs) -> SkillResult:
        """Invoke a specific tool on a specific Skill."""
        skill = self._skills.get(skill_name)
        if not skill:
            return SkillResult(success=False, message=f"Skill '{skill_name}' not found")
        return skill.invoke(tool_name, **kwargs)

    def invoke_by_full_name(self, full_name: str, **kwargs) -> SkillResult:
        """Invoke using 'skill_name__tool_name' format (matches OpenAI tool names)."""
        parts = full_name.split("__", 1)
        if len(parts) != 2:
            return SkillResult(success=False, message=f"Invalid tool name format: {full_name}")
        return self.invoke(parts[0], parts[1], **kwargs)

    def register_builtins(self) -> None:
        """Register all built-in ClawVault Skills."""
        from claw_vault.skills.sanitize_restore import SanitizeRestoreSkill
        from claw_vault.skills.prompt_firewall import PromptFirewallSkill
        from claw_vault.skills.security_scan import SecurityScanSkill
        from claw_vault.skills.vault_guard import VaultGuardSkill
        from claw_vault.skills.security_report import SecurityReportSkill
        from claw_vault.skills.skill_audit import SkillAuditSkill
        from claw_vault.skills.clawvault_installer import ClawVaultInstallerSkill

        for cls in [
            SanitizeRestoreSkill,
            PromptFirewallSkill,
            SecurityScanSkill,
            VaultGuardSkill,
            SecurityReportSkill,
            SkillAuditSkill,
            ClawVaultInstallerSkill,
        ]:
            self.register(cast(type[BaseSkill], cls))

        logger.info("builtin_skills_registered", count=len(self._skills))
