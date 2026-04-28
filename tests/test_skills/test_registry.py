"""Tests for the Skill registry and framework."""

import pytest

from claw_vault.skills.base import BaseSkill, SkillContext, SkillManifest, SkillResult, tool
from claw_vault.skills.registry import SkillRegistry


class DummySkill(BaseSkill):
    """A minimal test Skill."""

    def manifest(self) -> SkillManifest:
        return SkillManifest(
            name="dummy-skill",
            version="0.0.1",
            description="A dummy Skill for testing",
        )

    @tool(name="echo", description="Echo back the input text")
    def echo(self, text: str) -> SkillResult:
        return SkillResult(success=True, data={"echo": text}, message=f"Echo: {text}")

    @tool(name="add", description="Add two numbers")
    def add(self, a: int, b: int) -> SkillResult:
        return SkillResult(success=True, data={"result": a + b})


class TestBaseSkill:
    def test_manifest(self):
        skill = DummySkill()
        m = skill.manifest()
        assert m.name == "dummy-skill"

    def test_list_tools(self):
        skill = DummySkill()
        tools = skill.list_tools()
        names = {t.name for t in tools}
        assert "echo" in names
        assert "add" in names

    def test_invoke_echo(self):
        skill = DummySkill()
        result = skill.invoke("echo", text="hello")
        assert result.success
        assert result.data["echo"] == "hello"

    def test_invoke_add(self):
        skill = DummySkill()
        result = skill.invoke("add", a=3, b=4)
        assert result.success
        assert result.data["result"] == 7

    def test_invoke_unknown_tool(self):
        skill = DummySkill()
        result = skill.invoke("nonexistent")
        assert not result.success

    def test_to_openai_tools(self):
        skill = DummySkill()
        tools = skill.to_openai_tools()
        assert len(tools) == 2
        for t in tools:
            assert t["type"] == "function"
            assert t["function"]["name"].startswith("dummy-skill__")

    def test_to_skill_json(self):
        skill = DummySkill()
        j = skill.to_skill_json()
        assert j["name"] == "dummy-skill"
        assert len(j["tools"]) == 2


class TestSkillRegistry:
    def test_register(self):
        registry = SkillRegistry()
        skill = registry.register(DummySkill)
        assert skill.manifest().name == "dummy-skill"
        assert registry.get_skill("dummy-skill") is not None

    def test_unregister(self):
        registry = SkillRegistry()
        registry.register(DummySkill)
        assert registry.unregister("dummy-skill") is True
        assert registry.get_skill("dummy-skill") is None

    def test_list_skills(self):
        registry = SkillRegistry()
        registry.register(DummySkill)
        skills = registry.list_skills()
        assert len(skills) == 1
        assert skills[0]["name"] == "dummy-skill"

    def test_invoke(self):
        registry = SkillRegistry()
        registry.register(DummySkill)
        result = registry.invoke("dummy-skill", "echo", text="test")
        assert result.success
        assert result.data["echo"] == "test"

    def test_invoke_by_full_name(self):
        registry = SkillRegistry()
        registry.register(DummySkill)
        result = registry.invoke_by_full_name("dummy-skill__add", a=5, b=3)
        assert result.success
        assert result.data["result"] == 8

    def test_invoke_unknown_skill(self):
        registry = SkillRegistry()
        result = registry.invoke("nonexistent", "tool")
        assert not result.success

    def test_list_all_tools(self):
        registry = SkillRegistry()
        registry.register(DummySkill)
        tools = registry.list_all_tools()
        assert len(tools) == 2

    def test_register_builtins(self):
        registry = SkillRegistry()
        registry.register_builtins()
        skills = registry.list_skills()
        assert len(skills) >= 7
        names = {s["name"] for s in skills}
        assert "sanitize-restore" in names
        assert "prompt-firewall" in names
        assert "security-scan" in names
        assert "vault-guard" in names
        assert "security-report" in names
        assert "skill-audit" in names
        assert "clawvault_installer" in names

    def test_shared_context(self):
        ctx = SkillContext()
        registry = SkillRegistry(ctx=ctx)
        registry.register(DummySkill)

        # All skills should share the same context
        skill = registry.get_skill("dummy-skill")
        assert skill.ctx is ctx
