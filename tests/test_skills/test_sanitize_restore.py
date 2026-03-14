"""Tests for the Sanitize-Restore Skill."""

import pytest

from claw_vault.skills.base import SkillContext
from claw_vault.skills.sanitize_restore import SanitizeRestoreSkill


@pytest.fixture
def skill():
    return SanitizeRestoreSkill(ctx=SkillContext())


class TestSanitizeRestoreSkill:
    def test_manifest(self, skill):
        m = skill.manifest()
        assert m.name == "sanitize-restore"
        assert m.version == "0.1.0"

    def test_list_tools(self, skill):
        tools = skill.list_tools()
        names = {t.name for t in tools}
        assert "sanitize_message" in names
        assert "restore_response" in names
        assert "detect_sensitive" in names
        assert "clear_session" in names

    def test_sanitize_detects_api_key(self, skill):
        result = skill.invoke(
            "sanitize_message", text="key is sk-proj-abc123xyz456def789ghi012jkl345"
        )
        assert result.success
        assert result.data["detections"] >= 1
        assert "sk-proj-abc123xyz456def789ghi012jkl345" not in result.data["sanitized"]
        assert "[API_KEY_" in result.data["sanitized"]

    def test_sanitize_clean_text(self, skill):
        result = skill.invoke("sanitize_message", text="Hello, help me with Python.")
        assert result.success
        assert result.data["detections"] == 0

    def test_sanitize_password_and_ip(self, skill):
        result = skill.invoke(
            "sanitize_message",
            text="password=MySecret123 server=192.168.1.100",
        )
        assert result.success
        assert result.data["detections"] >= 2
        assert "MySecret123" not in result.data["sanitized"]
        assert "192.168.1.100" not in result.data["sanitized"]

    def test_restore_roundtrip(self, skill):
        # Sanitize
        san_result = skill.invoke(
            "sanitize_message",
            text="Use key sk-proj-abc123xyz456def789ghi012jkl345 please",
        )
        sanitized = san_result.data["sanitized"]

        # Simulate AI response with placeholder
        ai_response = f"The issue is with {sanitized.split('key ')[1].split(' ')[0]}"

        # Restore
        res_result = skill.invoke("restore_response", text=ai_response)
        assert res_result.success

    def test_detect_sensitive_readonly(self, skill):
        text = "password=Secret123"
        result = skill.invoke("detect_sensitive", text=text)
        assert result.success
        assert result.data["detections"] >= 1
        # Should not modify sanitizer state
        assert len(skill.ctx.sanitizer.mapping) == 0

    def test_clear_session(self, skill):
        # Create some mappings
        skill.invoke("sanitize_message", text="key sk-proj-abc123xyz456def789ghi012jkl345")
        assert len(skill.ctx.sanitizer.mapping) > 0

        # Clear
        result = skill.invoke("clear_session")
        assert result.success
        assert result.data["cleared"] >= 1
        assert len(skill.ctx.sanitizer.mapping) == 0

    def test_get_mapping_status(self, skill):
        skill.invoke("sanitize_message", text="key sk-proj-abc123xyz456def789ghi012jkl345")
        result = skill.invoke("get_mapping_status")
        assert result.success
        assert result.data["active_mappings"] >= 1

    def test_to_openai_tools_format(self, skill):
        tools = skill.to_openai_tools()
        assert len(tools) >= 4
        for t in tools:
            assert t["type"] == "function"
            assert "function" in t
            assert "name" in t["function"]
            assert t["function"]["name"].startswith("sanitize-restore__")

    def test_to_skill_json(self, skill):
        j = skill.to_skill_json()
        assert j["name"] == "sanitize-restore"
        assert len(j["tools"]) >= 4
