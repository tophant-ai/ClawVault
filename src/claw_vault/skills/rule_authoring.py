"""Skill for authoring custom detection rules and test cases via LLM agents.

This Skill is intentionally lightweight: it does not perform LLM calls itself.
Instead, it provides structured helper tools that OpenClaw Agents can use to:

- Normalize free-form requirements into a rule/test-case draft structure
- Validate and persist drafts via the dashboard HTTP API
"""

from __future__ import annotations

from typing import Any

import structlog

from claw_vault.skills.base import (
    BaseSkill,
    SkillManifest,
    SkillPermission,
    SkillResult,
    tool,
)

logger = structlog.get_logger()


class RuleAuthoringSkill(BaseSkill):
    """Tools for managing custom detection rules and test cases."""

    def manifest(self) -> SkillManifest:
        return SkillManifest(
            name="rule_authoring",
            version="0.1.0",
            description="Author and manage custom detection rules and test cases for ClawVault.",
            permissions=[
                SkillPermission.NETWORK,
                SkillPermission.AUDIT_LOG,
            ],
            tags=["security", "rules", "testing"],
        )

    @tool(
        name="summarize_requirement",
        description="Normalize a free-form requirement into a structured draft for a detection rule and optional test cases.",
        parameters={
            "requirement_text": {
                "type": "string",
                "description": "User requirement in natural language (e.g. threat model, scenario, or policy).",
            }
        },
    )
    def summarize_requirement(self, requirement_text: str) -> SkillResult:
        """Return a skeleton structure the LLM can fill for rule+test-case drafts."""
        if not requirement_text.strip():
            return SkillResult(success=False, message="requirement_text is empty")

        # This is intentionally template-like; the LLM is expected to refine it.
        data: dict[str, Any] = {
            "requirement": requirement_text,
            "rule_draft_template": {
                "id": "cp-<slug>",
                "name": "<short name>",
                "category": "GENERIC_SECRET",
                "regex": "<regex here>",
                "risk_score": 7.0,
                "enabled": True,
                "description": "<what this rule catches>",
            },
            "test_case_template": {
                "id": "tc-<slug>-1",
                "name": "<short name>",
                "category": "sensitive",
                "description": "<what this test validates>",
                "text": "<example input that should trigger>",
                "linked_pattern_ids": ["cp-<slug>"],
            },
        }
        return SkillResult(success=True, data=data, message="Generated rule/test-case draft template.")

    @tool(
        name="persist_rule_and_tests",
        description="Persist a custom detection rule and its test cases via the dashboard HTTP API.",
        parameters={
            "dashboard_base_url": {
                "type": "string",
                "description": "Base URL of the ClawVault dashboard API, e.g. http://127.0.0.1:8766/api",
            },
            "pattern": {
                "type": "object",
                "description": "Custom pattern object compatible with /config/custom-patterns.",
            },
            "test_cases": {
                "type": "array",
                "items": {
                    "type": "object",
                },
                "description": "Array of test case objects compatible with /config/custom-test-cases.",
            },
        },
    )
    def persist_rule_and_tests(
        self,
        dashboard_base_url: str,
        pattern: dict[str, Any],
        test_cases: list[dict[str, Any]],
    ) -> SkillResult:
        """Call the dashboard REST API to upsert a custom pattern and test cases."""
        import requests

        if not dashboard_base_url.endswith("/"):
            dashboard_base_url = dashboard_base_url.rstrip("/")

        try:
            pat_res = requests.post(
                f"{dashboard_base_url}/config/custom-patterns",
                json=pattern,
                timeout=5,
            )
            pat_res.raise_for_status()
        except Exception as e:
            logger.error("rule_authoring_pattern_error", error=str(e))
            return SkillResult(success=False, message=f"Failed to persist pattern: {e}")

        persisted_cases: list[dict[str, Any]] = []
        for tc in test_cases or []:
            try:
                tc_res = requests.post(
                    f"{dashboard_base_url}/config/custom-test-cases",
                    json=tc,
                    timeout=5,
                )
                tc_res.raise_for_status()
                persisted_cases.append(tc_res.json())
            except Exception as e:
                logger.error("rule_authoring_test_case_error", error=str(e), test_case=tc.get("id"))

        return SkillResult(
            success=True,
            data={
                "pattern": pattern,
                "test_cases": test_cases,
            },
            message="Pattern and test cases persisted via dashboard API.",
        )

