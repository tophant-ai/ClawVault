"""Decide whether a transcript line should be deleted based on persisted dashboard policy."""

from __future__ import annotations

from pathlib import Path

from claw_vault.detector.engine import DetectionEngine
from claw_vault.guard.action import Action
from claw_vault.guard.rule_engine import RuleEngine
from claw_vault.guard.rules_store import load_rules
from claw_vault.openclaw.agent_rules import AgentRedactionPolicy, AgentRuleResolver


class SessionLinePolicyEvaluator:
    """Evaluate transcript lines against persisted dashboard policy."""

    def __init__(
        self,
        resolver: AgentRuleResolver | None = None,
        rules_file: Path | None = None,
    ) -> None:
        self._resolver = resolver or AgentRuleResolver()
        self._rules_file = rules_file

    def should_delete_line(self, agent_id: str, text: str) -> bool:
        """Return whether the given transcript line should be deleted."""
        policy = self._resolver.resolve_policy(agent_id)
        if not policy.enabled:
            return False

        scan = self._build_engine(policy).scan_request(text, detection_config=policy.detection)
        if not scan.sensitive:
            return False

        rule_engine = RuleEngine(mode=policy.guard_mode, auto_sanitize=policy.auto_sanitize)
        if self._rules_file is not None:
            rule_engine.set_rules(load_rules(self._rules_file))

        custom_result = rule_engine.evaluate_custom_rules(scan)
        if custom_result is not None:
            return custom_result.action != Action.ALLOW

        return True

    def _build_engine(self, policy: AgentRedactionPolicy) -> DetectionEngine:
        engine = DetectionEngine()
        for index, pattern in enumerate(policy.custom_patterns):
            engine.sensitive_detector.add_custom_pattern(
                name=f"dashboard_{index}",
                regex_str=pattern,
            )
        return engine
