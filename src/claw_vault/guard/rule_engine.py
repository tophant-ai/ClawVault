"""Local rule engine for determining actions based on detection results."""

from __future__ import annotations

import structlog

from claw_vault.detector.engine import ScanResult, ThreatLevel
from claw_vault.guard.action import Action, ActionResult
from claw_vault.guard.rules_store import RuleCondition, RuleConfig, load_rules

logger = structlog.get_logger()

PATTERN_TYPE_ALIASES: dict[str, set[str]] = {
    "aws_access_key": {"aws_access_key", "aws_access_key_id"},
    "aws_access_key_id": {"aws_access_key", "aws_access_key_id"},
}


class RuleEngine:
    """Evaluates scan results and determines the appropriate action."""

    def __init__(self, mode: str = "interactive", auto_sanitize: bool = True) -> None:
        self._mode = mode
        self._auto_sanitize = auto_sanitize
        self._rules: list[RuleConfig] = load_rules()

    @property
    def rules(self) -> list[RuleConfig]:
        return list(self._rules)

    def set_rules(self, rules: list[RuleConfig]) -> None:
        """Replace in-memory rules (used by dashboard API)."""
        self._rules = list(rules)

    def evaluate_custom_rules(self, scan: ScanResult) -> ActionResult | None:
        """Evaluate only custom rules and return the first matched result."""
        if not self._rules:
            return None
        return self._evaluate_custom_rules(scan, self._build_details(scan))

    def evaluate(
        self,
        scan: ScanResult,
        guard_mode: str | None = None,
        auto_sanitize: bool | None = None,
    ) -> ActionResult:
        """Determine action based on scan results and mode."""
        effective_mode = guard_mode if guard_mode is not None else self._mode
        effective_auto_sanitize = (
            auto_sanitize if auto_sanitize is not None else self._auto_sanitize
        )

        if not scan.has_threats:
            return ActionResult(
                action=Action.ALLOW,
                reason="No threats detected",
                risk_score=0.0,
                details=[],
            )

        threat = scan.threat_level
        score = scan.max_risk_score
        details = self._build_details(scan)

        if self._rules:
            custom_result = self._evaluate_custom_rules(scan, details)
            if custom_result is not None:
                return custom_result

        has_injections = bool(scan.injections)
        has_commands = bool(scan.commands)
        has_sensitive_only = bool(scan.sensitive) and not has_injections and not has_commands

        if effective_mode == "strict":
            return self._strict_evaluate(threat, score, details, scan)
        elif effective_mode == "permissive":
            return self._permissive_evaluate(
                threat, score, details, scan, has_sensitive_only, effective_auto_sanitize
            )
        else:
            return self._interactive_evaluate(
                threat,
                score,
                details,
                scan,
                has_injections,
                has_commands,
                has_sensitive_only,
                effective_auto_sanitize,
            )

    def _strict_evaluate(
        self,
        threat: ThreatLevel,
        score: float,
        details: list[str],
        scan: ScanResult,
    ) -> ActionResult:
        return ActionResult(Action.BLOCK, "Strict mode: threat blocked", score, details)

    def _interactive_evaluate(
        self,
        threat: ThreatLevel,
        score: float,
        details: list[str],
        scan: ScanResult,
        has_injections: bool,
        has_commands: bool,
        has_sensitive_only: bool,
        auto_sanitize: bool,
    ) -> ActionResult:
        if has_injections:
            return ActionResult(Action.BLOCK, "Prompt injection blocked", score, details)
        if has_sensitive_only and scan.sensitive:
            if auto_sanitize:
                return ActionResult(
                    Action.SANITIZE, "Sensitive data auto-sanitized", score, details
                )
            return ActionResult(
                Action.ASK_USER,
                "Sensitive data detected — enable auto-sanitize for masking",
                score,
                details,
            )
        if has_commands:
            return ActionResult(
                Action.ASK_USER, "Dangerous command detected — review needed", score, details
            )
        if scan.sensitive and auto_sanitize:
            return ActionResult(Action.SANITIZE, "Sensitive data auto-sanitized", score, details)
        return ActionResult(Action.ASK_USER, "Threats detected — review needed", score, details)

    def _permissive_evaluate(
        self,
        threat: ThreatLevel,
        score: float,
        details: list[str],
        scan: ScanResult,
        has_sensitive_only: bool,
        auto_sanitize: bool,
    ) -> ActionResult:
        if has_sensitive_only and scan.sensitive and auto_sanitize:
            return ActionResult(
                Action.SANITIZE, "Sensitive data auto-sanitized (permissive)", score, details
            )
        return ActionResult(Action.ALLOW, "Permissive mode: allowed with logging", score, details)

    def _evaluate_custom_rules(self, scan: ScanResult, details: list[str]) -> ActionResult | None:
        """Evaluate user-defined rules from rules.yaml."""
        for rule in self._rules:
            if not rule.enabled:
                continue
            cond: RuleCondition = rule.when
            try:
                if not self._matches_condition(cond, scan):
                    continue
            except Exception as exc:
                logger.warning("guard.rules.eval_error", rule_id=rule.id, error=str(exc))
                continue

            try:
                action = Action(rule.action)
            except ValueError:
                logger.warning("guard.rules.invalid_action", rule_id=rule.id, action=rule.action)
                continue

            logger.info(
                "guard.rules.matched",
                rule_id=rule.id,
                rule_name=rule.name,
                action=action.value,
                max_risk_score=scan.max_risk_score,
            )
            return ActionResult(
                action=action,
                reason=f"Rule '{rule.name}' matched",
                risk_score=scan.max_risk_score,
                details=details,
            )

        return None

    @staticmethod
    def _matches_condition(cond: RuleCondition, scan: ScanResult) -> bool:
        """Check if a rule condition matches a given scan result."""
        has_sensitive = bool(scan.sensitive)
        has_commands = bool(scan.commands)
        has_injections = bool(scan.injections)

        if cond.has_sensitive is not None and cond.has_sensitive != has_sensitive:
            return False
        if cond.has_commands is not None and cond.has_commands != has_commands:
            return False
        if cond.has_injections is not None and cond.has_injections != has_injections:
            return False
        if cond.threat_levels is not None and scan.threat_level.value not in cond.threat_levels:
            return False
        if cond.min_risk_score is not None and scan.max_risk_score < cond.min_risk_score:
            return False

        if cond.pattern_types:
            matched = False
            for sensitive in scan.sensitive:
                if RuleEngine._pattern_type_matches(sensitive.pattern_type, cond.pattern_types):
                    matched = True
                    break
            if not matched:
                for command in scan.commands:
                    if command.reason in cond.pattern_types:
                        matched = True
                        break
            if not matched:
                for injection in scan.injections:
                    if injection.injection_type in cond.pattern_types:
                        matched = True
                        break
            if not matched:
                return False

        return True

    @staticmethod
    def _pattern_type_matches(pattern_type: str, expected_types: list[str]) -> bool:
        aliases = PATTERN_TYPE_ALIASES.get(pattern_type, {pattern_type})
        return any(expected in aliases for expected in expected_types)

    @staticmethod
    def _build_details(scan: ScanResult) -> list[str]:
        details: list[str] = []
        for sensitive in scan.sensitive:
            details.append(f"Sensitive: {sensitive.description} ({sensitive.masked_value})")
        for command in scan.commands:
            details.append(f"Command: {command.reason} — `{command.command[:40]}`")
        for injection in scan.injections:
            details.append(f"Injection: {injection.description}")
        return details
