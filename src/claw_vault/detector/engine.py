"""Unified detection engine that orchestrates all detectors."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

import structlog

from claw_vault.detector.command import CommandDetector, CommandRisk
from claw_vault.detector.injection import InjectionDetector, InjectionResult
from claw_vault.detector.patterns import DetectionResult, PatternCategory
from claw_vault.detector.sensitive import SensitiveDetector

if TYPE_CHECKING:
    pass

logger = structlog.get_logger()


DETECTION_CONFIG_TO_CATEGORIES: dict[str, set[PatternCategory]] = {
    "api_keys": {PatternCategory.API_KEY},
    "passwords": {PatternCategory.PASSWORD, PatternCategory.DATABASE_URI},
    "private_ips": {PatternCategory.PRIVATE_IP},
    "pii": {
        PatternCategory.PHONE_CN,
        PatternCategory.ID_CARD_CN,
        PatternCategory.CREDIT_CARD,
        PatternCategory.EMAIL,
    },
    "jwt_tokens": {PatternCategory.JWT_TOKEN},
    "ssh_keys": {PatternCategory.SSH_KEY},
    "credit_cards": {PatternCategory.CREDIT_CARD},
    "emails": {PatternCategory.EMAIL},
    "generic_secrets": {PatternCategory.GENERIC_SECRET},
    "aws_credentials": {PatternCategory.AWS_CREDENTIAL},
    "blockchain": {
        PatternCategory.BLOCKCHAIN_WALLET,
        PatternCategory.BLOCKCHAIN_PRIVATE_KEY,
        PatternCategory.BLOCKCHAIN_MNEMONIC,
    },
}


class ThreatLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ScanResult:
    """Aggregated result from all detectors."""

    sensitive: list[DetectionResult] = field(default_factory=list)
    commands: list[CommandRisk] = field(default_factory=list)
    injections: list[InjectionResult] = field(default_factory=list)

    @property
    def threat_level(self) -> ThreatLevel:
        max_score = self.max_risk_score
        if max_score >= 9.0:
            return ThreatLevel.CRITICAL
        elif max_score >= 7.0:
            return ThreatLevel.HIGH
        elif max_score >= 4.0:
            return ThreatLevel.MEDIUM
        elif max_score > 0:
            return ThreatLevel.LOW
        return ThreatLevel.SAFE

    @property
    def max_risk_score(self) -> float:
        scores: list[float] = []
        scores.extend(result.risk_score for result in self.sensitive)
        scores.extend(result.risk_score for result in self.commands)
        scores.extend(result.risk_score for result in self.injections)
        return max(scores) if scores else 0.0

    @property
    def has_threats(self) -> bool:
        return bool(self.sensitive or self.commands or self.injections)

    @property
    def total_detections(self) -> int:
        return len(self.sensitive) + len(self.commands) + len(self.injections)

    def summary(self) -> dict:
        return {
            "threat_level": self.threat_level.value,
            "max_risk_score": self.max_risk_score,
            "sensitive_count": len(self.sensitive),
            "command_count": len(self.commands),
            "injection_count": len(self.injections),
            "total": self.total_detections,
        }


class DetectionEngine:
    """Orchestrates all detection sub-engines for comprehensive scanning."""

    def __init__(self) -> None:
        self.sensitive_detector = SensitiveDetector()
        self.command_detector = CommandDetector()
        self.injection_detector = InjectionDetector()

    def scan_request(
        self, text: str, detection_config: dict[str, bool] | None = None
    ) -> ScanResult:
        """Full scan on outgoing request (user → AI)."""
        sensitive = self._filter_sensitive(self.sensitive_detector.detect(text), detection_config)
        injections = []
        if detection_config is None or detection_config.get("prompt_injection", True):
            injections = self.injection_detector.detect(text)
        return ScanResult(sensitive=sensitive, injections=injections)

    def scan_response(
        self, text: str, detection_config: dict[str, bool] | None = None
    ) -> ScanResult:
        """Full scan on incoming response (AI → user)."""
        commands = []
        if detection_config is None or detection_config.get("dangerous_commands", True):
            commands = self.command_detector.detect(text)
        return ScanResult(commands=commands)

    def scan_full(self, text: str, detection_config: dict[str, bool] | None = None) -> ScanResult:
        """Run all detectors on the given text."""
        sensitive = self._filter_sensitive(self.sensitive_detector.detect(text), detection_config)
        commands = []
        if detection_config is None or detection_config.get("dangerous_commands", True):
            commands = self.command_detector.detect(text)
        injections = []
        if detection_config is None or detection_config.get("prompt_injection", True):
            injections = self.injection_detector.detect(text)

        result = ScanResult(
            sensitive=sensitive,
            commands=commands,
            injections=injections,
        )

        if result.has_threats:
            logger.info("scan_complete", **result.summary())

        return result

    @staticmethod
    def _filter_sensitive(
        results: list[DetectionResult], detection_config: dict[str, bool] | None
    ) -> list[DetectionResult]:
        """Filter sensitive detection results based on detection config."""
        if detection_config is None:
            return results

        enabled_categories: set[PatternCategory] = set()
        for config_key, enabled in detection_config.items():
            if enabled and config_key in DETECTION_CONFIG_TO_CATEGORIES:
                enabled_categories.update(DETECTION_CONFIG_TO_CATEGORIES[config_key])

        if not enabled_categories:
            return results

        return [result for result in results if result.category in enabled_categories]
