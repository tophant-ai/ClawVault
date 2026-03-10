"""Unified detection engine that orchestrates all detectors."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

import structlog

from claw_vault.config import DetectionConfig
from claw_vault.detector.sensitive import SensitiveDetector
from claw_vault.detector.command import CommandDetector, CommandRisk
from claw_vault.detector.injection import InjectionDetector, InjectionResult
from claw_vault.detector.patterns import DetectionResult

logger = structlog.get_logger()


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
        scores.extend(r.risk_score for r in self.sensitive)
        scores.extend(r.risk_score for r in self.commands)
        scores.extend(r.risk_score for r in self.injections)
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

    def __init__(self, detection_config: DetectionConfig | None = None) -> None:
        # Build sensitive detector according to global detection configuration.
        # When no config is provided (e.g. tests), fall back to built-ins only.
        if detection_config is not None:
            custom_patterns = _build_custom_patterns(detection_config)
            self.sensitive_detector = SensitiveDetector(custom_patterns=custom_patterns)
        else:
            self.sensitive_detector = SensitiveDetector()
        self.command_detector = CommandDetector()
        self.injection_detector = InjectionDetector()

    def scan_request(self, text: str) -> ScanResult:
        """Full scan on outgoing request (user → AI).

        Checks for: sensitive data leakage, prompt injection in input.
        """
        sensitive = self.sensitive_detector.detect(text)
        injections = self.injection_detector.detect(text)
        return ScanResult(sensitive=sensitive, injections=injections)

    def scan_response(self, text: str) -> ScanResult:
        """Full scan on incoming response (AI → user).

        Checks for: dangerous commands in AI suggestions.
        """
        commands = self.command_detector.detect(text)
        return ScanResult(commands=commands)

    def scan_full(self, text: str) -> ScanResult:
        """Run all detectors on the given text."""
        sensitive = self.sensitive_detector.detect(text)
        commands = self.command_detector.detect(text)
        injections = self.injection_detector.detect(text)
        result = ScanResult(
            sensitive=sensitive,
            commands=commands,
            injections=injections,
        )

        if result.has_threats:
            logger.info("scan_complete", **result.summary())

        return result


def _build_custom_patterns(config: DetectionConfig) -> list[DetectionPattern]:
    """Convert DetectionConfig.custom_patterns into DetectionPattern objects."""
    from claw_vault.detector.patterns import DetectionPattern, PatternCategory
    import re

    patterns: list[DetectionPattern] = []
    for item in config.custom_patterns or []:
        # Defensive parsing – ignore malformed entries gracefully.
        try:
            name = item.get("name") or item.get("id") or "custom_pattern"
            regex_str = item.get("regex")
            if not regex_str:
                continue
            category_name = item.get("category") or "GENERIC_SECRET"
            try:
                category = PatternCategory[category_name]
            except KeyError:
                category = PatternCategory.GENERIC_SECRET
            risk_score = float(item.get("risk_score", 7.0))
            enabled = bool(item.get("enabled", True))
            description = item.get("description") or f"Custom pattern: {name}"

            pattern = DetectionPattern(
                category=category,
                name=str(name),
                regex=re.compile(regex_str),
                risk_score=risk_score,
                enabled=enabled,
                description=description,
            )
            patterns.append(pattern)
        except Exception:
            # Never break detection because of a bad custom pattern.
            continue

    return patterns
