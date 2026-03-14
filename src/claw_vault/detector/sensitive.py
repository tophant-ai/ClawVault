"""Sensitive data detector using regex pattern matching."""

from __future__ import annotations

import structlog

from claw_vault.detector.patterns import (
    BUILTIN_PATTERNS,
    DetectionPattern,
    DetectionResult,
    PatternCategory,
    mask_value,
)

logger = structlog.get_logger()


class SensitiveDetector:
    """Detects sensitive information in text using compiled regex patterns."""

    def __init__(
        self,
        patterns: list[DetectionPattern] | None = None,
        enabled_categories: set[PatternCategory] | None = None,
    ) -> None:
        self._patterns = patterns or BUILTIN_PATTERNS
        self._enabled_categories = enabled_categories
        if self._enabled_categories:
            self._patterns = [
                p for p in self._patterns if p.category in self._enabled_categories and p.enabled
            ]

    def detect(self, text: str) -> list[DetectionResult]:
        """Scan text for sensitive data patterns.

        Returns a list of DetectionResult sorted by position.
        """
        results: list[DetectionResult] = []

        for pattern in self._patterns:
            if not pattern.enabled:
                continue
            for match in pattern.regex.finditer(text):
                value = match.group(0)
                # If the pattern has a capturing group, use it
                if match.lastindex and match.lastindex >= 1:
                    value = match.group(1)

                result = DetectionResult(
                    pattern_type=pattern.name,
                    category=pattern.category,
                    value=value,
                    masked_value=mask_value(value),
                    start=match.start(),
                    end=match.end(),
                    risk_score=pattern.risk_score,
                    confidence=0.9,
                    description=pattern.description,
                )
                results.append(result)

        # Remove overlapping detections (keep higher risk_score)
        results = self._deduplicate(results)
        results.sort(key=lambda r: r.start)

        if results:
            logger.info(
                "sensitive_data_detected",
                count=len(results),
                categories=[r.category.value for r in results],
            )

        return results

    @staticmethod
    def _deduplicate(results: list[DetectionResult]) -> list[DetectionResult]:
        """Remove overlapping detections, keeping the one with higher risk score."""
        if len(results) <= 1:
            return results

        results.sort(key=lambda r: (-r.risk_score, r.start))
        kept: list[DetectionResult] = []
        used_ranges: list[tuple[int, int]] = []

        for result in results:
            overlaps = any(not (result.end <= s or result.start >= e) for s, e in used_ranges)
            if not overlaps:
                kept.append(result)
                used_ranges.append((result.start, result.end))

        return kept

    def add_custom_pattern(
        self,
        name: str,
        regex_str: str,
        category: PatternCategory = PatternCategory.GENERIC_SECRET,
        risk_score: float = 7.0,
    ) -> None:
        """Add a user-defined detection pattern at runtime."""
        import re

        pattern = DetectionPattern(
            category=category,
            name=f"custom_{name}",
            regex=re.compile(regex_str),
            risk_score=risk_score,
            description=f"Custom pattern: {name}",
        )
        self._patterns.append(pattern)
        logger.info("custom_pattern_added", name=name)
