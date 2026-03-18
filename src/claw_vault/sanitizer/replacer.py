"""Sanitizer: replaces sensitive data with placeholders before sending to AI."""

from __future__ import annotations

import threading
from collections import defaultdict

import structlog

from claw_vault.detector.patterns import DetectionResult, PatternCategory

logger = structlog.get_logger()

# Category → placeholder prefix mapping
CATEGORY_PREFIX: dict[PatternCategory, str] = {
    PatternCategory.API_KEY: "API_KEY",
    PatternCategory.AWS_CREDENTIAL: "AWS_CRED",
    PatternCategory.PASSWORD: "CREDENTIAL",
    PatternCategory.PRIVATE_IP: "IP_ADDR",
    PatternCategory.JWT_TOKEN: "TOKEN",
    PatternCategory.SSH_KEY: "SSH_KEY",
    PatternCategory.DATABASE_URI: "DB_URI",
    PatternCategory.CREDIT_CARD: "CARD",
    PatternCategory.EMAIL: "EMAIL",
    PatternCategory.PHONE_CN: "PHONE",
    PatternCategory.ID_CARD_CN: "ID_NUM",
    PatternCategory.BLOCKCHAIN_WALLET: "WALLET",
    PatternCategory.BLOCKCHAIN_PRIVATE_KEY: "PRIV_KEY",
    PatternCategory.BLOCKCHAIN_MNEMONIC: "MNEMONIC",
    PatternCategory.GENERIC_SECRET: "SECRET",
}


class Sanitizer:
    """Replaces detected sensitive data with placeholders.

    Maintains a session-scoped mapping for later restoration.
    Thread-safe.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # placeholder → original value
        self._mapping: dict[str, str] = {}
        # category → counter for unique placeholder generation
        self._counters: dict[str, int] = defaultdict(int)

    def sanitize(self, text: str, detections: list[DetectionResult]) -> str:
        """Replace all detected sensitive values with placeholders.

        Args:
            text: Original text containing sensitive data.
            detections: Results from SensitiveDetector.detect().

        Returns:
            Text with sensitive values replaced by placeholders like [API_KEY_1].
        """
        if not detections:
            return text

        # Sort by position descending so replacements don't shift indices
        sorted_detections = sorted(detections, key=lambda d: d.start, reverse=True)

        with self._lock:
            for det in sorted_detections:
                placeholder = self._get_or_create_placeholder(det)
                text = text[: det.start] + placeholder + text[det.end :]

        logger.info(
            "text_sanitized",
            replacements=len(sorted_detections),
            categories=[d.category.value for d in sorted_detections],
        )

        return text

    def _get_or_create_placeholder(self, detection: DetectionResult) -> str:
        """Get existing placeholder for this value or create a new one."""
        # Check if this exact value already has a placeholder
        for ph, val in self._mapping.items():
            if val == detection.value:
                return ph

        prefix = CATEGORY_PREFIX.get(detection.category, "SENSITIVE")
        self._counters[prefix] += 1
        placeholder = f"[{prefix}_{self._counters[prefix]}]"
        self._mapping[placeholder] = detection.value
        return placeholder

    def sanitize_by_value(self, text: str, detections: list[DetectionResult]) -> str:
        """Replace detected sensitive values by string matching (not position).

        Use this when scan was run on extracted content but sanitization
        targets the full body (e.g. proxy scanning last user message
        but sanitizing the entire JSON request).
        """
        if not detections:
            return text

        with self._lock:
            for det in detections:
                placeholder = self._get_or_create_placeholder(det)
                text = text.replace(det.value, placeholder)

        logger.info(
            "text_sanitized_by_value",
            replacements=len(detections),
            categories=[d.category.value for d in detections],
        )

        return text

    @property
    def mapping(self) -> dict[str, str]:
        """Current placeholder → original value mapping (read-only copy)."""
        with self._lock:
            return dict(self._mapping)

    def clear(self) -> None:
        """Clear all mappings (call on session end)."""
        with self._lock:
            self._mapping.clear()
            self._counters.clear()
        logger.info("sanitizer_cleared")
