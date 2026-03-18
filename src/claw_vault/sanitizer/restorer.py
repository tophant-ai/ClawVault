"""Restorer: replaces placeholders back to original values in AI responses."""

from __future__ import annotations

import re

import structlog

logger = structlog.get_logger()

PLACEHOLDER_REGEX = re.compile(r"\[[A-Z_]+_\d+\]")


class Restorer:
    """Restores placeholders in AI responses back to original sensitive values."""

    def restore(self, text: str, mapping: dict[str, str]) -> str:
        """Replace all placeholders in text with their original values.

        Args:
            text: AI response text containing placeholders.
            mapping: placeholder → original value mapping from Sanitizer.

        Returns:
            Text with placeholders restored to original values.
        """
        if not mapping:
            return text

        restored_count = 0
        for placeholder, original in mapping.items():
            if placeholder in text:
                text = text.replace(placeholder, original)
                restored_count += 1

        if restored_count:
            logger.info("response_restored", placeholders_restored=restored_count)

        return text

    def find_placeholders(self, text: str) -> list[str]:
        """Find all placeholder tokens in text."""
        return PLACEHOLDER_REGEX.findall(text)
