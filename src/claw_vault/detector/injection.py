"""Prompt injection detector for identifying malicious instructions in input."""

from __future__ import annotations

import re
from dataclasses import dataclass

import structlog

logger = structlog.get_logger()


@dataclass
class InjectionResult:
    injection_type: str
    matched_text: str
    risk_score: float
    confidence: float
    description: str


# Prompt injection patterns: (name, regex, risk_score, description)
INJECTION_PATTERNS: list[tuple[str, str, float, str]] = [
    # Direct instruction override
    (
        "instruction_override",
        r"(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:previous|above|prior|earlier|system)\s+(?:instructions?|prompts?|rules?|constraints?)",
        9.5,
        "Attempts to override system instructions",
    ),
    (
        "new_instructions",
        r"(?:new|updated|revised|real)\s+(?:instructions?|system\s+prompt|directive)",
        8.5,
        "Attempts to inject new instructions",
    ),
    (
        "role_hijack",
        r"(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|your\s+new\s+role\s+is)",
        8.0,
        "Attempts to hijack AI role",
    ),
    # Data exfiltration attempts
    (
        "exfil_request",
        r"(?:output|print|display|reveal|show|send|transmit)\s+(?:all\s+)?(?:api\s*keys?|passwords?|secrets?|credentials?|tokens?)",
        9.0,
        "Attempts to extract sensitive data",
    ),
    (
        "exfil_url",
        r"(?:send|post|upload|transmit)\s+(?:to|data\s+to)\s+https?://",
        9.0,
        "Attempts to send data to external URL",
    ),
    # Encoding evasion
    (
        "base64_payload",
        r"(?:base64|b64)\s*(?:decode|exec|eval|run)",
        7.5,
        "Encoded payload execution attempt",
    ),
    (
        "unicode_evasion",
        r"[\u200b-\u200f\u2028-\u202f\u2060-\u206f\ufeff]",
        6.0,
        "Invisible Unicode characters (possible evasion)",
    ),
    # Delimiter attacks
    (
        "delimiter_escape",
        r"---\s*(?:END|BEGIN|SYSTEM|ADMIN|ROOT)\s*---",
        8.0,
        "Delimiter-based injection attempt",
    ),
    (
        "xml_injection",
        r"<\s*(?:system|admin|root|prompt)\s*>",
        7.5,
        "XML-style prompt injection",
    ),
    (
        "markdown_injection",
        r"\[(?:system|admin|hidden)\]\s*\(",
        7.0,
        "Markdown-style injection attempt",
    ),
    # Jailbreak patterns
    (
        "dan_jailbreak",
        r"(?:DAN|do\s+anything\s+now|developer\s+mode|jailbreak)",
        7.0,
        "Known jailbreak pattern",
    ),
    (
        "hypothetical_bypass",
        r"(?:hypothetically|in\s+theory|for\s+educational\s+purposes?|imagine\s+you\s+could)",
        5.0,
        "Hypothetical framing (possible bypass)",
    ),
]


class InjectionDetector:
    """Detects prompt injection attacks in user or external input."""

    def __init__(self) -> None:
        self._compiled: list[tuple[str, re.Pattern[str], float, str]] = [
            (name, re.compile(pattern, re.IGNORECASE | re.MULTILINE), score, desc)
            for name, pattern, score, desc in INJECTION_PATTERNS
        ]

    def detect(self, text: str) -> list[InjectionResult]:
        """Scan text for prompt injection patterns.

        Returns a list of InjectionResult sorted by risk_score descending.
        """
        results: list[InjectionResult] = []

        for name, regex, score, desc in self._compiled:
            for match in regex.finditer(text):
                results.append(
                    InjectionResult(
                        injection_type=name,
                        matched_text=match.group(0)[:100],
                        risk_score=score,
                        confidence=0.85,
                        description=desc,
                    )
                )

        results.sort(key=lambda r: -r.risk_score)

        if results:
            logger.warning(
                "prompt_injection_detected",
                count=len(results),
                max_risk=results[0].risk_score,
                types=[r.injection_type for r in results[:3]],
            )

        return results

    def is_injection(self, text: str, threshold: float = 7.0) -> bool:
        """Quick check: does the text contain injection above threshold?"""
        results = self.detect(text)
        return any(r.risk_score >= threshold for r in results)
