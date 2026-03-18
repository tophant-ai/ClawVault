"""Dangerous command detector for AI-generated actions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

import structlog

logger = structlog.get_logger()


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class CommandRisk:
    command: str
    risk_level: RiskLevel
    risk_score: float
    reason: str
    matched_pattern: str


# Dangerous command patterns: (regex, risk_level, risk_score, reason)
DANGEROUS_PATTERNS: list[tuple[str, RiskLevel, float, str]] = [
    # File destruction
    (r"\brm\s+-[^\s]*r[^\s]*f", RiskLevel.CRITICAL, 9.5, "Recursive forced file deletion"),
    (r"\brm\s+-rf\s+/", RiskLevel.CRITICAL, 10.0, "Recursive deletion from root"),
    (r"\brmdir\s+/s", RiskLevel.CRITICAL, 9.5, "Recursive directory deletion (Windows)"),
    (r"\bdel\s+/[sfq]", RiskLevel.HIGH, 8.0, "Forced file deletion (Windows)"),
    (r"\bunlink\s+", RiskLevel.MEDIUM, 6.0, "File unlink operation"),
    # External script execution
    (r"curl\s+.*\|\s*(?:bash|sh|zsh)", RiskLevel.CRITICAL, 9.5, "Piped remote script execution"),
    (r"wget\s+.*\|\s*(?:bash|sh|zsh)", RiskLevel.CRITICAL, 9.5, "Piped remote script execution"),
    (r"curl\s+.*-o\s+.*&&\s*(?:bash|sh|chmod)", RiskLevel.HIGH, 8.5, "Download and execute script"),
    # Privilege escalation
    (r"\bsudo\s+", RiskLevel.HIGH, 7.5, "Privilege escalation via sudo"),
    (r"\bchmod\s+777\s+", RiskLevel.HIGH, 8.0, "Setting world-writable permissions"),
    (r"\bchmod\s+\+s\s+", RiskLevel.CRITICAL, 9.0, "Setting SUID bit"),
    (r"\bchown\s+root", RiskLevel.HIGH, 8.0, "Changing ownership to root"),
    # Data exfiltration
    (r"\bcurl\s+-[^\s]*d\s+.*@", RiskLevel.HIGH, 8.0, "Sending file data via curl"),
    (r"\bwget\s+--post-", RiskLevel.HIGH, 7.5, "POST data via wget"),
    (r"\bnc\s+-[^\s]*\s+\d+", RiskLevel.HIGH, 8.0, "Netcat connection (possible exfil)"),
    # System modification
    (r"\becho\s+.*>\s*/etc/", RiskLevel.CRITICAL, 9.0, "Writing to system config"),
    (r"\bdd\s+if=.*of=/dev/", RiskLevel.CRITICAL, 9.5, "Direct disk write operation"),
    (r"\bmkfs\b", RiskLevel.CRITICAL, 10.0, "Filesystem format operation"),
    (r"\b(?:shutdown|reboot|halt|poweroff)\b", RiskLevel.HIGH, 8.0, "System shutdown/reboot"),
    # Environment / credential access
    (
        r"\benv\b.*(?:SECRET|KEY|TOKEN|PASS)",
        RiskLevel.MEDIUM,
        6.5,
        "Environment variable access (secrets)",
    ),
    (r"\bprintenv\b", RiskLevel.LOW, 4.0, "Environment variable listing"),
    (
        r"\bcat\s+.*(?:\.env|credentials|passwd|shadow)",
        RiskLevel.HIGH,
        8.0,
        "Reading credential files",
    ),
    # Network
    (
        r"\bssh\s+-o\s+StrictHostKeyChecking=no",
        RiskLevel.HIGH,
        7.5,
        "SSH with disabled host key check",
    ),
    (r"\biptables\s+-F", RiskLevel.CRITICAL, 9.0, "Flushing firewall rules"),
    # Python-specific
    (r"os\.system\s*\(", RiskLevel.HIGH, 7.5, "os.system() call — possible command injection"),
    (r"subprocess\.(call|run|Popen)\s*\(", RiskLevel.MEDIUM, 6.0, "Subprocess execution"),
    (r"exec\s*\(", RiskLevel.HIGH, 7.5, "Dynamic code execution via exec()"),
    (r"eval\s*\(", RiskLevel.HIGH, 7.5, "Dynamic code evaluation via eval()"),
]


class CommandDetector:
    """Detects dangerous commands in AI-generated content."""

    def __init__(self) -> None:
        self._compiled: list[tuple[re.Pattern[str], RiskLevel, float, str]] = [
            (re.compile(pat, re.IGNORECASE), level, score, reason)
            for pat, level, score, reason in DANGEROUS_PATTERNS
        ]

    def detect(self, text: str) -> list[CommandRisk]:
        """Scan text for dangerous commands.

        Returns a list of CommandRisk sorted by risk_score descending.
        """
        results: list[CommandRisk] = []

        for regex, level, score, reason in self._compiled:
            for match in regex.finditer(text):
                results.append(
                    CommandRisk(
                        command=match.group(0).strip(),
                        risk_level=level,
                        risk_score=score,
                        reason=reason,
                        matched_pattern=regex.pattern,
                    )
                )

        results.sort(key=lambda r: -r.risk_score)

        if results:
            logger.warning(
                "dangerous_command_detected",
                count=len(results),
                max_risk=results[0].risk_score,
                commands=[r.command[:50] for r in results[:3]],
            )

        return results

    @property
    def max_risk(self) -> float:
        """Convenience: return max risk score across all detections (used after detect)."""
        return 0.0
