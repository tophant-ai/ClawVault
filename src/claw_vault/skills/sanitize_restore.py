"""Sanitize-Restore Skill: intercept sensitive data in conversations,
replace with placeholders before sending to AI, restore in responses.

Covers scenarios: A1 (conversation-sensitive interception) + A2 (masking and restoration)
"""

from __future__ import annotations

from claw_vault.skills.base import (
    BaseSkill,
    SkillManifest,
    SkillPermission,
    SkillResult,
    tool,
)


class SanitizeRestoreSkill(BaseSkill):
    """Sensitive data sanitization and restoration for AI conversations.

    This Skill hooks into user ↔ AI message flow:
    1. Before sending: detect sensitive data → replace with [PLACEHOLDER]
    2. After receiving: restore [PLACEHOLDER] → original values
    3. User sees seamless conversation; AI never sees real secrets.
    """

    def manifest(self) -> SkillManifest:
        return SkillManifest(
            name="sanitize-restore",
            version="0.1.0",
            description="Detect and sanitize sensitive data in conversations, restore on response",
            permissions=[
                SkillPermission.READ_CHAT,
                SkillPermission.MODIFY_CHAT,
            ],
            tags=["security", "privacy", "sanitization", "pii"],
            homepage="https://github.com/tophant-ai/ClawVault",
        )

    @tool(
        name="sanitize_message",
        description=(
            "Scan a message for sensitive data (API keys, passwords, IPs, PII) "
            "and replace them with safe placeholders. Returns sanitized text "
            "and a mapping for later restoration."
        ),
        examples=[
            {
                "input": {"text": "Connect with password=MySecret123 at 192.168.1.100"},
                "output": {
                    "sanitized": "Connect with password=[CREDENTIAL_1] at [IP_ADDR_1]",
                    "detections": 2,
                },
            }
        ],
    )
    def sanitize_message(self, text: str) -> SkillResult:
        """Detect sensitive data and replace with placeholders."""
        detections = self.ctx.detection_engine.sensitive_detector.detect(text)

        if not detections:
            return SkillResult(
                success=True,
                message="No sensitive data detected",
                data={"sanitized": text, "detections": 0, "items": []},
            )

        sanitized = self.ctx.sanitizer.sanitize(text, detections)
        items = [
            {
                "type": d.category.value,
                "description": d.description,
                "masked": d.masked_value,
                "risk_score": d.risk_score,
            }
            for d in detections
        ]

        self.ctx.log_audit(
            {
                "skill": "sanitize-restore",
                "action": "sanitize",
                "detections": len(detections),
                "categories": list({d.category.value for d in detections}),
            }
        )

        return SkillResult(
            success=True,
            message=f"Sanitized {len(detections)} sensitive item(s)",
            data={
                "sanitized": sanitized,
                "original_length": len(text),
                "sanitized_length": len(sanitized),
                "detections": len(detections),
                "items": items,
                "mapping_count": len(self.ctx.sanitizer.mapping),
            },
            risk_score=max(d.risk_score for d in detections),
            action_taken="sanitize",
        )

    @tool(
        name="restore_response",
        description=(
            "Restore placeholders in an AI response back to original values. "
            "Call this after receiving an AI response that contains [PLACEHOLDER] tokens."
        ),
    )
    def restore_response(self, text: str) -> SkillResult:
        """Restore placeholders back to original sensitive values."""
        mapping = self.ctx.sanitizer.mapping
        if not mapping:
            return SkillResult(
                success=True,
                message="No active mappings to restore",
                data={"restored": text, "restorations": 0},
            )

        placeholders_found = self.ctx.restorer.find_placeholders(text)
        restored = self.ctx.restorer.restore(text, mapping)
        restorations = sum(1 for ph in placeholders_found if ph in mapping)

        self.ctx.log_audit(
            {
                "skill": "sanitize-restore",
                "action": "restore",
                "restorations": restorations,
            }
        )

        return SkillResult(
            success=True,
            message=f"Restored {restorations} placeholder(s)",
            data={
                "restored": restored,
                "restorations": restorations,
                "placeholders_found": len(placeholders_found),
            },
            action_taken="restore",
        )

    @tool(
        name="detect_sensitive",
        description=(
            "Scan text for sensitive data without modifying it. "
            "Returns a list of detected items with types, positions, and risk scores. "
            "Use this for preview/audit without actual sanitization."
        ),
    )
    def detect_sensitive(self, text: str) -> SkillResult:
        """Detect sensitive data in text (read-only scan)."""
        detections = self.ctx.detection_engine.sensitive_detector.detect(text)

        items = [
            {
                "type": d.category.value,
                "pattern": d.pattern_type,
                "description": d.description,
                "masked": d.masked_value,
                "position": [d.start, d.end],
                "risk_score": d.risk_score,
                "confidence": d.confidence,
            }
            for d in detections
        ]

        return SkillResult(
            success=True,
            message=f"Found {len(detections)} sensitive item(s)" if detections else "Clean",
            data={"detections": len(detections), "items": items},
            risk_score=max((d.risk_score for d in detections), default=0.0),
        )

    @tool(
        name="clear_session",
        description="Clear all sanitization mappings. Call this when starting a new conversation session.",
    )
    def clear_session(self) -> SkillResult:
        """Clear sanitizer state for a fresh session."""
        mapping_count = len(self.ctx.sanitizer.mapping)
        self.ctx.sanitizer.clear()
        return SkillResult(
            success=True,
            message=f"Cleared {mapping_count} mapping(s)",
            data={"cleared": mapping_count},
        )

    @tool(
        name="get_mapping_status",
        description="Show current sanitization mapping status (how many placeholders are active).",
    )
    def get_mapping_status(self) -> SkillResult:
        """Get current mapping statistics."""
        mapping = self.ctx.sanitizer.mapping
        return SkillResult(
            success=True,
            data={
                "active_mappings": len(mapping),
                "placeholders": list(mapping.keys()),
            },
        )
