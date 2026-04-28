"""Vault-Guard Skill: protect managed files, intercept dangerous commands,
and block unauthorized data exfiltration.

Covers scenarios: B2 (data exfiltration interception) + B4 (malicious command interception) + C1 (file/credential management)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from claw_vault.skills.base import (
    BaseSkill,
    SkillManifest,
    SkillPermission,
    SkillResult,
    tool,
)


# Known malicious or suspicious domains
SUSPICIOUS_DOMAIN_PATTERNS = [
    r"evil\.com",
    r"pastebin\.com",
    r"requestbin\.(net|com)",
    r"webhook\.site",
    r"ngrok\.(io|app)",
    r"pipedream\.net",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # raw IP addresses
]


class VaultGuardSkill(BaseSkill):
    """Protects managed files, intercepts dangerous operations, blocks data exfiltration.

    Capabilities:
    - Manage sensitive files in the vault (add/remove/list)
    - Check if a file access should be allowed
    - Detect data exfiltration attempts (URL + content analysis)
    - Evaluate commands for risk before execution
    - Auto-discover sensitive files on the system
    """

    def manifest(self) -> SkillManifest:
        return SkillManifest(
            name="vault-guard",
            version="0.1.0",
            description="Protect managed files, intercept dangerous commands, block data exfiltration",
            permissions=[
                SkillPermission.READ_FILES,
                SkillPermission.READ_CHAT,
                SkillPermission.AUDIT_LOG,
            ],
            tags=["security", "vault", "file-protection", "exfiltration"],
            homepage="https://github.com/tophant-ai/ClawVault",
        )

    @tool(
        name="add_to_vault",
        description=(
            "Add a sensitive file to the vault for protection. "
            "Once managed, any Skill or AI attempting to read this file "
            "will trigger a security check and user confirmation."
        ),
    )
    def add_to_vault(self, file_path: str) -> SkillResult:
        """Add a file to vault protection."""
        path = Path(file_path).expanduser()
        if not path.exists():
            return SkillResult(success=False, message=f"File not found: {file_path}")

        mf = self.ctx.file_manager.add_file(file_path)

        self.ctx.log_audit(
            {
                "skill": "vault-guard",
                "action": "add_file",
                "file": str(path.resolve()),
            }
        )

        return SkillResult(
            success=True,
            message=f"✅ File added to vault: {path.name}",
            data={
                "file": str(path.resolve()),
                "added_at": mf.added_at.isoformat(),
                "total_managed": len(self.ctx.file_manager.list_managed()),
            },
        )

    @tool(
        name="remove_from_vault",
        description="Remove a file from vault protection.",
    )
    def remove_from_vault(self, file_path: str) -> SkillResult:
        """Remove a file from vault protection."""
        removed = self.ctx.file_manager.remove_file(file_path)
        if removed:
            return SkillResult(success=True, message=f"File removed from vault: {file_path}")
        return SkillResult(success=False, message=f"File not in vault: {file_path}")

    @tool(
        name="list_vault",
        description="List all files currently managed by the vault.",
    )
    def list_vault(self) -> SkillResult:
        """List all managed files and their access statistics."""
        stats = self.ctx.file_manager.get_stats()
        return SkillResult(
            success=True,
            message=f"Vault contains {stats['total_managed']} managed file(s)",
            data=stats,
        )

    @tool(
        name="discover_sensitive_files",
        description=(
            "Auto-discover common sensitive files on the system "
            "(~/.aws/credentials, ~/.ssh/id_rsa, .env files, etc.). "
            "Returns a list of found files that can be added to the vault."
        ),
    )
    def discover_sensitive_files(self) -> SkillResult:
        """Scan for common sensitive files."""
        discovered = self.ctx.file_manager.auto_discover()
        already_managed = [p for p in discovered if self.ctx.file_manager.is_managed(p)]
        unmanaged = [p for p in discovered if p not in already_managed]

        return SkillResult(
            success=True,
            message=f"Found {len(discovered)} sensitive file(s), {len(unmanaged)} not yet managed",
            data={
                "discovered": discovered,
                "already_managed": already_managed,
                "unmanaged": unmanaged,
                "total_found": len(discovered),
            },
        )

    @tool(
        name="check_file_access",
        description=(
            "Check if a file access request should be allowed. "
            "Call this before any Skill reads a file to verify it's not a managed/protected file."
        ),
    )
    def check_file_access(self, file_path: str, skill_name: str = "") -> SkillResult:
        """Check if access to a file is safe."""
        is_managed, reason = self.ctx.file_manager.check_access(file_path, skill_name)

        if is_managed:
            return SkillResult(
                success=True,
                message=f"⚠️ Protected file access: {reason}",
                data={
                    "is_managed": True,
                    "file": file_path,
                    "skill": skill_name,
                    "action_required": "user_confirmation",
                    "reason": reason,
                },
                risk_score=7.0,
                action_taken="ask_user",
                warnings=[reason],
            )

        return SkillResult(
            success=True,
            message="File is not managed — access allowed",
            data={"is_managed": False, "file": file_path},
            action_taken="allow",
        )

    @tool(
        name="check_exfiltration",
        description=(
            "Analyze a network request for potential data exfiltration. "
            "Checks target URL, request content, and whether sensitive data is being sent out. "
            "Call this before any outbound HTTP request from a Skill."
        ),
    )
    def check_exfiltration(self, url: str, content: str = "", skill_name: str = "") -> SkillResult:
        """Detect potential data exfiltration in outbound requests."""
        risks: list[dict[str, Any]] = []

        # Check target domain
        for pattern in SUSPICIOUS_DOMAIN_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                risks.append(
                    {
                        "type": "suspicious_domain",
                        "detail": f"Target URL matches suspicious pattern: {pattern}",
                        "score": 8.0,
                    }
                )
                break

        # Check if content contains sensitive data
        if content:
            detections = self.ctx.detection_engine.sensitive_detector.detect(content)
            for d in detections:
                risks.append(
                    {
                        "type": "sensitive_data_in_payload",
                        "detail": f"Outbound payload contains {d.description}: {d.masked_value}",
                        "score": d.risk_score,
                    }
                )

        # Check if content references managed files
        managed_files = self.ctx.file_manager.list_managed()
        for mf in managed_files:
            if mf.path in content or Path(mf.path).name in content:
                risks.append(
                    {
                        "type": "managed_file_reference",
                        "detail": f"Payload references managed file: {mf.path}",
                        "score": 9.0,
                    }
                )

        max_score = max((r["score"] for r in risks), default=0.0)
        is_exfiltration = max_score >= 7.0

        if is_exfiltration:
            action = "block"
            message = f"🚨 Data exfiltration attempt blocked! {len(risks)} risk(s) detected"
        elif risks:
            action = "warn"
            message = f"⚠️ Suspicious outbound request: {len(risks)} concern(s)"
        else:
            action = "allow"
            message = "Outbound request appears safe"

        self.ctx.log_audit(
            {
                "skill": "vault-guard",
                "action": "check_exfiltration",
                "url": url,
                "skill_name": skill_name,
                "result": action,
                "risks": len(risks),
            }
        )

        return SkillResult(
            success=True,
            message=message,
            data={
                "url": url,
                "is_exfiltration": is_exfiltration,
                "risks": risks,
                "recommended_action": action,
            },
            risk_score=max_score,
            action_taken=action,
            warnings=[r["detail"] for r in risks if r["score"] >= 7.0],
        )

    @tool(
        name="evaluate_command",
        description=(
            "Evaluate a system command for safety before execution. "
            "Checks for destructive operations, privilege escalation, "
            "and data exfiltration patterns."
        ),
    )
    def evaluate_command(self, command: str) -> SkillResult:
        """Evaluate a command for security risk."""
        commands = self.ctx.detection_engine.command_detector.detect(command)

        items = [
            {
                "command": c.command[:60],
                "risk_level": c.risk_level.value,
                "risk_score": c.risk_score,
                "reason": c.reason,
            }
            for c in commands
        ]

        max_score = max((c.risk_score for c in commands), default=0.0)

        if max_score >= 9.0:
            action = "block"
            message = f"🚨 Critical risk command — BLOCKED: {commands[0].reason}"
        elif max_score >= 7.0:
            action = "ask_user"
            message = f"⚠️ High risk command — user confirmation required"
        elif max_score >= 4.0:
            action = "warn"
            message = f"Medium risk command — proceed with caution"
        else:
            action = "allow"
            message = "Command appears safe"

        self.ctx.log_audit(
            {
                "skill": "vault-guard",
                "action": "evaluate_command",
                "command": command[:80],
                "result": action,
                "max_risk": max_score,
            }
        )

        return SkillResult(
            success=True,
            message=message,
            data={
                "command": command,
                "items": items,
                "max_risk_score": max_score,
                "recommended_action": action,
            },
            risk_score=max_score,
            action_taken=action,
            warnings=[c.reason for c in commands if c.risk_score >= 7.0],
        )
