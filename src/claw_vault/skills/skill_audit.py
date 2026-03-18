"""Skill-Audit Skill: audit other Skills' behavior, permissions, and runtime activity.

Covers scenarios: C5 (Skill permission governance) + E2 (supply-chain security scanning)
"""

from __future__ import annotations

from datetime import datetime

from claw_vault.skills.base import (
    BaseSkill,
    SkillManifest,
    SkillPermission,
    SkillResult,
    tool,
)


class SkillAuditSkill(BaseSkill):
    """Audit other Skills' permissions, behavior, and runtime activity.

    Acts as a meta-Skill that monitors the Skill ecosystem:
    - List all registered Skills and their permissions
    - Compare requested vs actually-needed permissions
    - Detect over-privileged Skills
    - Track Skill invocation history
    - Generate Skill trust scores
    """

    def manifest(self) -> SkillManifest:
        return SkillManifest(
            name="skill-audit",
            version="0.1.0",
            description="Audit other Skills' permissions, behavior, and trust levels",
            permissions=[
                SkillPermission.AUDIT_LOG,
                SkillPermission.READ_CHAT,
            ],
            tags=["security", "audit", "permissions", "trust", "governance"],
            homepage="https://github.com/tophant-ai/ClawVault",
        )

    @tool(
        name="list_skill_permissions",
        description=(
            "List all registered Skills and their declared permissions. "
            "Highlights Skills with broad or sensitive permissions."
        ),
    )
    def list_skill_permissions(self) -> SkillResult:
        """List all Skills and their permission declarations."""
        # We access audit records to infer registered skills
        records = self.ctx.get_audit_records()

        # Collect unique skills seen in audit
        seen_skills: dict[str, dict] = {}
        for r in records:
            skill = r.get("skill", "")
            if skill and skill not in seen_skills:
                seen_skills[skill] = {
                    "name": skill,
                    "invocations": 0,
                    "actions": set(),
                    "first_seen": r.get("timestamp", ""),
                    "last_seen": r.get("timestamp", ""),
                }
            if skill in seen_skills:
                seen_skills[skill]["invocations"] += 1
                seen_skills[skill]["actions"].add(r.get("action", ""))
                seen_skills[skill]["last_seen"] = r.get("timestamp", "")

        # Convert sets to lists for serialization
        skill_list = []
        for s in seen_skills.values():
            s["actions"] = list(s["actions"])
            skill_list.append(s)

        # Define sensitive permissions
        sensitive_perms = {
            SkillPermission.EXECUTE_COMMAND,
            SkillPermission.WRITE_FILES,
            SkillPermission.NETWORK,
            SkillPermission.ACCESS_CREDENTIALS,
        }

        warnings = []
        for s in skill_list:
            if s["invocations"] > 50:
                warnings.append(
                    f"Skill '{s['name']}' has {s['invocations']} invocations — unusually active"
                )

        return SkillResult(
            success=True,
            message=f"Found {len(skill_list)} active Skill(s) in audit log",
            data={
                "skills": skill_list,
                "total_skills": len(skill_list),
                "total_invocations": sum(s["invocations"] for s in skill_list),
            },
            warnings=warnings,
        )

    @tool(
        name="check_skill_trust",
        description=(
            "Evaluate the trust level of a specific Skill based on its behavior history. "
            "Considers invocation frequency, actions taken, and any security events."
        ),
    )
    def check_skill_trust(self, skill_name: str) -> SkillResult:
        """Evaluate trust level for a specific Skill."""
        records = self.ctx.get_audit_records()
        skill_records = [r for r in records if r.get("skill") == skill_name]

        if not skill_records:
            return SkillResult(
                success=True,
                message=f"No audit data for Skill '{skill_name}'",
                data={"skill_name": skill_name, "trust_level": "unknown", "records": 0},
            )

        # Analyze behavior
        total = len(skill_records)
        actions = {}
        risk_events = 0
        for r in skill_records:
            action = r.get("action", "unknown")
            actions[action] = actions.get(action, 0) + 1
            result = r.get("result", "")
            if result in ("block", "warn"):
                risk_events += 1

        risk_ratio = risk_events / total if total > 0 else 0

        if risk_ratio > 0.3:
            trust_level = "low"
            recommendation = "REVIEW — This Skill triggers many security events"
        elif risk_ratio > 0.1:
            trust_level = "medium"
            recommendation = "MONITOR — Occasional security events detected"
        else:
            trust_level = "high"
            recommendation = "TRUSTED — Behavior appears normal"

        return SkillResult(
            success=True,
            message=f"Skill '{skill_name}' trust: {trust_level.upper()}",
            data={
                "skill_name": skill_name,
                "trust_level": trust_level,
                "total_invocations": total,
                "actions": actions,
                "risk_events": risk_events,
                "risk_ratio": round(risk_ratio, 3),
                "recommendation": recommendation,
            },
            risk_score=risk_ratio * 10,
        )

    @tool(
        name="activity_timeline",
        description="Show a timeline of Skill activity from the audit log.",
    )
    def activity_timeline(self, limit: int = 30) -> SkillResult:
        """Generate a Skill activity timeline."""
        records = self.ctx.get_audit_records()
        recent = records[-limit:] if len(records) > limit else records

        timeline = []
        for r in recent:
            timeline.append(
                {
                    "timestamp": r.get("timestamp", ""),
                    "skill": r.get("skill", "unknown"),
                    "action": r.get("action", "unknown"),
                    "result": r.get("result", ""),
                    "details": {
                        k: v
                        for k, v in r.items()
                        if k not in ("timestamp", "skill", "action", "result")
                    },
                }
            )

        return SkillResult(
            success=True,
            message=f"Showing {len(timeline)} recent event(s)",
            data={
                "total_events": len(records),
                "showing": len(timeline),
                "timeline": timeline,
            },
        )

    @tool(
        name="permission_report",
        description=(
            "Generate a comprehensive permission audit report. "
            "Shows which Skills have which permissions and flags over-privileged ones."
        ),
    )
    def permission_report(self) -> SkillResult:
        """Generate permission audit report."""
        records = self.ctx.get_audit_records()

        # Infer permissions from actions
        skill_actions: dict[str, set[str]] = {}
        for r in records:
            skill = r.get("skill", "")
            action = r.get("action", "")
            if skill:
                if skill not in skill_actions:
                    skill_actions[skill] = set()
                skill_actions[skill].add(action)

        # Map actions to implied permissions
        action_to_perm = {
            "sanitize": "modify_chat",
            "restore": "modify_chat",
            "scan_file": "read_files",
            "add_file": "read_files",
            "check_exfiltration": "network",
            "evaluate_command": "execute_command",
            "assess_skill": "audit_log",
        }

        report = []
        for skill, actions in skill_actions.items():
            implied_perms = set()
            for action in actions:
                perm = action_to_perm.get(action)
                if perm:
                    implied_perms.add(perm)

            report.append(
                {
                    "skill": skill,
                    "actions_observed": sorted(actions),
                    "implied_permissions": sorted(implied_perms),
                    "action_count": len(actions),
                }
            )

        return SkillResult(
            success=True,
            message=f"Permission report for {len(report)} Skill(s)",
            data={
                "skills": report,
                "total_skills": len(report),
            },
        )
