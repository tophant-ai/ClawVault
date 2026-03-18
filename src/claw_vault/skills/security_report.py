"""Security-Report Skill: generate security reports, token statistics,
and risk summaries for users and teams.

Covers scenarios: D1 (security report dashboard) + D2 (token consumption monitoring)
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


class SecurityReportSkill(BaseSkill):
    """Generate security reports, token usage summaries, and risk assessments.

    Capabilities:
    - Generate session security summary
    - Report token usage and cost estimation
    - Budget status check
    - Vault file access statistics
    - Export audit log excerpts
    """

    def manifest(self) -> SkillManifest:
        return SkillManifest(
            name="security-report",
            version="0.1.0",
            description="Generate security reports, token statistics, and risk summaries",
            permissions=[
                SkillPermission.AUDIT_LOG,
                SkillPermission.READ_CHAT,
            ],
            tags=["security", "reporting", "monitoring", "tokens", "cost"],
            homepage="https://github.com/tophant-ai/clawvault",
        )

    @tool(
        name="session_summary",
        description=(
            "Generate a security summary for the current session. "
            "Includes interception stats, token usage, cost, and risk events."
        ),
    )
    def session_summary(self) -> SkillResult:
        """Generate current session security summary."""
        token_usage = self.ctx.token_counter.get_session_total()
        today_usage = self.ctx.token_counter.get_today_usage()
        vault_stats = self.ctx.file_manager.get_stats()
        audit_records = self.ctx.get_audit_records()

        # Count actions from audit records
        action_counts: dict[str, int] = {}
        skill_counts: dict[str, int] = {}
        for record in audit_records:
            action = record.get("action", "unknown")
            action_counts[action] = action_counts.get(action, 0) + 1
            skill = record.get("skill", "unknown")
            skill_counts[skill] = skill_counts.get(skill, 0) + 1

        report = {
            "generated_at": datetime.utcnow().isoformat(),
            "token_usage": {
                "session_total": token_usage.total_tokens,
                "session_cost_usd": round(token_usage.cost_usd, 4),
                "today_total": today_usage.total_tokens,
                "today_cost_usd": round(today_usage.cost_usd, 4),
                "input_tokens": token_usage.input_tokens,
                "output_tokens": token_usage.output_tokens,
            },
            "security_events": {
                "total_events": len(audit_records),
                "actions": action_counts,
                "by_skill": skill_counts,
            },
            "vault": vault_stats,
        }

        # Build human-readable summary
        lines = [
            f"📊 **ClawVault Session Report**",
            f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            f"",
            f"🔢 **Token Usage**",
            f"  Session: {token_usage.total_tokens:,} tokens (${token_usage.cost_usd:.4f})",
            f"  Today: {today_usage.total_tokens:,} tokens (${today_usage.cost_usd:.4f})",
            f"",
            f"🛡️ **Security Events**: {len(audit_records)} total",
        ]
        for action, count in sorted(action_counts.items()):
            lines.append(f"  • {action}: {count}")
        lines.append(f"")
        lines.append(
            f"📦 **Vault**: {vault_stats['total_managed']} file(s) managed, "
            f"{vault_stats['total_accesses']} access(es), "
            f"{vault_stats['total_blocks']} block(s)"
        )

        return SkillResult(
            success=True,
            message="\n".join(lines),
            data=report,
        )

    @tool(
        name="token_report",
        description=(
            "Detailed token usage and cost report. "
            "Shows breakdown by session, today, and per-model pricing."
        ),
    )
    def token_report(self) -> SkillResult:
        """Generate detailed token usage report."""
        session = self.ctx.token_counter.get_session_total()
        today = self.ctx.token_counter.get_today_usage()

        report = {
            "session": {
                "input_tokens": session.input_tokens,
                "output_tokens": session.output_tokens,
                "total_tokens": session.total_tokens,
                "cost_usd": round(session.cost_usd, 6),
            },
            "today": {
                "input_tokens": today.input_tokens,
                "output_tokens": today.output_tokens,
                "total_tokens": today.total_tokens,
                "cost_usd": round(today.cost_usd, 6),
            },
        }

        lines = [
            f"💰 **Token Usage Report**",
            f"",
            f"**Session Total**",
            f"  Input:  {session.input_tokens:>10,} tokens",
            f"  Output: {session.output_tokens:>10,} tokens",
            f"  Total:  {session.total_tokens:>10,} tokens",
            f"  Cost:   ${session.cost_usd:>10.4f}",
            f"",
            f"**Today**",
            f"  Input:  {today.input_tokens:>10,} tokens",
            f"  Output: {today.output_tokens:>10,} tokens",
            f"  Total:  {today.total_tokens:>10,} tokens",
            f"  Cost:   ${today.cost_usd:>10.4f}",
        ]

        return SkillResult(
            success=True,
            message="\n".join(lines),
            data=report,
        )

    @tool(
        name="budget_status",
        description="Check current token budget status and remaining capacity.",
    )
    def budget_status(self) -> SkillResult:
        """Check token budget status."""
        from claw_vault.monitor.budget import BudgetManager

        manager = BudgetManager(self.ctx.token_counter)
        check = manager.check()

        bar_length = 20
        filled = int(check.daily_pct / 100 * bar_length)
        bar = "█" * filled + "░" * (bar_length - filled)

        lines = [
            f"💰 **Budget Status**: {check.status.value.upper()}",
            f"",
            f"Daily:   [{bar}] {check.daily_pct:.1f}%",
            f"         {check.daily_used:,} / {check.daily_limit:,} tokens",
            f"Monthly: {check.monthly_pct:.1f}% used",
            f"         {check.monthly_used:,} / {check.monthly_limit:,} tokens",
            f"Cost:    ${check.cost_usd:.4f}",
            f"",
            f"Status:  {check.message}",
        ]

        return SkillResult(
            success=True,
            message="\n".join(lines),
            data={
                "status": check.status.value,
                "daily_pct": check.daily_pct,
                "daily_used": check.daily_used,
                "daily_limit": check.daily_limit,
                "monthly_pct": check.monthly_pct,
                "monthly_used": check.monthly_used,
                "monthly_limit": check.monthly_limit,
                "cost_usd": check.cost_usd,
                "message": check.message,
            },
        )

    @tool(
        name="vault_report",
        description="Report on vault-protected files: access counts, blocks, and activity.",
    )
    def vault_report(self) -> SkillResult:
        """Generate vault file access report."""
        stats = self.ctx.file_manager.get_stats()

        if not stats["files"]:
            return SkillResult(
                success=True,
                message="📦 Vault is empty — no files currently managed",
                data=stats,
            )

        lines = [
            f"📦 **Vault File Report**",
            f"Total managed: {stats['total_managed']}",
            f"Total accesses: {stats['total_accesses']}",
            f"Total blocks: {stats['total_blocks']}",
            f"",
        ]
        for f in stats["files"]:
            name = Path(f["path"]).name
            lines.append(f"  📄 {name}")
            lines.append(f"     Accesses: {f['access_count']}, Blocks: {f['blocked_count']}")

        return SkillResult(
            success=True,
            message="\n".join(lines),
            data=stats,
        )

    @tool(
        name="audit_log",
        description="Retrieve recent audit log entries from the current session.",
    )
    def audit_log(self, limit: int = 20) -> SkillResult:
        """Get recent audit log entries."""
        records = self.ctx.get_audit_records()
        recent = records[-limit:] if len(records) > limit else records

        return SkillResult(
            success=True,
            message=f"Showing {len(recent)} of {len(records)} audit record(s)",
            data={
                "total_records": len(records),
                "showing": len(recent),
                "records": recent,
            },
        )
