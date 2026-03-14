"""Token budget management with alerts and circuit breaking."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

import structlog

from claw_vault.monitor.token_counter import TokenCounter

logger = structlog.get_logger()


class BudgetStatus(str, Enum):
    OK = "ok"
    WARNING = "warning"  # > 80% used
    EXCEEDED = "exceeded"  # 100% used
    CIRCUIT_BREAK = "circuit_break"  # anomaly detected


@dataclass
class BudgetCheck:
    status: BudgetStatus
    daily_used: int
    daily_limit: int
    daily_pct: float
    monthly_used: int
    monthly_limit: int
    monthly_pct: float
    cost_usd: float
    message: str


class BudgetManager:
    """Manages token budgets and triggers alerts when limits are approached."""

    def __init__(
        self,
        token_counter: TokenCounter,
        daily_limit: int = 50_000,
        monthly_limit: int = 1_000_000,
        cost_alert_usd: float = 50.0,
        warning_threshold: float = 0.8,
    ) -> None:
        self._counter = token_counter
        self._daily_limit = daily_limit
        self._monthly_limit = monthly_limit
        self._cost_alert = cost_alert_usd
        self._warning_threshold = warning_threshold

    def check(self) -> BudgetCheck:
        """Check current budget status."""
        today = self._counter.get_today_usage()
        session = self._counter.get_session_total()

        daily_pct = today.total_tokens / self._daily_limit if self._daily_limit else 0
        monthly_pct = session.total_tokens / self._monthly_limit if self._monthly_limit else 0

        if daily_pct >= 1.0 or monthly_pct >= 1.0:
            status = BudgetStatus.EXCEEDED
            msg = f"Budget exceeded: daily {daily_pct:.0%}, monthly {monthly_pct:.0%}"
        elif daily_pct >= self._warning_threshold or monthly_pct >= self._warning_threshold:
            status = BudgetStatus.WARNING
            msg = f"Budget warning: daily {daily_pct:.0%}, monthly {monthly_pct:.0%}"
        else:
            status = BudgetStatus.OK
            msg = "Within budget"

        if today.cost_usd >= self._cost_alert:
            status = BudgetStatus.EXCEEDED
            msg = f"Cost alert: ${today.cost_usd:.2f} exceeds ${self._cost_alert:.2f} limit"

        result = BudgetCheck(
            status=status,
            daily_used=today.total_tokens,
            daily_limit=self._daily_limit,
            daily_pct=round(daily_pct * 100, 1),
            monthly_used=session.total_tokens,
            monthly_limit=self._monthly_limit,
            monthly_pct=round(monthly_pct * 100, 1),
            cost_usd=today.cost_usd,
            message=msg,
        )

        if status != BudgetStatus.OK:
            logger.warning("budget_alert", status=status.value, message=msg)

        return result

    def should_block(self) -> bool:
        """Quick check: should the next request be blocked due to budget?"""
        check = self.check()
        return check.status in (BudgetStatus.EXCEEDED, BudgetStatus.CIRCUIT_BREAK)
