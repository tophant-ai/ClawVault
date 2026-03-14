"""Tests for token counter and budget manager."""

from claw_vault.monitor.token_counter import TokenCounter
from claw_vault.monitor.budget import BudgetManager, BudgetStatus


class TestTokenCounter:
    def test_estimate_tokens(self, token_counter):
        tokens = token_counter.estimate_tokens("Hello world test")
        assert tokens > 0

    def test_estimate_cost(self, token_counter):
        cost = token_counter.estimate_cost(1000, 500, "gpt-4o")
        assert cost > 0

    def test_record_usage(self, token_counter):
        usage = token_counter.record_usage("Hello world", "Hi there", "gpt-4o")
        assert usage.total_tokens > 0
        assert usage.cost_usd > 0

    def test_today_usage_accumulates(self, token_counter):
        token_counter.record_usage("A" * 400, "B" * 400, "default")
        token_counter.record_usage("C" * 400, "D" * 400, "default")
        today = token_counter.get_today_usage()
        assert today.total_tokens >= 200  # at least 200 tokens from 1600 chars

    def test_detect_model_from_url(self, token_counter):
        assert "gpt" in token_counter.detect_model_from_url("https://api.openai.com/v1/chat")
        assert "claude" in token_counter.detect_model_from_url(
            "https://api.anthropic.com/v1/messages"
        )


class TestBudgetManager:
    def test_ok_status(self, token_counter):
        manager = BudgetManager(token_counter, daily_limit=50000)
        check = manager.check()
        assert check.status == BudgetStatus.OK

    def test_warning_status(self, token_counter):
        # Record enough tokens to trigger warning (>80%)
        manager = BudgetManager(token_counter, daily_limit=100, warning_threshold=0.5)
        token_counter.record_usage("A" * 400, "B" * 400, "default")  # ~200 tokens
        check = manager.check()
        assert check.status in (BudgetStatus.WARNING, BudgetStatus.EXCEEDED)

    def test_should_block(self, token_counter):
        manager = BudgetManager(token_counter, daily_limit=1)
        token_counter.record_usage("Hello world test text", "Response", "default")
        assert manager.should_block() is True
