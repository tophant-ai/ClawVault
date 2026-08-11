"""Token counting and cost estimation for various AI model providers."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime

import structlog

logger = structlog.get_logger()

# Approximate pricing per 1K tokens (USD) — input / output
MODEL_PRICING: dict[str, tuple[float, float]] = {
    "gpt-4": (0.03, 0.06),
    "gpt-4-turbo": (0.01, 0.03),
    "gpt-4o": (0.005, 0.015),
    "gpt-4o-mini": (0.00015, 0.0006),
    "gpt-3.5-turbo": (0.0005, 0.0015),
    "claude-3-opus": (0.015, 0.075),
    "claude-3-sonnet": (0.003, 0.015),
    "claude-3-haiku": (0.00025, 0.00125),
    "claude-3.5-sonnet": (0.003, 0.015),
    # MiniMax text models (global api.minimax.io / China api.minimaxi.com).
    # Input / output per 1K tokens derived from per-million-token pricing.
    "MiniMax-M3": (0.0006, 0.0024),
    "MiniMax-M2.7": (0.0003, 0.0012),
    "default": (0.005, 0.015),
}


@dataclass
class TokenUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0
    model: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


class TokenCounter:
    """Estimates token count and cost for API calls.

    Uses a simple heuristic: ~4 characters per token for English text.
    For accurate counting, integrate tiktoken for OpenAI models.
    """

    CHARS_PER_TOKEN = 4  # rough estimate

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._daily_usage: dict[str, TokenUsage] = {}  # date_str → cumulative
        self._session_total = TokenUsage()

    def estimate_tokens(self, text: str) -> int:
        """Estimate token count from text length."""
        return max(1, len(text) // self.CHARS_PER_TOKEN)

    def estimate_cost(self, input_tokens: int, output_tokens: int, model: str = "default") -> float:
        """Estimate cost in USD."""
        pricing = MODEL_PRICING.get(model, MODEL_PRICING["default"])
        cost = (input_tokens / 1000) * pricing[0] + (output_tokens / 1000) * pricing[1]
        return round(cost, 6)

    def record_usage(self, input_text: str, output_text: str, model: str = "default") -> TokenUsage:
        """Record a request/response token usage."""
        input_tokens = self.estimate_tokens(input_text)
        output_tokens = self.estimate_tokens(output_text)
        total = input_tokens + output_tokens
        cost = self.estimate_cost(input_tokens, output_tokens, model)

        usage = TokenUsage(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total,
            cost_usd=cost,
            model=model,
        )

        today = datetime.now(UTC).strftime("%Y-%m-%d")

        with self._lock:
            if today not in self._daily_usage:
                self._daily_usage[today] = TokenUsage()

            daily = self._daily_usage[today]
            daily.input_tokens += input_tokens
            daily.output_tokens += output_tokens
            daily.total_tokens += total
            daily.cost_usd += cost

            self._session_total.input_tokens += input_tokens
            self._session_total.output_tokens += output_tokens
            self._session_total.total_tokens += total
            self._session_total.cost_usd += cost

        logger.debug(
            "token_usage_recorded",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost,
            model=model,
        )

        return usage

    def get_today_usage(self) -> TokenUsage:
        today = datetime.now(UTC).strftime("%Y-%m-%d")
        with self._lock:
            return self._daily_usage.get(today, TokenUsage())

    def get_session_total(self) -> TokenUsage:
        with self._lock:
            return TokenUsage(
                input_tokens=self._session_total.input_tokens,
                output_tokens=self._session_total.output_tokens,
                total_tokens=self._session_total.total_tokens,
                cost_usd=self._session_total.cost_usd,
            )

    def detect_model_from_url(self, url: str) -> str:
        """Attempt to detect model name from API URL path."""
        if "minimax" in url:
            return "MiniMax-M3"
        elif "openai" in url:
            return "gpt-4o"
        elif "anthropic" in url:
            return "claude-3.5-sonnet"
        return "default"

    def detect_model_from_request(self, url: str, body: str) -> str:
        """Detect supported request models before falling back to URL attribution."""
        if "minimax" in url.lower():
            try:
                data = json.loads(body)
            except (json.JSONDecodeError, TypeError):
                data = None
            if isinstance(data, dict):
                model = data.get("model")
                if model in {"MiniMax-M3", "MiniMax-M2.7"}:
                    return model
        return self.detect_model_from_url(url)
