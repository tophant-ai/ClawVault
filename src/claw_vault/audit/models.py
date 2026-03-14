"""Data models for audit records."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class AuditRecord(BaseModel):
    """Single audit log entry."""

    id: Optional[int] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    agent_id: str | None = None
    session_id: str = ""
    direction: str = "request"  # "request" | "response"
    api_endpoint: str = ""
    method: str = ""
    token_count: int = 0
    cost_usd: float = 0.0
    detections: list[str] = Field(default_factory=list)
    risk_level: str = "safe"  # safe | low | medium | high | critical
    risk_score: float = 0.0
    action_taken: str = "allow"  # allow | block | sanitize | ask_user
    skill_name: Optional[str] = None
    details: str = ""
    agent_name: str | None = None
    user_content: str | None = None


class DailySummary(BaseModel):
    """Aggregated daily statistics."""

    date: str
    total_requests: int = 0
    total_tokens: int = 0
    total_cost_usd: float = 0.0
    interceptions: int = 0
    blocks: int = 0
    sanitizations: int = 0
    max_risk_score: float = 0.0
    detection_categories: dict[str, int] = Field(default_factory=dict)
