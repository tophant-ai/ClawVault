"""Data models for local filesystem scanning."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class ScanType(str, Enum):
    CREDENTIAL = "credential"
    VULNERABILITY = "vulnerability"
    SKILL_AUDIT = "skill_audit"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanSchedule(BaseModel):
    """A cron-scheduled scan job."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    cron: str
    scan_type: ScanType = ScanType.CREDENTIAL
    path: str = ""
    max_files: int = 100
    enabled: bool = True
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )


class ScanFinding(BaseModel):
    """A single finding from a local scan."""

    file_path: str
    finding_type: str  # "sensitive", "command", "injection", "vulnerability", "skill_risk"
    description: str
    risk_score: float = 0.0
    detail: dict = Field(default_factory=dict)


class LocalScanResult(BaseModel):
    """Result of a local filesystem scan."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        + "Z"
    )
    scan_type: ScanType
    path: str
    status: ScanStatus = ScanStatus.PENDING
    files_scanned: int = 0
    findings: list[ScanFinding] = Field(default_factory=list)
    max_risk_score: float = 0.0
    threat_level: str = "safe"
    duration_seconds: float = 0.0
    error: str | None = None
    schedule_id: str | None = None
