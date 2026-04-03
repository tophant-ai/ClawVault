"""Pydantic models for file monitoring events and alerts."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class FileChangeType(str, Enum):
    CREATED = "created"
    MODIFIED = "modified"
    DELETED = "deleted"
    ACCESSED = "accessed"


class FileChangeEvent(BaseModel):
    """A single file system change event with optional content scan results."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    change_type: FileChangeType
    file_path: str
    file_name: str
    matched_pattern: str | None = None
    is_managed: bool = False
    file_size_bytes: int | None = None

    # Content scan results (populated when scan_content_on_change is True)
    has_threats: bool = False
    threat_level: str = "safe"
    risk_score: float = 0.0
    sensitive_count: int = 0
    detection_summary: list[str] = Field(default_factory=list)

    # Guard mode action (set by service based on current guard mode)
    action_taken: str = "allow"  # allow | block | ask_user | log
    needs_user_action: bool = False

    # Enforcement tracking (set when enforcement callback is active)
    enforcement_applied: bool = False
    flagged_values_count: int = 0


class FileMonitorAlert(BaseModel):
    """Dashboard-friendly alert derived from a FileChangeEvent."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    severity: str = "low"
    summary: str = ""
    event_id: str = ""
    file_path: str = ""
    change_type: str = ""
