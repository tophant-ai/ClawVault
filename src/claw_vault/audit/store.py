"""SQLite-based audit log storage with async support."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import aiosqlite
import structlog

from claw_vault.audit.models import AuditRecord, DailySummary

logger = structlog.get_logger()

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    session_id TEXT NOT NULL DEFAULT '',
    direction TEXT NOT NULL DEFAULT 'request',
    api_endpoint TEXT NOT NULL DEFAULT '',
    method TEXT NOT NULL DEFAULT '',
    token_count INTEGER NOT NULL DEFAULT 0,
    cost_usd REAL NOT NULL DEFAULT 0.0,
    detections TEXT NOT NULL DEFAULT '[]',
    risk_level TEXT NOT NULL DEFAULT 'safe',
    risk_score REAL NOT NULL DEFAULT 0.0,
    action_taken TEXT NOT NULL DEFAULT 'allow',
    skill_name TEXT,
    details TEXT NOT NULL DEFAULT '',
    agent_id TEXT,
    agent_name TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_risk ON audit_logs(risk_level);
CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_logs(session_id);
"""


class AuditStore:
    """Async SQLite audit log storage."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._db: Optional[aiosqlite.Connection] = None

    async def initialize(self) -> None:
        """Create database and tables if they don't exist."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(str(self._db_path))
        await self._db.executescript(SCHEMA)
        await self._ensure_columns()
        await self._db.commit()
        logger.info("audit_store_initialized", path=str(self._db_path))

    async def _ensure_columns(self) -> None:
        """Apply additive schema migrations for older SQLite databases."""
        assert self._db is not None
        cursor = await self._db.execute("PRAGMA table_info(audit_logs)")
        rows = await cursor.fetchall()
        existing_columns = {row[1] for row in rows}

        if "agent_id" not in existing_columns:
            await self._db.execute("ALTER TABLE audit_logs ADD COLUMN agent_id TEXT")
        if "agent_name" not in existing_columns:
            await self._db.execute("ALTER TABLE audit_logs ADD COLUMN agent_name TEXT")

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None

    async def log(self, record: AuditRecord) -> int:
        """Insert an audit record. Returns the record ID."""
        assert self._db is not None
        cursor = await self._db.execute(
            """INSERT INTO audit_logs
            (timestamp, session_id, direction, api_endpoint, method,
             token_count, cost_usd, detections, risk_level, risk_score,
             action_taken, skill_name, details, agent_id, agent_name)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                record.timestamp.isoformat(),
                record.session_id,
                record.direction,
                record.api_endpoint,
                record.method,
                record.token_count,
                record.cost_usd,
                json.dumps(record.detections),
                record.risk_level,
                record.risk_score,
                record.action_taken,
                record.skill_name,
                record.details,
                record.agent_id,
                record.agent_name,
            ),
        )
        await self._db.commit()
        return cursor.lastrowid or 0

    async def query_recent(self, limit: int = 50) -> list[AuditRecord]:
        """Get most recent audit records."""
        assert self._db is not None
        cursor = await self._db.execute(
            "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        return [self._row_to_record(row) for row in rows]

    async def query_by_date_range(self, start: datetime, end: datetime) -> list[AuditRecord]:
        """Get audit records within a date range."""
        assert self._db is not None
        cursor = await self._db.execute(
            "SELECT * FROM audit_logs WHERE timestamp BETWEEN ? AND ? ORDER BY timestamp DESC",
            (start.isoformat(), end.isoformat()),
        )
        rows = await cursor.fetchall()
        return [self._row_to_record(row) for row in rows]

    async def get_daily_summary(self, date_str: str | None = None) -> DailySummary:
        """Get aggregated stats for a specific day (default: today)."""
        assert self._db is not None
        if date_str is None:
            date_str = datetime.utcnow().strftime("%Y-%m-%d")

        cursor = await self._db.execute(
            """SELECT
                COUNT(*) as total,
                COALESCE(SUM(token_count), 0) as tokens,
                COALESCE(SUM(cost_usd), 0.0) as cost,
                COALESCE(SUM(CASE WHEN action_taken != 'allow' THEN 1 ELSE 0 END), 0) as interceptions,
                COALESCE(SUM(CASE WHEN action_taken = 'block' THEN 1 ELSE 0 END), 0) as blocks,
                COALESCE(SUM(CASE WHEN action_taken = 'sanitize' THEN 1 ELSE 0 END), 0) as sanitizations,
                COALESCE(MAX(risk_score), 0.0) as max_risk
            FROM audit_logs
            WHERE timestamp LIKE ?""",
            (f"{date_str}%",),
        )
        row = await cursor.fetchone()
        if not row:
            return DailySummary(date=date_str)

        return DailySummary(
            date=date_str,
            total_requests=row[0],
            total_tokens=row[1],
            total_cost_usd=row[2],
            interceptions=row[3],
            blocks=row[4],
            sanitizations=row[5],
            max_risk_score=row[6],
        )

    async def cleanup_old_records(self, retention_days: int = 7) -> int:
        """Delete records older than retention period. Returns count deleted."""
        assert self._db is not None
        cutoff = (datetime.utcnow() - timedelta(days=retention_days)).isoformat()
        cursor = await self._db.execute("DELETE FROM audit_logs WHERE timestamp < ?", (cutoff,))
        await self._db.commit()
        deleted = int(cursor.rowcount or 0)
        if deleted:
            logger.info("audit_cleanup", deleted=deleted, retention_days=retention_days)
        return deleted

    async def export_json(self, limit: int = 1000) -> list[dict[str, object]]:
        """Export recent records as JSON-serializable dicts."""
        records = await self.query_recent(limit)
        return [r.model_dump() for r in records]

    @staticmethod
    def _row_to_record(row: tuple[object, ...]) -> AuditRecord:
        return AuditRecord(
            id=row[0],
            timestamp=datetime.fromisoformat(row[1]),
            session_id=row[2],
            direction=row[3],
            api_endpoint=row[4],
            method=row[5],
            token_count=row[6],
            cost_usd=row[7],
            detections=json.loads(row[8]),
            risk_level=row[9],
            risk_score=row[10],
            action_taken=row[11],
            skill_name=row[12],
            details=row[13],
            agent_id=row[14],
            agent_name=row[15],
        )
