"""Dedicated JSONL traffic logger for full proxy request and response payloads."""

from __future__ import annotations

import json
import threading
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()

UTC_TZ = timezone(timedelta(0))

REDACTED_HEADERS = {
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-access-token",
    "cookie",
    "set-cookie",
}


class ProxyTrafficLogger:
    """Append full proxy traffic events to a dedicated JSONL file."""

    def __init__(self, path: Path, enabled: bool = True) -> None:
        self._path = path
        self._enabled = enabled
        self._lock = threading.Lock()

        if self._enabled:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.touch(exist_ok=True)
            try:
                self._path.chmod(0o600)
            except OSError:
                logger.warning("proxy_traffic_log_permission_update_failed", path=str(self._path))

    @property
    def path(self) -> Path:
        """Return the on-disk path for the traffic log."""
        return self._path

    def log_transaction(
        self,
        *,
        proxy_session_id: str,
        flow_id: str,
        action: str,
        source: str,
        agent_id: str | None,
        session_id: str | None,
        risk_level: str | None,
        risk_score: float | None,
        request: Mapping[str, Any],
        response: Mapping[str, Any],
    ) -> None:
        """Persist a single request/response transaction event."""
        payload = {
            "logged_at": self._timestamp(),
            "proxy_session_id": proxy_session_id,
            "flow_id": flow_id,
            "agent_id": agent_id,
            "session_id": session_id,
            "action": action,
            "source": source,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "request": self._normalize_request(request),
            "response": self._normalize_response(response),
        }
        self._write(payload)

    def _write(self, payload: dict[str, Any]) -> None:
        if not self._enabled:
            return

        line = json.dumps(payload, ensure_ascii=False)
        with self._lock:
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(f"{line}\n")

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(UTC_TZ).isoformat()

    def _normalize_request(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "method": str(payload.get("method", "")),
            "url": str(payload.get("url", "")),
            "headers": self._sanitize_headers(self._coerce_headers(payload.get("headers"))),
            "body": self._parse_body(payload.get("body")),
            "forwarded_body": self._parse_body(payload.get("forwarded_body")),
        }

    def _normalize_response(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "status_code": int(payload.get("status_code", 0)),
            "headers": self._sanitize_headers(self._coerce_headers(payload.get("headers"))),
            "body": self._parse_body(payload.get("body")),
            "returned_body": self._parse_body(payload.get("returned_body")),
        }

    @staticmethod
    def _coerce_headers(value: Any) -> Mapping[str, str]:
        if isinstance(value, Mapping):
            return {str(key): str(item) for key, item in value.items()}
        return {}

    @staticmethod
    def _parse_body(value: Any) -> Any:
        if value is None:
            return None
        if not isinstance(value, str):
            return value
        stripped = value.strip()
        if not stripped:
            return ""
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            return value

    @staticmethod
    def _sanitize_headers(headers: Mapping[str, str]) -> dict[str, str]:
        sanitized: dict[str, str] = {}
        for key, value in headers.items():
            header_name = str(key)
            lowered = header_name.lower()
            if lowered in REDACTED_HEADERS:
                sanitized[header_name] = "[REDACTED]"
                continue
            sanitized[header_name] = str(value)
        return sanitized
