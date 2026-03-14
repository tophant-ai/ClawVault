"""Delete transcript lines around ClawVault 403 error records."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Final

_UTF8: Final[str] = "utf-8"
_ERROR_MESSAGE_PATTERN: Final[re.Pattern[str]] = re.compile(
    r'"errorMessage"\s*:\s*"403 \[ClawVault\]'
)


@dataclass(frozen=True)
class FileRedactionResult:
    """Result of filtering transcript lines."""

    changed: bool
    deleted_line_count: int
    scanned_line_count: int
    next_offset: int
    content: bytes


class SessionFileRedactor:
    """Delete a matched error line and the line immediately before it."""

    def redact_clawvault_error_pairs(self, content: bytes) -> FileRedactionResult:
        """Delete complete lines containing the target error marker and their predecessors."""
        complete_end = content.rfind(b"\n")
        if complete_end < 0:
            return FileRedactionResult(
                changed=False,
                deleted_line_count=0,
                scanned_line_count=0,
                next_offset=0,
                content=content,
            )

        complete_end += 1
        complete_content = content[:complete_end]
        remainder = content[complete_end:]
        raw_lines = complete_content.splitlines(keepends=True)
        delete_indexes: set[int] = set()

        for index, raw_line in enumerate(raw_lines):
            text = raw_line.decode(_UTF8, errors="replace")
            if not self._line_has_target_error(text):
                continue
            delete_indexes.add(index)
            if index > 0:
                delete_indexes.add(index - 1)

        if not delete_indexes:
            return FileRedactionResult(
                changed=False,
                deleted_line_count=0,
                scanned_line_count=len(raw_lines),
                next_offset=complete_end,
                content=content,
            )

        kept_lines = [
            raw_line for index, raw_line in enumerate(raw_lines) if index not in delete_indexes
        ]
        updated_complete_content = b"".join(kept_lines)
        updated_content = updated_complete_content + remainder
        return FileRedactionResult(
            changed=True,
            deleted_line_count=len(delete_indexes),
            scanned_line_count=len(raw_lines),
            next_offset=len(updated_complete_content),
            content=updated_content,
        )

    def _line_has_target_error(self, text: str) -> bool:
        if _ERROR_MESSAGE_PATTERN.search(text) is not None:
            return True

        stripped = text.strip()
        if not stripped:
            return False

        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            return False

        return self._payload_has_target_error(payload)

    def _payload_has_target_error(self, payload: Any) -> bool:
        if isinstance(payload, dict):
            for key, value in payload.items():
                if key == "errorMessage" and isinstance(value, str):
                    if value.startswith("403 [ClawVault]"):
                        return True
                if self._payload_has_target_error(value):
                    return True
            return False

        if isinstance(payload, list):
            return any(self._payload_has_target_error(item) for item in payload)

        return False
