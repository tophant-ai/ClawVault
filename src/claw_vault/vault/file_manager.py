"""File manager: track and protect sensitive files in the vault."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import structlog

logger = structlog.get_logger()

# Common sensitive file paths to auto-discover
AUTO_DISCOVER_PATHS: list[str] = [
    "~/.aws/credentials",
    "~/.aws/config",
    "~/.ssh/id_rsa",
    "~/.ssh/id_ed25519",
    "~/.ssh/config",
    "~/.npmrc",
    "~/.pypirc",
    "~/.docker/config.json",
    "~/.kube/config",
    "~/.gitconfig",
    "~/.netrc",
    "~/.env",
]

# File patterns to detect in project directories
PROJECT_SENSITIVE_PATTERNS: list[str] = [
    ".env",
    ".env.local",
    ".env.production",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "secrets.yaml",
    "secrets.json",
    "credentials.json",
    "service-account*.json",
]


@dataclass
class ManagedFile:
    path: str
    added_at: datetime = field(default_factory=datetime.utcnow)
    access_count: int = 0
    last_accessed: Optional[datetime] = None
    blocked_count: int = 0


class FileManager:
    """Manages sensitive files in the vault.

    Tracks which files are 'managed' (protected), and provides
    access control checks when Skills/AI try to read them.
    """

    def __init__(self) -> None:
        self._managed: dict[str, ManagedFile] = {}

    def add_file(self, path: str) -> ManagedFile:
        """Add a file to the vault for protection."""
        resolved = str(Path(path).expanduser().resolve())
        if resolved not in self._managed:
            self._managed[resolved] = ManagedFile(path=resolved)
            logger.info("file_managed", path=resolved)
        return self._managed[resolved]

    def remove_file(self, path: str) -> bool:
        """Remove a file from vault protection."""
        resolved = str(Path(path).expanduser().resolve())
        if resolved in self._managed:
            del self._managed[resolved]
            logger.info("file_unmanaged", path=resolved)
            return True
        return False

    def is_managed(self, path: str) -> bool:
        """Check if a file is under vault protection."""
        resolved = str(Path(path).expanduser().resolve())
        return resolved in self._managed

    def check_access(self, path: str, skill_name: str = "") -> tuple[bool, str]:
        """Check if access to a managed file should be allowed.

        Returns (is_managed, reason).
        If is_managed is True, the caller should prompt the user.
        """
        resolved = str(Path(path).expanduser().resolve())
        if resolved not in self._managed:
            return False, ""

        mf = self._managed[resolved]
        mf.access_count += 1
        mf.last_accessed = datetime.utcnow()

        reason = f"Managed file access: {resolved}"
        if skill_name:
            reason += f" by Skill '{skill_name}'"

        logger.warning(
            "managed_file_access", path=resolved, skill=skill_name, count=mf.access_count
        )
        return True, reason

    def record_block(self, path: str) -> None:
        """Record that access to a managed file was blocked."""
        resolved = str(Path(path).expanduser().resolve())
        if resolved in self._managed:
            self._managed[resolved].blocked_count += 1

    def auto_discover(self) -> list[str]:
        """Scan for common sensitive files and return discovered paths."""
        discovered: list[str] = []
        for pattern in AUTO_DISCOVER_PATHS:
            expanded = Path(pattern).expanduser()
            if expanded.exists():
                discovered.append(str(expanded.resolve()))
        if discovered:
            logger.info("auto_discover_complete", found=len(discovered))
        return discovered

    def list_managed(self) -> list[ManagedFile]:
        """List all managed files."""
        return list(self._managed.values())

    def get_stats(self) -> dict:
        """Get vault file statistics."""
        return {
            "total_managed": len(self._managed),
            "total_accesses": sum(m.access_count for m in self._managed.values()),
            "total_blocks": sum(m.blocked_count for m in self._managed.values()),
            "files": [
                {
                    "path": m.path,
                    "access_count": m.access_count,
                    "blocked_count": m.blocked_count,
                    "added_at": m.added_at.isoformat(),
                }
                for m in self._managed.values()
            ],
        }
