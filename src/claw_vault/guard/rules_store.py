"""Persistence and data models for custom guard rules.

Rules are stored in the unified config file under the ``rules`` key:
``~/.ClawVault/config.yaml``.

The format is intentionally simple and human-friendly, for example:

```yaml
rules:
  - id: block-injections
    name: Block all prompt injections
    enabled: true
    action: block
    when:
      has_injections: true

  - id: sanitize-sensitive
    name: Auto-sanitize sensitive data above risk 5
    enabled: true
    action: sanitize
    when:
      has_sensitive: true
      min_risk_score: 5.0
```
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

import structlog
import yaml
from pydantic import BaseModel, Field

from claw_vault.config import DEFAULT_CONFIG_DIR, DEFAULT_CONFIG_FILE

logger = structlog.get_logger()

# Legacy path — kept only for migration detection in config.py.
RULES_FILE: Path = DEFAULT_CONFIG_DIR / "rules.yaml"


class RuleCondition(BaseModel):
    """Conditions under which a rule should fire.

    All fields are optional; unspecified fields are treated as "don't care".
    """

    # High-level flags
    has_sensitive: Optional[bool] = None
    has_commands: Optional[bool] = None
    has_injections: Optional[bool] = None

    # Match on computed scan properties
    threat_levels: Optional[list[str]] = None  # e.g. ["low", "medium", "high", "critical"]
    min_risk_score: Optional[float] = None

    # Match on specific detector pattern / reason types
    pattern_types: Optional[list[str]] = None


class RuleConfig(BaseModel):
    """Single rule definition stored in config.yaml under the ``rules`` key."""

    id: str
    name: str
    description: str = ""
    enabled: bool = True

    # One of "allow", "block", "sanitize", "ask_user"
    action: str

    # Matching condition
    when: RuleCondition = Field(default_factory=RuleCondition)

    # If we ever support multiple matches, this flag can be used
    # to continue evaluating further rules. For now, the first
    # matching rule wins, but we keep the field for forward-compat.
    stop_processing: bool = True

    # Optional metadata (e.g. "user" / "system")
    source: str = "user"


def load_rules(
    path: Path | None = None,
    raw_rules: list[dict[str, Any]] | None = None,
) -> list[RuleConfig]:
    """Load rules from the unified config or from an explicit list of dicts.

    *raw_rules*: if provided, parse these dicts directly (used when
    the caller already has ``Settings.rules`` in memory).

    *path*: if given, read this YAML file; extract the ``rules`` key if the
    root is a dict, or treat the whole file as a list (legacy format).
    """
    if raw_rules is not None:
        return _parse_rule_dicts(raw_rules)

    rules_path = path or DEFAULT_CONFIG_FILE
    if not rules_path.exists():
        return []

    try:
        raw = yaml.safe_load(rules_path.read_text(encoding="utf-8")) or {}
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.warning("guard.rules.load_failed", path=str(rules_path), error=str(exc))
        return []

    # Unified config: rules is a key in the dict
    if isinstance(raw, dict):
        entries = raw.get("rules", [])
        if not isinstance(entries, list):
            return []
        return _parse_rule_dicts(entries)

    # Legacy format: root is a list
    if isinstance(raw, list):
        return _parse_rule_dicts(raw)

    logger.warning(
        "guard.rules.invalid_format", path=str(rules_path), detail="unexpected root type"
    )
    return []


def _parse_rule_dicts(entries: list[Any]) -> list[RuleConfig]:
    """Validate a list of raw dicts into ``RuleConfig`` objects."""
    items: list[RuleConfig] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        try:
            items.append(RuleConfig(**entry))
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("guard.rules.invalid_entry", error=str(exc), entry=entry)
    return items


def save_rules(rules: list[RuleConfig], path: Path | None = None) -> None:
    """Persist rules into the unified config file.

    Reads the full config, replaces the ``rules`` key, and writes it back.
    """
    config_path = path or DEFAULT_CONFIG_FILE

    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)

        # Read existing config to preserve all other sections
        existing: dict[str, Any] = {}
        if config_path.exists():
            existing = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
            if not isinstance(existing, dict):
                existing = {}

        as_dicts = [r.model_dump(exclude_none=True) for r in rules]
        existing["rules"] = as_dicts

        config_path.write_text(
            yaml.safe_dump(existing, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.warning("guard.rules.save_failed", path=str(config_path), error=str(exc))


def export_rules(rules: list[RuleConfig]) -> list[dict[str, Any]]:
    """Convert rule models to plain dicts for JSON APIs."""
    return [r.model_dump(exclude_none=True) for r in rules]
