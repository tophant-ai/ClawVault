"""Persistence and data models for custom guard rules.

Rules are stored in a YAML file under the ClawVault config directory:
`~/.ClawVault/rules.yaml`.

The format is intentionally simple and human-friendly, for example:

```yaml
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
from typing import List, Optional

import structlog
import yaml
from pydantic import BaseModel, Field

from claw_vault.config import DEFAULT_CONFIG_DIR

logger = structlog.get_logger()

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
    """Single rule definition stored in rules.yaml."""

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


def load_rules(path: Path | None = None) -> list[RuleConfig]:
    """Load rules from YAML. Returns an empty list on any error."""
    rules_path = path or RULES_FILE
    if not rules_path.exists():
        return []

    try:
        raw = yaml.safe_load(rules_path.read_text(encoding="utf-8")) or []
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.warning("guard.rules.load_failed", path=str(rules_path), error=str(exc))
        return []

    if not isinstance(raw, list):
        logger.warning(
            "guard.rules.invalid_format", path=str(rules_path), detail="root is not a list"
        )
        return []

    items: list[RuleConfig] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        try:
            items.append(RuleConfig(**entry))
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("guard.rules.invalid_entry", error=str(exc), entry=entry)
    return items


def save_rules(rules: list[RuleConfig], path: Path | None = None) -> None:
    """Persist rules to YAML. Best-effort with warning logs on failure."""
    rules_path = path or RULES_FILE
    try:
        rules_path.parent.mkdir(parents=True, exist_ok=True)
        as_dicts = [r.model_dump(exclude_none=True) for r in rules]
        rules_path.write_text(
            yaml.safe_dump(as_dicts, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.warning("guard.rules.save_failed", path=str(rules_path), error=str(exc))


def export_rules(rules: list[RuleConfig]) -> list[dict]:
    """Convert rule models to plain dicts for JSON APIs."""
    return [r.model_dump(exclude_none=True) for r in rules]
