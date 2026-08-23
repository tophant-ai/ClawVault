"""Utilities for loading the canonical default ClawVault configuration."""

from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Any

import yaml

_TEMPLATE_NAME = "config.example.yaml"

_INLINE_DEFAULT_CONFIG = """\
# ClawVault Configuration
# Copy to ~/.ClawVault/config.yaml and customize

proxy:
  host: "127.0.0.1"
  port: 8765
  ssl_verify: true
  intercept_hosts:
    - "api.openai.com"
    - "api.anthropic.com"
    - "api.siliconflow.cn"
    - "*.openai.azure.com"
    - "generativelanguage.googleapis.com"
    - "openrouter.ai"
    - "dashscope.aliyuncs.com"
    - "ark.cn-beijing.volces.com"
    - "api.deepseek.com"
    - "api.moonshot.cn"
    - "api.minimax.io"
    - "api.minimaxi.com"

detection:
  enabled: true
  api_keys: true
  passwords: true
  private_ips: true
  pii: true
  custom_patterns: []

guard:
  mode: "permissive" # permissive | interactive | strict
  auto_sanitize: false
  blocked_domains: []

monitor:
  daily_token_budget: 50000
  monthly_token_budget: 1000000
  cost_alert_usd: 50.0

audit:
  retention_days: 7
  log_level: "INFO"
  export_format: "json"

dashboard:
  enabled: true
  host: "127.0.0.1"
  port: 8766

cloud:
  enabled: false
  aiscc_api_url: "https://api.aiscc.io/v1/audit"
  aiscc_api_key: ""

openclaw:
  session_redaction:
    enabled: true
    sessions_root: "~/.openclaw/agents"
    state_file: "~/.ClawVault/state/openclaw_session_redactor.json"
    lock_timeout_ms: 3000
    watch_debounce_ms: 250
    watch_step_ms: 50
    processing_retries: 3

file_monitor:
  enabled: true
  watch_home_sensitive: true
  watch_project_sensitive: true
  watch_patterns:
    - ".env"
    - ".env.*"
    - "*.pem"
    - "*.key"
    - "*.p12"
    - "*.pfx"
    - "secrets.yaml"
    - "secrets.json"
    - "credentials.json"
    - "service-account*.json"
    - "id_rsa"
    - "id_ed25519"
  scan_content_on_change: true
  max_file_size_kb: 512
  alert_on_delete: true
  alert_on_create: true
  alert_on_modify: true

rules: []

agents:
  version: "1.0"
  entries: {}

vaults:
  version: "1.0"
  presets: []
"""


def get_default_config_text() -> str:
    """Return the canonical default config YAML text.

    The packaged resource is used first so pip/GitHub installs behave the same
    as source checkouts. Source-tree lookup keeps editable/development flows
    resilient, and the inline fallback is a final safety net.
    """
    try:
        resource = resources.files("claw_vault").joinpath(_TEMPLATE_NAME)
        if resource.is_file():
            return resource.read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, OSError, TypeError):
        pass

    for parent in Path(__file__).resolve().parents:
        candidate = parent / _TEMPLATE_NAME
        if candidate.exists():
            return candidate.read_text(encoding="utf-8")

    return _INLINE_DEFAULT_CONFIG


def get_default_config() -> dict[str, Any]:
    """Return the canonical default config parsed as a dictionary."""
    config = yaml.safe_load(get_default_config_text())
    if not isinstance(config, dict):
        return yaml.safe_load(_INLINE_DEFAULT_CONFIG)
    return config
