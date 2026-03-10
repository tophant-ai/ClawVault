"""Configuration models for ClawVault."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_CONFIG_DIR = Path.home() / ".claw-vault"
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.yaml"


class ProxyConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8765
    ssl_verify: bool = True
    intercept_hosts: list[str] = Field(
        default_factory=lambda: [
            "api.openai.com",
            "api.anthropic.com",
            "api.siliconflow.cn",
            "*.openai.azure.com",
            "generativelanguage.googleapis.com",
        ]
    )


class DetectionConfig(BaseModel):
    enabled: bool = True
    api_keys: bool = True
    passwords: bool = True
    private_ips: bool = True
    pii: bool = True
    # User-defined detection patterns, persisted in config.yaml.
    # Each item is a dict-like structure that can be interpreted by detectors
    # (e.g. name/regex/category/risk_score/enabled/description).
    custom_patterns: list[dict[str, Any]] = Field(default_factory=list)
    # User-defined test cases for the dashboard /scan tests.
    # Each item is expected to contain id/name/category/description/text and
    # optional bookkeeping fields (e.g. linked_pattern_ids, generated_by).
    custom_test_cases: list[dict[str, Any]] = Field(default_factory=list)


class GuardConfig(BaseModel):
    mode: str = "permissive"  # permissive | interactive | strict
    auto_sanitize: bool = True
    blocked_domains: list[str] = Field(default_factory=list)


class MonitorConfig(BaseModel):
    daily_token_budget: int = 50_000
    monthly_token_budget: int = 1_000_000
    cost_alert_usd: float = 50.0


class AuditConfig(BaseModel):
    retention_days: int = 7
    log_level: str = "INFO"
    export_format: str = "json"


class DashboardConfig(BaseModel):
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 8766


class CloudConfig(BaseModel):
    enabled: bool = False
    aiscc_api_url: str = "https://api.aiscc.io/v1/audit"
    aiscc_api_key: str = ""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CLAW_VAULT_",
        env_nested_delimiter="__",
    )

    config_dir: Path = DEFAULT_CONFIG_DIR
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    guard: GuardConfig = Field(default_factory=GuardConfig)
    monitor: MonitorConfig = Field(default_factory=MonitorConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)
    cloud: CloudConfig = Field(default_factory=CloudConfig)

    def ensure_dirs(self) -> None:
        self.config_dir.mkdir(parents=True, exist_ok=True)
        (self.config_dir / "certs").mkdir(exist_ok=True)
        (self.config_dir / "data").mkdir(exist_ok=True)


def load_settings(config_path: Optional[Path] = None) -> Settings:
    """Load settings from environment and optional YAML config file."""
    import yaml

    settings = Settings()
    path = config_path or DEFAULT_CONFIG_FILE
    if path.exists():
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        settings = Settings(**data)
    settings.ensure_dirs()
    return settings
