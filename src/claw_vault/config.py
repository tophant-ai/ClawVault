"""Configuration models for ClawVault."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_CONFIG_DIR = Path.home() / ".ClawVault"
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.yaml"
DEFAULT_AGENTS_FILE = DEFAULT_CONFIG_DIR / "agents.yaml"


class ProxyConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8765
    ssl_verify: bool = True
    traffic_log_enabled: bool = True
    traffic_log_path: Path = DEFAULT_CONFIG_DIR / "data" / "proxy_traffic.jsonl"
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
    aws_credentials: bool = True
    blockchain: bool = True
    passwords: bool = True
    private_ips: bool = True
    pii: bool = True
    jwt_tokens: bool = True
    ssh_keys: bool = True
    credit_cards: bool = True
    emails: bool = True
    generic_secrets: bool = True
    dangerous_commands: bool = True
    prompt_injection: bool = True
    custom_patterns: list[str] = Field(default_factory=list)


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


class OpenClawSessionRedactionConfig(BaseModel):
    enabled: bool = True
    sessions_root: Path = Path.home() / ".openclaw" / "agents"
    additional_sessions_roots: list[Path] = Field(default_factory=list)
    auto_discover_sessions_roots: bool = True
    state_file: Path = DEFAULT_CONFIG_DIR / "state" / "openclaw_session_redactor.json"
    lock_timeout_ms: int = 3000
    watch_debounce_ms: int = 250
    watch_step_ms: int = 50
    processing_retries: int = 3


class OpenClawConfig(BaseModel):
    session_redaction: OpenClawSessionRedactionConfig = Field(
        default_factory=OpenClawSessionRedactionConfig
    )


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
    openclaw: OpenClawConfig = Field(default_factory=OpenClawConfig)

    def ensure_dirs(self) -> None:
        self.config_dir.mkdir(parents=True, exist_ok=True)
        (self.config_dir / "certs").mkdir(exist_ok=True)
        (self.config_dir / "data").mkdir(exist_ok=True)
        (self.config_dir / "state").mkdir(exist_ok=True)


def load_settings(config_path: Path | None = None) -> Settings:
    """Load settings from environment and optional YAML config file."""
    import yaml

    settings = Settings()
    path = config_path or DEFAULT_CONFIG_FILE
    if path.exists():
        with open(path) as f:
            data = yaml.safe_load(f) or {}

        # Fix corrupted custom_patterns field if present
        if "detection" in data and "custom_patterns" in data["detection"]:
            custom_patterns = data["detection"]["custom_patterns"]
            if isinstance(custom_patterns, list):
                # Filter out any non-string items (e.g., dict objects)
                data["detection"]["custom_patterns"] = [
                    p for p in custom_patterns if isinstance(p, str)
                ]
            else:
                # Reset to empty list if not a list
                data["detection"]["custom_patterns"] = []

        settings = Settings(**data)
    settings.ensure_dirs()
    return settings
