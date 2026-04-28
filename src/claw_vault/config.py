"""Configuration models for ClawVault."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import structlog
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = structlog.get_logger()

DEFAULT_CONFIG_DIR = Path.home() / ".ClawVault"
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.yaml"
# Kept for migration detection only — new code should not use this.
DEFAULT_AGENTS_FILE = DEFAULT_CONFIG_DIR / "agents.yaml"
_LEGACY_RULES_FILE = DEFAULT_CONFIG_DIR / "rules.yaml"


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
            "openrouter.ai",
            "dashscope.aliyuncs.com",
            "ark.cn-beijing.volces.com",
            "api.deepseek.com",
            "api.moonshot.cn",
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


class FileMonitorConfig(BaseModel):
    enabled: bool = True
    watch_home_sensitive: bool = True
    watch_project_sensitive: bool = True
    watch_paths: list[str] = Field(default_factory=list)
    watch_patterns: list[str] = Field(
        default_factory=lambda: [
            ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx",
            "secrets.yaml", "secrets.json", "credentials.json",
            "service-account*.json", "id_rsa", "id_ed25519",
        ]
    )
    scan_content_on_change: bool = True
    max_file_size_kb: int = 512
    watch_debounce_ms: int = 500
    watch_step_ms: int = 100
    alert_on_delete: bool = True
    alert_on_create: bool = True
    alert_on_modify: bool = True
    alert_on_access: bool = False
    access_debounce_seconds: int = 5


class LocalScanConfig(BaseModel):
    """Configuration for local filesystem scanning and scheduling."""

    enabled: bool = True
    default_scan_paths: list[str] = Field(default_factory=lambda: [str(Path.home())])
    max_files_per_scan: int = 200
    max_file_size_kb: int = 1024
    skip_dirs: list[str] = Field(
        default_factory=lambda: [
            "node_modules", ".git", "venv", "__pycache__", ".venv", ".cache",
        ]
    )
    scan_file_patterns: list[str] = Field(
        default_factory=lambda: [
            "*.env", "*.env.*", "*.yaml", "*.yml", "*.json", "*.toml",
            "*.ini", "*.cfg", "*.conf", "*.properties", "*.pem", "*.key",
        ]
    )
    schedules: list[dict[str, Any]] = Field(default_factory=list)
    history_max: int = 100


class AgentsConfig(BaseModel):
    """Per-agent overrides, previously stored in agents.yaml."""

    version: str = "1.0"
    entries: dict[str, dict[str, Any]] = Field(default_factory=dict)


class VaultPreset(BaseModel):
    """Configuration preset (vault scenario)."""

    id: str
    name: str
    description: str
    icon: str = "🔒"
    builtin: bool = False
    created_at: str = ""

    # Configuration snapshot
    detection: dict[str, Any]
    guard: dict[str, Any]
    file_monitor: dict[str, Any]
    rules: list[dict[str, Any]]


class VaultsConfig(BaseModel):
    """Vaults configuration container."""

    version: str = "1.0"
    presets: list[VaultPreset] = Field(default_factory=list)
    active_preset_id: str | None = None


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
    file_monitor: FileMonitorConfig = Field(default_factory=FileMonitorConfig)
    local_scan: LocalScanConfig = Field(default_factory=LocalScanConfig)
    rules: list[dict[str, Any]] = Field(default_factory=list)
    agents: AgentsConfig = Field(default_factory=AgentsConfig)
    vaults: VaultsConfig = Field(default_factory=VaultsConfig)

    def ensure_dirs(self) -> None:
        self.config_dir.mkdir(parents=True, exist_ok=True)
        (self.config_dir / "certs").mkdir(exist_ok=True)
        (self.config_dir / "data").mkdir(exist_ok=True)
        (self.config_dir / "state").mkdir(exist_ok=True)


def save_settings(settings: Settings, path: Path | None = None) -> None:
    """Serialize the full Settings model (including rules and agents) to YAML."""
    import yaml

    config_path = path or DEFAULT_CONFIG_FILE

    # Build detection dict with all boolean flags + custom_patterns
    detection = settings.detection.model_dump(mode="json")

    data: dict[str, Any] = {
        "proxy": settings.proxy.model_dump(mode="json"),
        "detection": detection,
        "guard": settings.guard.model_dump(mode="json"),
        "monitor": settings.monitor.model_dump(mode="json"),
        "audit": settings.audit.model_dump(mode="json"),
        "dashboard": settings.dashboard.model_dump(mode="json"),
        "cloud": settings.cloud.model_dump(mode="json"),
        "openclaw": settings.openclaw.model_dump(mode="json"),
        "file_monitor": settings.file_monitor.model_dump(mode="json"),
        "local_scan": settings.local_scan.model_dump(mode="json"),
        "rules": list(settings.rules),
        "agents": settings.agents.model_dump(mode="json"),
        "vaults": settings.vaults.model_dump(mode="json"),
    }

    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
    except Exception as exc:
        logger.warning("config.save_failed", path=str(config_path), error=str(exc))


def _migrate_legacy_files(settings: Settings, config_dir: Path) -> bool:
    """Migrate rules.yaml and agents.yaml into the unified Settings object.

    Returns True if any migration occurred.
    """
    import yaml

    migrated = False
    old_rules = config_dir / "rules.yaml"
    old_agents = config_dir / "agents.yaml"

    # Migrate rules.yaml
    if old_rules.exists() and not settings.rules:
        try:
            raw = yaml.safe_load(old_rules.read_text(encoding="utf-8")) or []
            if isinstance(raw, list):
                settings.rules = [e for e in raw if isinstance(e, dict)]
                migrated = True
                logger.info("config.migrated_rules", path=str(old_rules))
        except Exception as exc:
            logger.warning("config.migrate_rules_failed", error=str(exc))

    # Migrate agents.yaml
    if old_agents.exists() and not settings.agents.entries:
        try:
            raw = yaml.safe_load(old_agents.read_text(encoding="utf-8")) or {}
            entries = raw.get("agents", {})
            if isinstance(entries, dict):
                settings.agents.entries = entries
                settings.agents.version = raw.get("version", "1.0")
                migrated = True
                logger.info("config.migrated_agents", path=str(old_agents))
        except Exception as exc:
            logger.warning("config.migrate_agents_failed", error=str(exc))

    # Rename old files to .bak so migration doesn't re-trigger
    if migrated:
        for old_file in (old_rules, old_agents):
            if old_file.exists():
                try:
                    old_file.rename(old_file.with_suffix(".yaml.bak"))
                except Exception as exc:
                    logger.warning(
                        "config.rename_legacy_failed", path=str(old_file), error=str(exc)
                    )

    return migrated


def load_settings(config_path: Path | None = None) -> Settings:
    """Load settings from environment and optional YAML config file."""
    import yaml

    settings = Settings()
    path = config_path or DEFAULT_CONFIG_FILE
    if path.exists():
        with open(path, encoding='utf-8') as f:
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

    # Migrate legacy separate files into unified config
    config_dir = path.parent if path else DEFAULT_CONFIG_DIR
    if _migrate_legacy_files(settings, config_dir):
        save_settings(settings, path)

    # Initialize or refresh builtin presets
    builtins = get_builtin_presets()
    builtin_ids = {p.id for p in builtins}
    if not settings.vaults.presets:
        settings.vaults.presets = builtins
        save_settings(settings, path)
    else:
        # Replace stale builtins, keep custom presets
        custom = [p for p in settings.vaults.presets if not p.builtin]
        existing_builtin_ids = {p.id for p in settings.vaults.presets if p.builtin}
        if existing_builtin_ids != builtin_ids:
            settings.vaults.presets = builtins + custom
            save_settings(settings, path)

    return settings


def get_builtin_presets() -> list[VaultPreset]:
    """Return builtin vault presets for common protection scenarios."""
    from datetime import datetime
    now = datetime.now().isoformat()

    return [
        VaultPreset(
            id="file-protection",
            name="File Protection",
            description="Monitor and protect sensitive files: .env, keys, certificates, secrets",
            icon="📁",
            builtin=True,
            created_at=now,
            detection={"enabled": True, "api_keys": True, "passwords": True, "private_ips": False, "pii": False, "jwt_tokens": False, "ssh_keys": True, "credit_cards": False, "emails": False, "generic_secrets": True, "dangerous_commands": False, "prompt_injection": False, "aws_credentials": True, "blockchain": False, "custom_patterns": []},
            guard={"mode": "strict", "auto_sanitize": True, "blocked_domains": []},
            file_monitor={"enabled": True, "watch_home_sensitive": True, "watch_paths": [], "watch_patterns": [".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.crt", "*.cer", "secrets.yaml", "secrets.json", "credentials.json", "service-account*.json", "id_rsa", "id_ed25519"], "scan_content_on_change": True, "max_file_size_kb": 1024, "watch_debounce_ms": 500, "watch_step_ms": 100, "alert_on_delete": True, "alert_on_create": True, "alert_on_modify": True, "alert_on_access": False, "access_debounce_seconds": 5},
            rules=[{"id": "block-leaked-keys", "name": "Block leaked API keys in files", "enabled": True, "action": "block", "when": {"has_sensitive": True, "min_risk_score": 7}}],
        ),
        VaultPreset(
            id="photo-protection",
            name="Photo & Media Protection",
            description="Prevent exposure of image metadata, GPS locations, and personal media paths",
            icon="📷",
            builtin=True,
            created_at=now,
            detection={"enabled": True, "api_keys": False, "passwords": False, "private_ips": True, "pii": True, "jwt_tokens": False, "ssh_keys": False, "credit_cards": False, "emails": True, "generic_secrets": False, "dangerous_commands": False, "prompt_injection": True, "aws_credentials": False, "blockchain": False, "custom_patterns": []},
            guard={"mode": "interactive", "auto_sanitize": True, "blocked_domains": []},
            file_monitor={"enabled": True, "watch_home_sensitive": False, "watch_paths": [], "watch_patterns": ["*.jpg", "*.jpeg", "*.png", "*.heic", "*.raw", "*.exif", "*.tiff"], "scan_content_on_change": False, "max_file_size_kb": 256, "watch_debounce_ms": 500, "watch_step_ms": 100, "alert_on_delete": True, "alert_on_create": True, "alert_on_modify": True, "alert_on_access": False, "access_debounce_seconds": 5},
            rules=[{"id": "block-pii-in-media", "name": "Block PII exposure in media context", "enabled": True, "action": "block", "when": {"has_sensitive": True, "pattern_types": ["pii", "email"]}}],
        ),
        VaultPreset(
            id="account-secrets",
            name="Account & Secret Protection",
            description="Guard API keys, passwords, tokens, and cloud credentials from leaking",
            icon="🔐",
            builtin=True,
            created_at=now,
            detection={"enabled": True, "api_keys": True, "passwords": True, "private_ips": False, "pii": False, "jwt_tokens": True, "ssh_keys": True, "credit_cards": True, "emails": False, "generic_secrets": True, "dangerous_commands": False, "prompt_injection": False, "aws_credentials": True, "blockchain": True, "custom_patterns": []},
            guard={"mode": "strict", "auto_sanitize": True, "blocked_domains": []},
            file_monitor={"enabled": True, "watch_home_sensitive": True, "watch_paths": [], "watch_patterns": [".env", ".env.*", "*.key", "*.pem", "credentials.json", "service-account*.json", ".npmrc", ".pypirc", ".docker/config.json"], "scan_content_on_change": True, "max_file_size_kb": 512, "watch_debounce_ms": 500, "watch_step_ms": 100, "alert_on_delete": True, "alert_on_create": True, "alert_on_modify": True, "alert_on_access": False, "access_debounce_seconds": 5},
            rules=[{"id": "block-all-credentials", "name": "Block all credential leaks", "enabled": True, "action": "block", "when": {"has_sensitive": True}}, {"id": "block-injections", "name": "Block prompt injections", "enabled": True, "action": "block", "when": {"has_injections": True}}],
        ),
        VaultPreset(
            id="privacy-shield",
            name="Privacy Shield",
            description="Protect personal identity: PII, emails, phone numbers, addresses, IDs",
            icon="🛡️",
            builtin=True,
            created_at=now,
            detection={"enabled": True, "api_keys": False, "passwords": False, "private_ips": True, "pii": True, "jwt_tokens": False, "ssh_keys": False, "credit_cards": True, "emails": True, "generic_secrets": False, "dangerous_commands": False, "prompt_injection": True, "aws_credentials": False, "blockchain": False, "custom_patterns": []},
            guard={"mode": "interactive", "auto_sanitize": True, "blocked_domains": []},
            file_monitor={"enabled": False, "watch_home_sensitive": False, "watch_paths": [], "watch_patterns": [".env"], "scan_content_on_change": True, "max_file_size_kb": 512, "watch_debounce_ms": 500, "watch_step_ms": 100, "alert_on_delete": False, "alert_on_create": False, "alert_on_modify": False, "alert_on_access": False, "access_debounce_seconds": 5},
            rules=[{"id": "sanitize-pii", "name": "Auto-sanitize personal data", "enabled": True, "action": "sanitize", "when": {"has_sensitive": True, "pattern_types": ["pii", "credit_card", "email"]}}],
        ),
        VaultPreset(
            id="full-lockdown",
            name="Full Lockdown",
            description="Maximum protection: block all threats, monitor all files, strict mode",
            icon="🔒",
            builtin=True,
            created_at=now,
            detection={"enabled": True, "api_keys": True, "passwords": True, "private_ips": True, "pii": True, "jwt_tokens": True, "ssh_keys": True, "credit_cards": True, "emails": True, "generic_secrets": True, "dangerous_commands": True, "prompt_injection": True, "aws_credentials": True, "blockchain": True, "custom_patterns": []},
            guard={"mode": "strict", "auto_sanitize": True, "blocked_domains": []},
            file_monitor={"enabled": True, "watch_home_sensitive": True, "watch_paths": [], "watch_patterns": [".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.crt", "*.cer", "secrets.yaml", "secrets.json", "credentials.json", "service-account*.json", "id_rsa", "id_ed25519"], "scan_content_on_change": True, "max_file_size_kb": 512, "watch_debounce_ms": 500, "watch_step_ms": 100, "alert_on_delete": True, "alert_on_create": True, "alert_on_modify": True, "alert_on_access": False, "access_debounce_seconds": 5},
            rules=[{"id": "block-all-sensitive", "name": "Block all sensitive data", "enabled": True, "action": "block", "when": {"has_sensitive": True}}, {"id": "block-all-injections", "name": "Block all injections", "enabled": True, "action": "block", "when": {"has_injections": True}}, {"id": "block-all-commands", "name": "Block all dangerous commands", "enabled": True, "action": "block", "when": {"has_commands": True}}],
        ),
    ]

