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


DETECTION_FLAGS: tuple[str, ...] = (
    "api_keys", "aws_credentials", "blockchain", "passwords", "private_ips",
    "pii", "jwt_tokens", "ssh_keys", "credit_cards", "emails",
    "generic_secrets", "dangerous_commands", "prompt_injection",
)


def _det(*on: str, custom_patterns: list[str] | None = None) -> dict[str, Any]:
    """Build a detection dict: all flags off except those named in ``on``."""
    d: dict[str, Any] = {flag: flag in on for flag in DETECTION_FLAGS}
    d["enabled"] = True
    d["custom_patterns"] = list(custom_patterns or [])
    return d


def _guard(mode: str, *, auto_sanitize: bool = True) -> dict[str, Any]:
    """Build a guard config dict from Pydantic defaults + overrides."""
    return GuardConfig(mode=mode, auto_sanitize=auto_sanitize).model_dump(mode="json")


def _fm(**overrides: Any) -> dict[str, Any]:
    """Build a file_monitor dict from Pydantic defaults + overrides."""
    return FileMonitorConfig(**overrides).model_dump(mode="json")


def _preset(
    id: str,
    name: str,
    description: str,
    icon: str,
    *,
    created_at: str,
    detection: dict[str, Any],
    guard: dict[str, Any],
    file_monitor: dict[str, Any],
    rules: list[dict[str, Any]],
) -> VaultPreset:
    """Construct a builtin VaultPreset, injecting builtin=True + created_at."""
    return VaultPreset(
        id=id, name=name, description=description, icon=icon,
        builtin=True, created_at=created_at,
        detection=detection, guard=guard,
        file_monitor=file_monitor, rules=rules,
    )


def get_builtin_presets() -> list[VaultPreset]:
    """Return builtin vault presets for common protection scenarios."""
    from datetime import datetime
    now = datetime.now().isoformat()

    return [
        _preset(
            "file-protection", "File Protection",
            "Monitor and protect sensitive files: .env, keys, certificates, secrets",
            "📁", created_at=now,
            detection=_det("api_keys", "passwords", "ssh_keys", "generic_secrets", "aws_credentials"),
            guard=_guard("strict"),
            file_monitor=_fm(
                watch_patterns=[".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx",
                                "*.crt", "*.cer", "secrets.yaml", "secrets.json",
                                "credentials.json", "service-account*.json",
                                "id_rsa", "id_ed25519"],
                max_file_size_kb=1024,
            ),
            rules=[{"id": "block-leaked-keys", "name": "Block leaked API keys in files",
                    "enabled": True, "action": "block",
                    "when": {"has_sensitive": True, "min_risk_score": 7}}],
        ),
        _preset(
            "photo-protection", "Photo & Media Protection",
            "Prevent exposure of image metadata, GPS locations, and personal media paths",
            "📷", created_at=now,
            detection=_det("private_ips", "pii", "emails", "prompt_injection"),
            guard=_guard("interactive"),
            file_monitor=_fm(
                watch_home_sensitive=False,
                watch_patterns=["*.jpg", "*.jpeg", "*.png", "*.heic", "*.raw", "*.exif", "*.tiff"],
                scan_content_on_change=False,
                max_file_size_kb=256,
            ),
            rules=[{"id": "block-pii-in-media", "name": "Block PII exposure in media context",
                    "enabled": True, "action": "block",
                    "when": {"has_sensitive": True, "pattern_types": ["pii", "email"]}}],
        ),
        _preset(
            "account-secrets", "Account & Secret Protection",
            "Guard API keys, passwords, tokens, and cloud credentials from leaking",
            "🔐", created_at=now,
            detection=_det("api_keys", "passwords", "jwt_tokens", "ssh_keys",
                           "credit_cards", "generic_secrets", "aws_credentials", "blockchain"),
            guard=_guard("strict"),
            file_monitor=_fm(
                watch_patterns=[".env", ".env.*", "*.key", "*.pem", "credentials.json",
                                "service-account*.json", ".npmrc", ".pypirc", ".docker/config.json"],
            ),
            rules=[{"id": "block-all-credentials", "name": "Block all credential leaks",
                    "enabled": True, "action": "block", "when": {"has_sensitive": True}},
                   {"id": "block-injections", "name": "Block prompt injections",
                    "enabled": True, "action": "block", "when": {"has_injections": True}}],
        ),
        _preset(
            "privacy-shield", "Privacy Shield",
            "Protect personal identity: PII, emails, phone numbers, addresses, IDs",
            "🛡️", created_at=now,
            detection=_det("private_ips", "pii", "credit_cards", "emails", "prompt_injection"),
            guard=_guard("interactive"),
            file_monitor=_fm(
                enabled=False,
                watch_home_sensitive=False,
                watch_patterns=[".env"],
                alert_on_delete=False,
                alert_on_create=False,
                alert_on_modify=False,
            ),
            rules=[{"id": "sanitize-pii", "name": "Auto-sanitize personal data",
                    "enabled": True, "action": "sanitize",
                    "when": {"has_sensitive": True, "pattern_types": ["pii", "credit_card", "email"]}}],
        ),
        _preset(
            "full-lockdown", "Full Lockdown",
            "Maximum protection: block all threats, monitor all files, strict mode",
            "🔒", created_at=now,
            detection=_det(*DETECTION_FLAGS),
            guard=_guard("strict"),
            file_monitor=_fm(
                watch_patterns=[".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx",
                                "*.crt", "*.cer", "secrets.yaml", "secrets.json",
                                "credentials.json", "service-account*.json",
                                "id_rsa", "id_ed25519"],
            ),
            rules=[{"id": "block-all-sensitive", "name": "Block all sensitive data",
                    "enabled": True, "action": "block", "when": {"has_sensitive": True}},
                   {"id": "block-all-injections", "name": "Block all injections",
                    "enabled": True, "action": "block", "when": {"has_injections": True}},
                   {"id": "block-all-commands", "name": "Block all dangerous commands",
                    "enabled": True, "action": "block", "when": {"has_commands": True}}],
        ),
        _preset(
            "developer-workflow", "Developer Workflow",
            "Protect dev environments: shell history, git config, SSH config, and hardcoded secrets in source",
            "💻", created_at=now,
            detection=_det("api_keys", "passwords", "jwt_tokens", "ssh_keys",
                           "generic_secrets", "aws_credentials", "prompt_injection"),
            guard=_guard("interactive"),
            file_monitor=_fm(
                watch_patterns=[".env", ".env.*", ".bash_history", ".zsh_history",
                                ".gitconfig", ".git-credentials", ".netrc", "config",
                                "*.py", "*.js", "*.ts", "*.go", "*.rs", "*.java", "*.rb"],
                max_file_size_kb=2048,
            ),
            rules=[{"id": "sanitize-dev-keys", "name": "Sanitize hardcoded API keys",
                    "enabled": True, "action": "sanitize",
                    "when": {"has_sensitive": True,
                             "pattern_types": ["api_key", "generic_secret", "aws_credential"]}},
                   {"id": "ask-on-injection", "name": "Ask user on prompt injection",
                    "enabled": True, "action": "ask_user", "when": {"has_injections": True}}],
        ),
        _preset(
            "cloud-infra", "Cloud Infrastructure & IaC",
            "Lock down Terraform state, Kubernetes manifests, Ansible vaults, and cloud credential files",
            "☁️", created_at=now,
            detection=_det("api_keys", "passwords", "jwt_tokens", "ssh_keys",
                           "generic_secrets", "dangerous_commands", "aws_credentials"),
            guard=_guard("strict"),
            file_monitor=_fm(
                watch_paths=["~/.aws", "~/.kube", "~/.config/gcloud", "~/.azure"],
                watch_patterns=["*.tf", "*.tfstate", "*.tfstate.backup", "*.tfvars",
                                "terraform.tfvars.json", "*.yaml", "*.yml", "kubeconfig",
                                ".kube/config", "ansible-vault", "*.vault", "values.yaml"],
                max_file_size_kb=2048,
            ),
            rules=[{"id": "block-cloud-creds", "name": "Block AWS/cloud credential leaks",
                    "enabled": True, "action": "block",
                    "when": {"has_sensitive": True, "pattern_types": ["aws_credential"]}},
                   {"id": "block-high-risk-commands", "name": "Block high-risk commands",
                    "enabled": True, "action": "block",
                    "when": {"has_commands": True, "threat_levels": ["high", "critical"]}}],
        ),
        _preset(
            "crypto-wallet", "Crypto Wallet Protection",
            "Guard cryptocurrency wallets, keystores, mnemonics, and seed phrases from exfiltration",
            "💰", created_at=now,
            detection=_det("passwords", "ssh_keys", "generic_secrets", "blockchain"),
            guard=_guard("strict", auto_sanitize=False),
            file_monitor=_fm(
                watch_patterns=["wallet.dat", "keystore*", "UTC--*", "seed.txt",
                                "mnemonic*", "*.wallet", "*.keystore"],
                alert_on_access=True,
            ),
            rules=[{"id": "block-wallet-leak", "name": "Block blockchain wallet leaks",
                    "enabled": True, "action": "block",
                    "when": {"has_sensitive": True,
                             "pattern_types": ["blockchain_wallet", "blockchain_private_key",
                                               "blockchain_mnemonic"]}}],
        ),
        _preset(
            "database-protection", "Database Protection",
            "Prevent leakage of SQL dumps, connection strings, backup files, and exported datasets",
            "🗄️", created_at=now,
            detection=_det("passwords", "pii", "credit_cards", "emails", "generic_secrets"),
            guard=_guard("strict"),
            file_monitor=_fm(
                watch_home_sensitive=False,
                watch_patterns=["*.sql", "*.dump", "*.bak", "*.db", "*.sqlite",
                                "*.sqlite3", "*.mdb", "dump.rdb", "mongodump*",
                                "*.csv", "*.tsv"],
                max_file_size_kb=8192,
            ),
            rules=[{"id": "block-dump-leak", "name": "Block database dump leaks",
                    "enabled": True, "action": "block",
                    "when": {"has_sensitive": True, "min_risk_score": 6}},
                   {"id": "sanitize-pii-in-dumps", "name": "Sanitize PII in dumps",
                    "enabled": True, "action": "sanitize",
                    "when": {"has_sensitive": True,
                             "pattern_types": ["email", "credit_card", "pii"]}}],
        ),
        _preset(
            "healthcare-hipaa", "Healthcare & HIPAA",
            "HIPAA-aligned protection for medical records, patient PII, and health data exchange files",
            "🏥", created_at=now,
            detection=_det("pii", "credit_cards", "emails", "prompt_injection",
                           custom_patterns=[r"\bMRN[-:\s]*\d{6,10}\b",
                                            r"\b\d{3}-\d{2}-\d{4}\b"]),
            guard=_guard("strict"),
            file_monitor=_fm(
                watch_home_sensitive=False,
                watch_patterns=["*.hl7", "*.dcm", "*.dicom", "*.cda",
                                "patient*.pdf", "medical*.pdf", "records*.csv"],
                max_file_size_kb=4096,
            ),
            rules=[{"id": "block-patient-pii", "name": "Block patient PII exposure",
                    "enabled": True, "action": "block",
                    "when": {"has_sensitive": True, "pattern_types": ["pii", "email"]}},
                   {"id": "sanitize-health-data", "name": "Sanitize health data",
                    "enabled": True, "action": "sanitize",
                    "when": {"has_sensitive": True, "min_risk_score": 4}}],
        ),
        _preset(
            "financial-strict", "Financial Strict Mode",
            "Strict blocking for financial records: credit cards, bank accounts, IBANs, statements",
            "💳", created_at=now,
            detection=_det("passwords", "pii", "credit_cards", "emails", "prompt_injection",
                           custom_patterns=[r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"]),
            guard=_guard("strict", auto_sanitize=False),
            file_monitor=_fm(
                watch_home_sensitive=False,
                watch_patterns=["*.csv", "invoice*.pdf", "statement*.pdf", "tax*.pdf",
                                "payroll*", "*.ofx", "*.qfx", "*.xlsx"],
                max_file_size_kb=4096,
            ),
            rules=[{"id": "block-credit-cards", "name": "Block credit card leaks",
                    "enabled": True, "action": "block",
                    "when": {"has_sensitive": True, "pattern_types": ["credit_card"]}},
                   {"id": "block-high-risk-financial", "name": "Block high-risk financial data",
                    "enabled": True, "action": "block",
                    "when": {"has_sensitive": True, "min_risk_score": 7}}],
        ),
        _preset(
            "audit-only", "Audit Only",
            "Full detection with all threats allowed — logs every event without blocking, ideal for onboarding",
            "📝", created_at=now,
            detection=_det(*DETECTION_FLAGS),
            guard=_guard("permissive", auto_sanitize=False),
            file_monitor=_fm(
                enabled=False,
                watch_home_sensitive=False,
                watch_patterns=[".env"],
                scan_content_on_change=False,
                alert_on_delete=False,
                alert_on_create=False,
                alert_on_modify=False,
            ),
            rules=[{"id": "allow-all-audited", "name": "Allow all (audit logged)",
                    "enabled": True, "action": "allow", "when": {"has_sensitive": True}}],
        ),
        _preset(
            "communication-logs", "Communication Logs",
            "Protect exported emails, chat logs, and IM archives from PII and contact leakage",
            "💬", created_at=now,
            detection=_det("private_ips", "pii", "emails", "prompt_injection"),
            guard=_guard("interactive"),
            file_monitor=_fm(
                watch_home_sensitive=False,
                watch_patterns=["*.mbox", "*.eml", "*.pst", "*.ost", "*.msg", "*.vcf",
                                "slack_export*", "discord_export*", "chat*.json", "*.chatlog"],
                max_file_size_kb=4096,
            ),
            rules=[{"id": "sanitize-comm-pii", "name": "Sanitize PII in communications",
                    "enabled": True, "action": "sanitize",
                    "when": {"has_sensitive": True,
                             "pattern_types": ["pii", "email", "phone_cn"]}},
                   {"id": "ask-on-comm-injection", "name": "Ask on injection in logs",
                    "enabled": True, "action": "ask_user",
                    "when": {"has_injections": True}}],
        ),
        _preset(
            "source-code-repo", "Source Code Repository",
            "Scan source trees for hardcoded secrets, credentials in git configs, and leaked API keys",
            "📦", created_at=now,
            detection=_det("api_keys", "passwords", "jwt_tokens", "ssh_keys",
                           "generic_secrets", "aws_credentials", "blockchain"),
            guard=_guard("strict"),
            file_monitor=_fm(
                watch_home_sensitive=False,
                watch_patterns=[".git/config", ".git-credentials", ".gitconfig",
                                "*.py", "*.js", "*.ts", "*.go", "*.rs", "*.java", "*.rb",
                                "*.php", "*.c", "*.cpp", "*.cs", "*.swift", "*.kt",
                                "Dockerfile", "docker-compose*.yml", "Makefile"],
                max_file_size_kb=2048,
            ),
            rules=[{"id": "block-hardcoded-keys", "name": "Block hardcoded keys in source",
                    "enabled": True, "action": "block",
                    "when": {"has_sensitive": True,
                             "pattern_types": ["api_key", "aws_credential",
                                               "jwt_token", "generic_secret"]}},
                   {"id": "sanitize-passwords", "name": "Sanitize hardcoded passwords",
                    "enabled": True, "action": "sanitize",
                    "when": {"has_sensitive": True, "pattern_types": ["password"]}}],
        ),
        _preset(
            "ci-cd-pipelines", "CI/CD Pipelines",
            "Guard CI configuration files — GitHub Actions, GitLab CI, Jenkins, CircleCI — from secret leaks",
            "🔧", created_at=now,
            detection=_det("api_keys", "passwords", "jwt_tokens", "ssh_keys",
                           "generic_secrets", "dangerous_commands", "aws_credentials"),
            guard=_guard("strict"),
            file_monitor=_fm(
                watch_home_sensitive=False,
                watch_patterns=["*.yml", "*.yaml", "Jenkinsfile", ".travis.yml",
                                "azure-pipelines.yml", "bitbucket-pipelines.yml",
                                ".drone.yml", ".woodpecker.yml", "buildkite.yml"],
                max_file_size_kb=1024,
            ),
            rules=[{"id": "block-ci-secrets", "name": "Block inline CI secrets",
                    "enabled": True, "action": "block", "when": {"has_sensitive": True}},
                   {"id": "block-ci-dangerous-cmds", "name": "Block high-risk CI commands",
                    "enabled": True, "action": "block",
                    "when": {"has_commands": True, "threat_levels": ["high", "critical"]}}],
        ),
        _preset(
            "mobile-dev", "Mobile Development",
            "Protect mobile signing keys, Firebase configs, keystores, and provisioning profiles",
            "📱", created_at=now,
            detection=_det("api_keys", "passwords", "jwt_tokens", "ssh_keys",
                           "generic_secrets", "aws_credentials"),
            guard=_guard("strict", auto_sanitize=False),
            file_monitor=_fm(
                watch_home_sensitive=False,
                watch_patterns=["GoogleService-Info.plist", "google-services.json",
                                "*.keystore", "*.jks", "*.p12", "*.mobileprovision",
                                "*.cer", "AuthKey_*.p8", "api_keys.xml",
                                "gradle.properties", "local.properties", "Podfile.lock"],
                max_file_size_kb=2048,
            ),
            rules=[{"id": "block-mobile-secrets", "name": "Block mobile signing secrets",
                    "enabled": True, "action": "block", "when": {"has_sensitive": True}},
                   {"id": "block-mobile-api-keys", "name": "Block mobile API keys",
                    "enabled": True, "action": "block",
                    "when": {"has_sensitive": True,
                             "pattern_types": ["api_key", "generic_secret"]}}],
        ),
        _preset(
            "backup-archive", "Backup & Archive Files",
            "Scan archives (tar, zip, 7z, rar) and backup images for embedded credentials and PII",
            "🗜️", created_at=now,
            detection=_det("api_keys", "passwords", "pii", "ssh_keys", "credit_cards",
                           "generic_secrets", "aws_credentials"),
            guard=_guard("strict", auto_sanitize=False),
            file_monitor=_fm(
                watch_home_sensitive=False,
                watch_patterns=["*.tar", "*.tar.gz", "*.tgz", "*.tar.bz2", "*.tbz2",
                                "*.tar.xz", "*.zip", "*.7z", "*.rar", "*.bak",
                                "*.backup", "*.img", "*.iso"],
                scan_content_on_change=False,
                max_file_size_kb=16384,
            ),
            rules=[{"id": "block-high-risk-archive", "name": "Block high-risk archives",
                    "enabled": True, "action": "block",
                    "when": {"has_sensitive": True, "min_risk_score": 7}}],
        ),
        _preset(
            "legal-contracts", "Legal & Contracts",
            "Safeguard legal documents — contracts, NDAs, agreements — from client name and term leakage",
            "📜", created_at=now,
            detection=_det("pii", "credit_cards", "emails", "prompt_injection",
                           custom_patterns=[r"Contract\s*No\.?[-:\s]*[A-Z0-9-]{6,}",
                                            r"\$\d{1,3}(,\d{3})+(\.\d{2})?"]),
            guard=_guard("interactive"),
            file_monitor=_fm(
                watch_home_sensitive=False,
                watch_patterns=["contract*.pdf", "agreement*.pdf", "nda*.pdf",
                                "*.docx", "*.doc", "legal*.pdf", "mou*.pdf", "sow*.pdf"],
                max_file_size_kb=10240,
            ),
            rules=[{"id": "sanitize-legal-pii", "name": "Sanitize PII in contracts",
                    "enabled": True, "action": "sanitize",
                    "when": {"has_sensitive": True, "pattern_types": ["pii", "email"]}},
                   {"id": "ask-on-legal-risk", "name": "Ask user on risky contract content",
                    "enabled": True, "action": "ask_user",
                    "when": {"has_sensitive": True, "min_risk_score": 5}}],
        ),
        _preset(
            "enterprise-internal", "Enterprise Internal",
            "Prevent leakage of employee emails, internal domains, and collaboration-tool tokens",
            "🏢", created_at=now,
            detection=_det("api_keys", "private_ips", "pii", "emails",
                           "generic_secrets", "prompt_injection",
                           custom_patterns=[r"xox[baprs]-[A-Za-z0-9-]{10,}",
                                            r"ntn_[A-Za-z0-9]{40,}"]),
            guard=_guard("interactive"),
            file_monitor=_fm(
                watch_home_sensitive=False,
                watch_patterns=["*.docx", "*.pptx", "*.xlsx", "org_chart*",
                                "employee*", "staff*", "internal*"],
                max_file_size_kb=4096,
            ),
            rules=[{"id": "sanitize-internal-ids", "name": "Sanitize internal identifiers",
                    "enabled": True, "action": "sanitize",
                    "when": {"has_sensitive": True,
                             "pattern_types": ["email", "pii", "private_ip"]}},
                   {"id": "block-internal-tokens", "name": "Block internal tool tokens",
                    "enabled": True, "action": "block",
                    "when": {"has_sensitive": True,
                             "pattern_types": ["api_key", "generic_secret"]}}],
        ),
        _preset(
            "gdpr-compliance", "GDPR Compliance",
            "Strict EU GDPR enforcement — blocks PII exposure, consent-form data, and data-subject records",
            "🇪🇺", created_at=now,
            detection=_det("passwords", "private_ips", "pii", "credit_cards",
                           "emails", "prompt_injection",
                           custom_patterns=[r"\b[A-Z]{2}\d{8,12}\b",
                                            r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"]),
            guard=_guard("strict", auto_sanitize=False),
            file_monitor=_fm(
                watch_home_sensitive=False,
                watch_patterns=["consent*.pdf", "dpa*.pdf", "gdpr*", "erasure*",
                                "data_subject*", "*.csv", "user_export*", "*.ofx"],
                max_file_size_kb=4096,
            ),
            rules=[{"id": "block-gdpr-pii", "name": "Block GDPR PII exposure",
                    "enabled": True, "action": "block",
                    "when": {"has_sensitive": True,
                             "pattern_types": ["pii", "email", "credit_card"]}},
                   {"id": "block-gdpr-high-risk", "name": "Block high-risk GDPR data",
                    "enabled": True, "action": "block",
                    "when": {"has_sensitive": True,
                             "threat_levels": ["high", "critical"]}}],
        ),
        _preset(
            "hr-recruiting", "HR & Recruiting",
            "Protect personal data in resumes, interview notes, offer letters, and candidate records",
            "👔", created_at=now,
            detection=_det("pii", "emails", "prompt_injection"),
            guard=_guard("interactive"),
            file_monitor=_fm(
                watch_home_sensitive=False,
                watch_patterns=["resume*.pdf", "cv*.pdf", "*.docx", "candidate*",
                                "applicant*", "interview*.pdf", "offer*.pdf", "hr_*"],
                max_file_size_kb=4096,
            ),
            rules=[{"id": "sanitize-candidate-pii", "name": "Sanitize candidate PII",
                    "enabled": True, "action": "sanitize",
                    "when": {"has_sensitive": True,
                             "pattern_types": ["pii", "email", "phone_cn"]}},
                   {"id": "ask-on-candidate-risk", "name": "Ask on high-risk candidate data",
                    "enabled": True, "action": "ask_user",
                    "when": {"has_sensitive": True, "min_risk_score": 5}}],
        ),
    ]

