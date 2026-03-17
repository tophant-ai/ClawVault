# ClawVault Architecture

> [中文版](./zh/architecture.md)

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     AI Tools / OpenClaw IDE                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │
│  │ User Chat │  │  Skills  │  │  Files   │  │ AI Providers │   │
│  └─────┬─────┘  └────┬─────┘  └────┬─────┘  └──────┬───────┘   │
└────────┼──────────────┼──────────────┼───────────────┼───────────┘
         │              │              │               │
    ┌────▼──────────────▼──────────────▼───────────────▼────┐
    │              ClawVault Transparent Proxy               │
    │  ┌─────────────────────────────────────────────────┐   │
    │  │              Interceptor Pipeline                │   │
    │  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌───────┐ │   │
    │  │  │Sensitive │ │ Command │ │ Prompt  │ │ Token │ │   │
    │  │  │Detector  │ │ Guard   │ │Injection│ │Counter│ │   │
    │  │  └────┬─────┘ └────┬────┘ └────┬────┘ └───┬───┘ │   │
    │  │       └────────────┴───────────┴──────────┘     │   │
    │  │                    │                             │   │
    │  │            ┌───────▼────────┐                    │   │
    │  │            │  Rule Engine   │                    │   │
    │  │            │ (allow/block/  │                    │   │
    │  │            │  sanitize/ask) │                    │   │
    │  │            └───────┬────────┘                    │   │
    │  └────────────────────┼─────────────────────────────┘   │
    │                       │                                  │
    │  ┌────────────────────▼─────────────────────────────┐   │
    │  │              Response Pipeline                    │   │
    │  │  ┌──────────┐  ┌───────────┐  ┌──────────────┐  │   │
    │  │  │ Restore  │  │ Response  │  │ Audit Logger │  │   │
    │  │  │(desanit.)│  │  Scanner  │  │              │  │   │
    │  │  └──────────┘  └───────────┘  └──────────────┘  │   │
    │  └──────────────────────────────────────────────────┘   │
    └──────────┬──────────────┬───────────────┬───────────────┘
               │              │               │
    ┌──────────▼──┐  ┌───────▼───────┐  ┌───▼────────────┐
    │  Vault      │  │  Audit Store  │  │  Dashboard     │
    │  (Encrypted │  │  (SQLite)     │  │  (FastAPI +    │
    │   Storage)  │  │               │  │   Web UI)      │
    └─────────────┘  └───────────────┘  └────────────────┘
```

## Module Structure

```
clawvault/
├── src/claw_vault/
│   ├── __init__.py           # Version info
│   ├── __main__.py           # Entry: python -m claw_vault
│   ├── cli.py                # Typer CLI commands
│   ├── config.py             # Pydantic settings model
│   │
│   ├── proxy/                # Transparent proxy layer
│   │   ├── server.py         # mitmproxy lifecycle management
│   │   └── interceptor.py    # Request/response interception logic
│   │
│   ├── detector/             # Detection engine
│   │   ├── engine.py         # Detection orchestrator
│   │   ├── sensitive.py      # Sensitive data detection (regex + rules)
│   │   ├── command.py        # Dangerous command detection
│   │   ├── injection.py      # Prompt injection detection
│   │   └── patterns.py       # Detection pattern definitions
│   │
│   ├── sanitizer/            # Sanitization & restoration
│   │   ├── replacer.py       # Replace sensitive data with placeholders
│   │   └── restorer.py       # Restore placeholders in responses
│   │
│   ├── guard/                # Interception & decision
│   │   ├── rule_engine.py    # Local rule engine
│   │   └── action.py         # Actions: allow / block / sanitize / ask
│   │
│   ├── vault/                # Vault (file & credential management)
│   │   ├── file_manager.py   # Sensitive file discovery & management
│   │   └── crypto.py         # Encryption utilities
│   │
│   ├── monitor/              # Monitoring & statistics
│   │   ├── token_counter.py  # Token counting & cost tracking
│   │   └── budget.py         # Budget enforcement
│   │
│   ├── audit/                # Audit logging
│   │   ├── store.py          # SQLite-backed audit store
│   │   └── models.py         # Data models
│   │
│   ├── skills/               # Skill layer (OpenClaw integration)
│   │   ├── base.py           # BaseSkill, @tool decorator, SkillContext
│   │   ├── registry.py       # Skill registry
│   │   ├── sanitize_restore.py   # Sanitize & restore skill
│   │   ├── prompt_firewall.py    # Prompt injection firewall skill
│   │   ├── security_scan.py      # Security scanning skill
│   │   ├── vault_guard.py        # File guardian skill
│   │   ├── security_report.py    # Security report skill
│   │   └── skill_audit.py        # Skill audit skill
│   │
│   └── dashboard/            # Web dashboard
│       ├── app.py            # FastAPI application
│       ├── api.py            # REST API endpoints
│       └── static/
│           └── index.html    # Single-page dashboard UI
│
├── tests/                    # Test suite
├── scripts/                  # Deployment & operations scripts
├── pyproject.toml            # Project config & dependencies
├── config.example.yaml       # Configuration template
└── README.md
```

## Core Data Flow

### Request Interception

```
User Input → Proxy Intercept → Detection Pipeline → Decision → Action
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
              Sensitive?      Dangerous CMD?   Injection?
                    │               │               │
                    ▼               ▼               ▼
              Risk Score      Risk Score       Risk Score
                    │               │               │
                    └───────┬───────┘───────────────┘
                            ▼
                      Rule Engine
                    ┌───────┼───────┐
                    ▼       ▼       ▼
                  ALLOW   BLOCK   ASK_USER
                    │       │       │
                    ▼       ▼       ▼
                 Forward  Drop   Prompt
                    │               │
                    └───────┬───────┘
                            ▼
                      Audit Log
```

### Sanitize & Restore Flow

```
Request:  "password is MyP@ss" → detect → replace → "password is [CRED_1]" → AI
Response: "check [CRED_1]..."  → restore → "check MyP@ss..."  → User

Local Mapping (in-memory, session-scoped):
{ "[CRED_1]": "MyP@ss", "[IP_1]": "192.168.1.1" }
Auto-cleared on session end.
```

## Key Interfaces

### Detection Engine

```python
class DetectionResult:
    pattern_type: str        # "api_key", "password", "ip_private", etc.
    value: str               # Matched raw value
    position: tuple[int,int] # (start, end) in text
    risk_score: float        # 0.0 - 10.0
    confidence: float        # 0.0 - 1.0

class Detector(Protocol):
    def detect(self, text: str) -> list[DetectionResult]: ...
```

### Rule Engine

```python
class Action(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    SANITIZE = "sanitize"
    ASK_USER = "ask_user"

class RuleEngine:
    def evaluate(self, detections: list[DetectionResult]) -> Action: ...
```

### Audit Record

```python
class AuditRecord:
    id: int
    timestamp: datetime
    session_id: str
    direction: str          # "request" | "response"
    api_endpoint: str
    token_count: int
    cost_usd: float
    detections: list[str]   # Detected pattern types
    risk_level: str         # "low" | "medium" | "high" | "critical"
    action_taken: str       # "allow" | "block" | "sanitize"
    skill_name: str | None
```

## Configuration

See [`config.example.yaml`](../config.example.yaml) for the full template. Key sections:

```yaml
proxy:
  port: 8765
  intercept_hosts: ["api.openai.com", "api.anthropic.com", ...]

detection:
  enabled: true
  api_keys: true
  passwords: true
  private_ips: true
  pii: true

guard:
  mode: "permissive"      # permissive | interactive | strict
  auto_sanitize: false

monitor:
  daily_token_budget: 50000
  monthly_token_budget: 1000000

dashboard:
  enabled: true
  port: 8766
```

## Performance Targets

| Metric | Target | Approach |
|--------|--------|----------|
| Proxy latency | < 50ms (p95) | Async I/O, parallel detection |
| Blocking decision | < 200ms | Local rule engine first |
| Memory usage | < 100MB | SQLite + streaming |
| CPU (idle) | < 5% | Event-driven, no polling |
| CPU (active) | < 15% | Pre-compiled regex |

## Security Principles

1. **Least privilege** — Proxy only intercepts configured target hosts
2. **Local-first** — All detection runs locally; cloud features are opt-in
3. **Encrypted storage** — Credentials encrypted with AES-256
4. **No telemetry** — No data sent externally unless user explicitly enables cloud
5. **Auditable** — Core security logic is compact and reviewable
