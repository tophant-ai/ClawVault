# ClawVault 技术架构

> [English](../architecture.md)

## 系统总览

```
┌─────────────────────────────────────────────────────────────────┐
│                     AI 工具 / OpenClaw IDE                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │
│  │ 用户对话  │  │  Skills  │  │   文件   │  │  AI 提供商   │   │
│  └─────┬─────┘  └────┬─────┘  └────┬─────┘  └──────┬───────┘   │
└────────┼──────────────┼──────────────┼───────────────┼───────────┘
         │              │              │               │
    ┌────▼──────────────▼──────────────▼───────────────▼────┐
    │              ClawVault 透明代理                        │
    │  ┌─────────────────────────────────────────────────┐   │
    │  │              拦截管线                             │   │
    │  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌───────┐ │   │
    │  │  │敏感数据  │ │危险命令  │ │提示词   │ │Token  │ │   │
    │  │  │检测器    │ │守卫     │ │注入检测  │ │计数器  │ │   │
    │  │  └────┬─────┘ └────┬────┘ └────┬────┘ └───┬───┘ │   │
    │  │       └────────────┴───────────┴──────────┘     │   │
    │  │                    │                             │   │
    │  │            ┌───────▼────────┐                    │   │
    │  │            │   规则引擎     │                    │   │
    │  │            │ (放行/拦截/    │                    │   │
    │  │            │  脱敏/询问)    │                    │   │
    │  │            └───────┬────────┘                    │   │
    │  └────────────────────┼─────────────────────────────┘   │
    │                       │                                  │
    │  ┌────────────────────▼─────────────────────────────┐   │
    │  │              响应管线                              │   │
    │  │  ┌──────────┐  ┌───────────┐  ┌──────────────┐  │   │
    │  │  │ 还原     │  │ 响应扫描  │  │  审计日志    │  │   │
    │  │  │(反脱敏)  │  │           │  │              │  │   │
    │  │  └──────────┘  └───────────┘  └──────────────┘  │   │
    │  └──────────────────────────────────────────────────┘   │
    └──────────┬──────────────┬───────────────┬───────────────┘
               │              │               │
    ┌──────────▼──┐  ┌───────▼───────┐  ┌───▼────────────┐
    │  保险箱     │  │  审计存储     │  │  仪表盘        │
    │  (加密存储) │  │  (SQLite)     │  │  (FastAPI +    │
    │             │  │               │  │   Web UI)      │
    └─────────────┘  └───────────────┘  └────────────────┘
```

## 模块结构

```
clawvault/
├── src/claw_vault/
│   ├── __init__.py           # 版本信息
│   ├── __main__.py           # 入口：python -m claw_vault
│   ├── cli.py                # Typer CLI 命令
│   ├── config.py             # Pydantic 配置模型
│   │
│   ├── proxy/                # 透明代理层
│   │   ├── server.py         # mitmproxy 生命周期管理
│   │   └── interceptor.py    # 请求/响应拦截逻辑
│   │
│   ├── detector/             # 检测引擎
│   │   ├── engine.py         # 检测调度器
│   │   ├── sensitive.py      # 敏感信息检测（正则+规则）
│   │   ├── command.py        # 危险命令检测
│   │   ├── injection.py      # 提示词注入检测
│   │   └── patterns.py       # 检测模式定义
│   │
│   ├── sanitizer/            # 脱敏与还原
│   │   ├── replacer.py       # 将敏感数据替换为占位符
│   │   └── restorer.py       # 在响应中还原占位符
│   │
│   ├── guard/                # 拦截与决策
│   │   ├── rule_engine.py    # 本地规则引擎
│   │   └── action.py         # 动作：放行/拦截/脱敏/询问
│   │
│   ├── vault/                # 保险箱（文件与凭证管理）
│   │   ├── file_manager.py   # 敏感文件发现与管理
│   │   └── crypto.py         # 加解密工具
│   │
│   ├── monitor/              # 监控与统计
│   │   ├── token_counter.py  # Token 计数与费用追踪
│   │   └── budget.py         # 预算管控
│   │
│   ├── audit/                # 审计日志
│   │   ├── store.py          # SQLite 审计存储
│   │   └── models.py         # 数据模型
│   │
│   ├── skills/               # Skill 层（OpenClaw 集成）
│   │   ├── base.py           # BaseSkill、@tool 装饰器、SkillContext
│   │   ├── registry.py       # Skill 注册中心
│   │   ├── sanitize_restore.py   # 脱敏与还原 Skill
│   │   ├── prompt_firewall.py    # 提示词注入防火墙 Skill
│   │   ├── security_scan.py      # 安全扫描 Skill
│   │   ├── vault_guard.py        # 文件守护 Skill
│   │   ├── security_report.py    # 安全报告 Skill
│   │   └── skill_audit.py        # Skill 审计 Skill
│   │
│   └── dashboard/            # Web 仪表盘
│       ├── app.py            # FastAPI 应用
│       ├── api.py            # REST API 端点
│       └── static/
│           └── index.html    # 单页仪表盘 UI
│
├── tests/                    # 测试套件
├── scripts/                  # 部署与运维脚本
├── pyproject.toml            # 项目配置与依赖
├── config.example.yaml       # 配置模板
└── README.md
```

## 核心数据流

### 请求拦截流程

```
用户输入 → 代理拦截 → 检测管线 → 决策 → 动作
                          │
              ┌───────────┼───────────┐
              ▼           ▼           ▼
         敏感数据？   危险命令？   注入攻击？
              │           │           │
              ▼           ▼           ▼
          风险评分     风险评分     风险评分
              │           │           │
              └─────┬─────┘───────────┘
                    ▼
               规则引擎
              ┌─────┼─────┐
              ▼     ▼     ▼
            放行   拦截   询问
              │     │     │
              ▼     ▼     ▼
            转发   丢弃   提示
              │           │
              └─────┬─────┘
                    ▼
               审计日志
```

### 脱敏还原流程

```
请求：  "密码是 MyP@ss" → 检测 → 替换 → "密码是 [CRED_1]" → AI
响应：  "检查 [CRED_1]..." → 还原 → "检查 MyP@ss..." → 用户

本地映射（内存中，会话级别）：
{ "[CRED_1]": "MyP@ss", "[IP_1]": "192.168.1.1" }
会话结束自动清除。
```

## 关键接口

### 检测引擎

```python
class DetectionResult:
    pattern_type: str        # "api_key", "password", "ip_private" 等
    value: str               # 匹配到的原始值
    position: tuple[int,int] # 文本中的 (起始, 结束) 位置
    risk_score: float        # 0.0 - 10.0
    confidence: float        # 0.0 - 1.0

class Detector(Protocol):
    def detect(self, text: str) -> list[DetectionResult]: ...
```

### 规则引擎

```python
class Action(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    SANITIZE = "sanitize"
    ASK_USER = "ask_user"

class RuleEngine:
    def evaluate(self, detections: list[DetectionResult]) -> Action: ...
```

### 审计记录

```python
class AuditRecord:
    id: int
    timestamp: datetime
    session_id: str
    direction: str          # "request" | "response"
    api_endpoint: str
    token_count: int
    cost_usd: float
    detections: list[str]   # 检测到的模式类型列表
    risk_level: str         # "low" | "medium" | "high" | "critical"
    action_taken: str       # "allow" | "block" | "sanitize"
    skill_name: str | None
```

## 配置

完整模板见 [`config.example.yaml`](../../config.example.yaml)。主要配置项：

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

## 性能目标

| 指标 | 目标 | 实现方式 |
|------|------|---------|
| 代理延迟 | < 50ms (p95) | 异步 I/O，并行检测 |
| 拦截决策 | < 200ms | 本地规则引擎优先 |
| 内存占用 | < 100MB | SQLite + 流式处理 |
| CPU（空闲） | < 5% | 事件驱动，无轮询 |
| CPU（活跃） | < 15% | 预编译正则 |

## 安全原则

1. **最小权限** — 代理仅拦截配置的目标域名
2. **本地优先** — 所有检测在本地完成，云端功能可选
3. **加密存储** — 凭证使用 AES-256 加密
4. **无遥测** — 不主动发送数据，除非用户明确开启云端功能
5. **可审计** — 核心安全逻辑紧凑，易于审查
