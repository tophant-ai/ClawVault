# ClawVault

**[English](./README.md)** | **[中文](./README.zh-CN.md)**

> OpenClaw 安全保险箱 — 原子级"钳"控，让 AI 的每次伸手都在你的视线之内。

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## 什么是 ClawVault？

ClawVault 是一个面向 OpenClaw 的 Agent 运行时的开源安全保险箱。  
核心目标是为 Agent、模型调用与文件资产等提供**可视化监控、原子化控制与生成式策略**三层治理能力。

### 核心能力

#### 1. 可视化监控能力
用户可以配置自己的"保险箱"，将关心的 Agent、Skill、凭证与文件资源"关进保险箱"。  
一旦有人触碰这些资产，"保安龙虾"会通过 IM 告诉你：昨天谁动了你的保险箱里的东西。

**技术实现**：
- 基于 API 网关与文件侧监测，采集 Agent 的关键行为事件（调用记录、文件访问、变更轨迹）
- 支持周期性变更通知与实时告警

#### 2. 原子化控制能力

精细化到 Agent 级别的控制，以可组合的"原子能力"作为最小单元，覆盖：
- Agent 交互与调用策略
- 模型路由、白名单与配额控制
- 安全检测项（敏感信息识别、凭证检测、提示注入防护等）
- 文件访问权限约束

用户可以像"搭积木"一样，按场景组合这些原子能力，形成可复用的策略配置。

#### 3. 生成式能力
保险箱里的每个"储藏阁"，除了内置基础安全场景，还允许用户通过自然语言调动原子能力来添加检测场景、添加 Skill 等。

**示例**：  
通过聊天界面告诉系统：
```
对于客服 Agent，如果用户上传了包含'合同'字样的 PDF，
必须先经过敏感信息脱敏，且只允许使用 GPT-4o-mini 调用，
单次消耗不能超过 2000 tokens。
```
系统会自动生成对应的策略规则并执行。

---

### 功能

- **敏感数据检测** — API 密钥、密码、PII、信用卡等 15+ 种模式
- **提示词注入防御** — 拦截角色劫持、指令覆盖、数据窃取
- **危险命令拦截** — 拦截 `rm -rf`、`curl|bash`、权限提升
- **自动脱敏** — 将敏感信息替换为占位符，响应时自动还原
- **Token 预算控制** — 日/月限额与费用告警
- **实时仪表盘** — Web UI，支持 Agent 配置、检测详情、快速测试

保险箱内置 **透明代理网关模块**，用于拦截 AI 工具与外部 API（OpenAI、Anthropic 等）之间的流量。

## 快速开始

```bash
# 安装
pip install -e .

# 启动（代理 + 仪表盘）
claw-vault start

# 扫描文本
claw-vault scan "password=MySecret key=sk-proj-abc123"

# 交互式演示
claw-vault demo
```

## 部署到服务器

```bash
# 一键打包、上传、安装
./scripts/deploy.sh <服务器IP> root

# 在服务器上：配置集成 + 启动
./scripts/setup.sh
./scripts/start.sh
```

## 脚本

| 脚本 | 用途 |
|------|------|
| `scripts/deploy.sh <ip> [user]` | 部署到云服务器 |
| `scripts/start.sh` | 启动 ClawVault（加 `--with-openclaw` 同时启动 OpenClaw） |
| `scripts/stop.sh` | 停止所有服务 |
| `scripts/test.sh` | 运行 CLI + API 测试 |
| `scripts/setup.sh` | 配置 OpenClaw 代理集成 |
| `scripts/uninstall.sh` | 卸载并恢复原始状态 |

## 架构

```
    OpenClaw
       │
       ▼
┌─────────────────────────────────┐
│    ClawVault（安全保险箱）       │
├─────────────────────────────────┤
│ 网关模块                         │
│  • 透明代理  :8765               │
│  • 流量拦截                      │
├─────────────────────────────────┤
│ 检测引擎                         │
│  • 敏感数据                      │
│  • 注入攻击模式                  │
│  • 危险命令                      │
├─────────────────────────────────┤
│ 防护 / 脱敏器                    │
│  • 放行 / 拦截 / 脱敏            │
├─────────────────────────────────┤
│ 审计 + 监控                      │
│  • SQLite 存储                   │
│  • Token 预算追踪                │
├─────────────────────────────────┤
│ 仪表盘                           │
│  • Web UI :8766                 │
│  • Agent 配置与测试              │
└─────────────────────────────────┘
```

## 配置

```yaml
# ~/.claw-vault/config.yaml
proxy:
  port: 8765
  intercept_hosts: ["api.openai.com", "api.anthropic.com"]

guard:
  mode: "interactive"  # interactive | strict | permissive

monitor:
  daily_token_budget: 50000
```




## 文档

| 文档 | 说明 |
|------|------|
| [开发环境搭建](doc/zh/INSTALL_DEV.md) | 本地开发环境 |
| [生产部署](doc/zh/INSTALL_PRODUCTION.md) | 服务器部署 |
| [OpenClaw 集成](doc/zh/OPENCLAW_INTEGRATION.md) | 对接 OpenClaw |
| [系统架构](doc/zh/architecture.md) | 架构设计与模块说明 |
| [安全模式](doc/zh/GUARD_MODE.md) | strict / interactive / permissive |
| [使用场景](doc/zh/scenarios.md) | 应用场景与路线图 |

完整文档索引见 [doc/zh/](doc/zh/)。

## 开发

```bash
git clone https://github.com/tophant-ai/ClawVault.git
cd ClawVault
python3 -m venv venv && source venv/bin/activate
pip install -e ".[dev]"
pytest
```

### 开发进度

| 能力模块 | 状态 | 说明 |
|---------|------|------|
| API 网关监测与拦截 | ✅ 已实现 | 第一版核心能力 |
| 文件侧监测 | 🚧 开发中 | 逐步接入 |
| Agent 级原子化控制 | 🚧 开发中 | 网关侧已可用，其他场景扩展中 |
| 生成式策略编排 | 🚧 开发中 | 逐步接入 |

---


## 许可证

MIT
