<div align="center">
  <img src="./doc/images/logo1.png" alt="ClawVault Logo" width="200"/>
  
  <p><strong>OpenClaw 安全保险箱 — 原子级"钳"控，让 AI 的每次伸手都在你的视线之内。</strong></p>
  <p>
    <a href="https://github.com/tophant-ai/ClawVault/blob/master/LICENSE">
      <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License"/>
    </a>
    <a href="https://www.python.org/downloads/">
      <img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python 3.10+"/>
    </a>
    <a href="https://github.com/tophant-ai/ClawVault/stargazers">
      <img src="https://img.shields.io/github/stars/tophant-ai/ClawVault?style=social" alt="Stars"/>
    </a>
  </p>
</div>

**[English](./README.md)** | **[中文](./README.zh-CN.md)**

<div align="center">
  <img src="./doc/images/cartoon_zh-cn.png" alt="ClawVault 漫画" width="800"/>
</div>

## 🎯 ClawVault 适合你，如果你

- ✅ 你担心与AI Agent对话时，泄露个人私密数据
- ✅ 你想严防AI Agent窃取API密钥、隐私文件和凭证
- ✅ 你需要阻止AI Agent误处理涉密私密文件
- ✅ 你需要记录AI对隐私文件和敏感数据的访问日志
- ✅ 你需要检测AI注入攻击和危险命令

你现在可以开启个人AI保险箱
- 1️⃣装入隐私文件
- 2️⃣自主配置储藏室
- 3️⃣编写远程管理Skill

https://github.com/user-attachments/assets/361db35e-d85c-493b-a3b2-517164659a01

## 🖼️ 效果展示

<div align="center">
  
| 交互拦截效果 | 拦截记录 |
|:------------:|:------------:|
| <img src="doc/images/block-tui.png" width="400"> | <img src="doc/images/block-web.png" width="400"> |

</div>

https://github.com/user-attachments/assets/d580cfa1-8410-4095-90cb-3d693413a24e

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

#### 3. 交互式策略配置
用户可以通过直观的 Web 界面定义和修改安全策略。系统提供预置的安全模板，并允许自定义检测规则和代理权限。

**示例**：
使用仪表盘配置客服代理安全：
1. 选择代理：`customer-service`
2. 启用文档上传的 PII 检测
3. 限制模型访问仅允许 `GPT-4o-mini`
4. 设置 token 限制：`每次请求 2000`
5. 保存并立即应用策略

所有更改通过代理网关立即生效。

---

## ✨ 功能特性

- **🔍 敏感数据检测** — API 密钥、密码、PII、信用卡等 15+ 种模式
- **🛡️ 提示词注入防御** — 拦截角色劫持、指令覆盖、数据窃取
- **⚠️ 危险命令拦截** — 拦截 `rm -rf`、`curl|bash`、权限提升
- **🔄 自动脱敏** — 将敏感信息替换为占位符，响应时自动还原
- **💰 Token 预算控制** — 日/月限额与费用告警
- **📊 实时仪表盘** — Web UI，支持审计日志、Protection Monitor、Agent 配置与快速测试
- **🤖 Agent 集成** — OpenClaw 会话/运行时防护，以及 Claude Code prompt/tool hooks

ClawVault 结合 **透明代理网关**、本地 Agent hooks 和仪表盘监控，用于保护 AI provider 流量、OpenClaw 会话，以及 Claude Code 的用户输入和工具调用。

## 🚀 快速开始

https://github.com/user-attachments/assets/1f424172-8833-4ccc-b0d2-abf67c1758dd

### 方式 1：作为 OpenClaw Skill 安装（推荐）

```bash
# 从 ClawHub 安装专用安装器
openclaw skills install tophant-clawvault-installer --version=0.2.9 --force

# 或使用 clawhub CLI 安装
clawhub install tophant-clawvault-installer --version 0.2.9
```

**ClawHub 地址:** https://clawhub.ai/Martin2877/tophant-clawvault-installer

安装器 Skill 提供 AI 引导的安装和管理：
- `/tophant-clawvault-installer install --mode quick` - 快速安装
- `/tophant-clawvault-installer health` - 检查状态
- `/tophant-clawvault-installer generate-rule "拦截 AWS 凭证"` - 创建安全规则
- `/tophant-clawvault-installer test --category all` - 运行检测测试

详见 [skills/tophant-clawvault-installer/](skills/tophant-clawvault-installer/) 查看 Skill 文档。

安装后的运行期操作由 [skills/tophant-clawvault-operator/](skills/tophant-clawvault-operator/) 提供。

### 方式 2：作为 Python 包安装

```bash
# 安装
pip install -e .

# 启动（代理 + 仪表盘）
clawvault start

# 扫描文本
clawvault scan "password=[PASSWORD_EXAMPLE] key=[SYNTHETIC_API_KEY]"

# 交互式演示
clawvault demo
```

## 🚀 部署到服务器

```bash
# 一键打包、上传、安装
./scripts/deploy.sh <服务器IP> root

# 在服务器上：配置集成 + 启动
./scripts/setup.sh
./scripts/start.sh
```

## 📜 脚本

| 脚本 | 用途 |
|------|------|
| `scripts/deploy.sh <ip> [user]` | 部署到云服务器 |
| `scripts/start.sh` | 启动 ClawVault（加 `--with-openclaw` 同时启动 OpenClaw） |
| `scripts/stop.sh` | 停止所有服务 |
| `scripts/test.sh` | 运行 CLI + API 测试 |
| `scripts/setup.sh` | 配置 OpenClaw 代理集成 |
| `scripts/setup-claude-code.sh` | 配置 Claude Code 用户输入和工具调用 hooks（默认 dry-run） |
| `scripts/uninstall.sh` | 卸载并恢复原始状态 |

## 🏗️ 架构

```
    OpenClaw
       │
       ▼
┌─────────────────────────────────┐
│    ClawVault（安全保险箱）        │
├─────────────────────────────────┤
│ 网关模块                         │
│  • 透明代理  :8765               │
│  • 流量拦截                      │
├─────────────────────────────────┤
│ 检测引擎                         │
│  • 敏感数据                      │
│  • 注入攻击模式                   │
│  • 危险命令                      │
├─────────────────────────────────┤
│ 防护 / 脱敏器                     │
│  • 放行 / 拦截 / 脱敏             │
├─────────────────────────────────┤
│ 审计 + 监控                      │
│  • SQLite 存储                  │
│  • Token 预算追踪                │
├─────────────────────────────────┤
│ 仪表盘                           │
│  • Web UI :8766                 │
│  • Agent 配置与测试              │
└─────────────────────────────────┘
```

## ⚙️ 配置

```yaml
# ~/.ClawVault/config.yaml
proxy:
  port: 8765
  intercept_hosts: ["api.openai.com", "api.anthropic.com"]

guard:
  mode: "interactive"  # interactive | strict | permissive

monitor:
  daily_token_budget: 50000
```

### Claude Code Hooks

ClawVault 可以在 Claude Code 的用户输入和工具执行两个阶段提供保护：

- `UserPromptSubmit`：在用户 prompt 发送给模型前进行检测。
- `PreToolUse`：在 Claude Code 工具调用执行前进行检测。

两类 hooks 复用 ClawVault/OpenClaw 同一套 detector、RuleEngine、guard mode、audit store 和仪表盘展示语义。

先预览，不修改 Claude Code 设置：

```bash
./scripts/setup-claude-code.sh --dry-run
```

审核后安装：

```bash
./scripts/setup-claude-code.sh --yes
```

安装器会安全合并 `~/.claude/settings.json`：保留已有 hooks、MCP servers、permissions、model、status line 和 OpenClaw 配置；写入前会创建备份，重复执行保持幂等，并且卸载时只移除 ClawVault hooks：

```bash
clawvault claude-code status
clawvault claude-code uninstall --yes
```

安装 Claude Code hooks 后需要保持 ClawVault 运行；如果本地 guard API 不可用，hooks 会 fail closed。

手工验证：

- 安全 prompt：应放行。
- 合成 API key prompt：应在发送给模型前阻断。
- 危险命令 prompt：按当前 guard mode 阻断或进入确认。
- `pwd` 这类安全工具调用：应放行并记录审计。
- Dashboard Audit Log 和 Protection Monitor 应显示对应事件。

## 📚 文档

| 文档 | 说明 |
|------|------|
| [开发环境搭建](doc/zh/INSTALL_DEV.md) | 本地开发环境 |
| [生产部署](doc/zh/INSTALL_PRODUCTION.md) | 服务器部署 |
| [OpenClaw 集成](doc/zh/OPENCLAW_INTEGRATION.md) | 对接 OpenClaw |
| [系统架构](doc/zh/architecture.md) | 架构设计与模块说明 |
| [安全模式](doc/zh/GUARD_MODE.md) | strict / interactive / permissive |
| [使用场景](doc/zh/scenarios.md) | 应用场景与路线图 |

完整文档索引见 [doc/zh/](doc/zh/)。

## 🛠️ 开发

```bash
git clone https://github.com/tophant-ai/ClawVault.git
cd ClawVault
python3 -m venv venv && source venv/bin/activate
pip install -e ".[dev]"
pytest
```

## 📊 开发进度

| 能力模块 | 状态 | 说明 |
|---------|------|------|
| API 网关监测与拦截 | ✅ 已实现 | 第一版核心能力 |
| 文件侧监测 | 🚧 开发中 | 逐步接入 |
| Agent 级原子化控制 | 🚧 开发中 | 网关侧已可用，其他场景扩展中 |
| 生成式策略编排 | 🚧 开发中 | 逐步接入 |

---


## 📄 许可证

MIT © 2026 [Tophant](https://www.tophant.com/) SPAI Lab

---

## 🤝 社区
**社区加入方式：**
- Discord：加入我们的 Discord 进行实时交流与协作：https://discord.gg/P4pQCQgZ
- 微信：扫描下方二维码，发送关键词 clawvault 即可入群。
<img width="1440" height="2988" alt="微信图片_20260518115512_35_192" src="https://github.com/user-attachments/assets/217329b1-537a-4a1f-8717-baaa2554ad92" />

- [GitHub Issues](https://github.com/tophant-ai/ClawVault/issues) — 错误报告和功能请求
- [安全问题](https://github.com/tophant-ai/ClawVault/security/advisories) — 安全漏洞报告

🌟 给我们点个 Star 吧！这能帮助项目被更多人发现，也激励我们打造更棒的开源工具！

---

<div align="center">
  <p><strong>🦞 为想要保护 AI 安全，而非看管代理的人而构建。</strong></p>
  <p><a href="#top">返回顶部 ↑</a></p>
</div>
