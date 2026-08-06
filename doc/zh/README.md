# ClawVault 文档

> [English](../README.md)

## 快速上手

| 文档 | 说明 |
|------|------|
| [INSTALL_DEV.md](./INSTALL_DEV.md) | 开发环境搭建 |
| [INSTALL_PRODUCTION.md](./INSTALL_PRODUCTION.md) | 生产环境部署 |
| [OPENCLAW_INTEGRATION.md](./OPENCLAW_INTEGRATION.md) | OpenClaw 集成指南 |
| [OPENCLAW_SKILL.md](./OPENCLAW_SKILL.md) | OpenClaw Skill 完整指南 |

## 参考文档

| 文档 | 说明 |
|------|------|
| [architecture.md](./architecture.md) | 系统架构与模块设计 |
| [scenarios.md](./scenarios.md) | 使用场景与路线图 |
| [GUARD_MODE.md](./GUARD_MODE.md) | 安全模式：strict / interactive / permissive |

## 生成式规则文档

| 文档 | 说明 |
|------|------|
| [GENERATIVE_RULES.md](./GENERATIVE_RULES.md) | 生成式规则引擎完整指南（中文） |
| [GENERATIVE_RULES_QUICKSTART.md](./GENERATIVE_RULES_QUICKSTART.md) | 生成式规则 5 分钟快速上手 |
| [TEST_CASES_RULES.md](./TEST_CASES_RULES.md) | 自定义规则与测试用例清单 |

## 脚本

| 脚本 | 说明 |
|------|------|
| `scripts/deploy.sh <ip> [user]` | 部署到云服务器 |
| `scripts/start.sh` | 启动 ClawVault（加 `--with-openclaw` 同时启动 OpenClaw） |
| `scripts/stop.sh` | 停止所有服务 |
| `scripts/test.sh` | 运行 CLI + API 测试 |
| `scripts/setup.sh` | 配置 OpenClaw 代理集成 |
| `scripts/setup-claude-code.sh` | 配置 Claude Code 用户输入和工具调用 hooks（默认 dry-run） |
| `scripts/uninstall.sh` | 卸载并恢复 |
