# ClawVault Documentation

> 中文文档索引见 [doc/zh/README.md](./zh/README.md)

## English Documents

### Getting Started

| Document | Description |
|----------|-------------|
| [INSTALL_DEV.md](./INSTALL_DEV.md) | Development environment setup |
| [INSTALL_PRODUCTION.md](./INSTALL_PRODUCTION.md) | Production server deployment |
| [OPENCLAW_INTEGRATION.md](./OPENCLAW_INTEGRATION.md) | OpenClaw integration guide |
| [OPENCLAW_SKILL.md](./OPENCLAW_SKILL.md) | OpenClaw skill complete guide |

### Reference

| Document | Description |
|----------|-------------|
| [architecture.md](./architecture.md) | System architecture and module design |
| [scenarios.md](./scenes.md) | Use cases and roadmap |
| [GUARD_MODE.md](./GUARD_MODE.md) | Guard modes: strict / interactive / permissive |

## Chinese Documents (`doc/zh/`)

All Chinese-only guides now live under `doc/zh/` to keep languages separated.

| File | Description |
|------|-------------|
| [zh/README.md](./zh/README.md) | Chinese documentation index |
| [zh/INSTALL_DEV.md](./zh/INSTALL_DEV.md) | 开发环境搭建 |
| [zh/INSTALL_PRODUCTION.md](./zh/INSTALL_PRODUCTION.md) | 生产环境部署 |
| [zh/OPENCLAW_INTEGRATION.md](./zh/OPENCLAW_INTEGRATION.md) | OpenClaw 集成指南 |
| [zh/GUARD_MODE.md](./zh/GUARD_MODE.md) | Guard 模式说明 |
| [zh/architecture.md](./zh/architecture.md) | 系统架构与模块设计 |
| [zh/scenarios.md](./zh/scenarios.md) | 使用场景与路线图 |
| [zh/GENERATIVE_RULES.md](./zh/GENERATIVE_RULES.md) | 生成式规则引擎详解 |
| [zh/GENERATIVE_RULES_QUICKSTART.md](./zh/GENERATIVE_RULES_QUICKSTART.md) | 生成式规则快速开始 |
| [zh/TEST_CASES_RULES.md](./zh/TEST_CASES_RULES.md) | 自定义规则与测试用例清单 |

## Scripts

| Script | Description |
|--------|-------------|
| `scripts/deploy.sh <ip> [user]` | Deploy to cloud server |
| `scripts/start.sh` | Start ClawVault (add `--with-openclaw` for OpenClaw) |
| `scripts/stop.sh` | Stop all services |
| `scripts/test.sh` | Run CLI + API tests |
| `scripts/setup.sh` | Configure OpenClaw proxy integration |
| `scripts/setup-claude-code.sh` | Configure Claude Code prompt and tool hooks (dry-run by default) |
| `scripts/uninstall.sh` | Uninstall and restore |

