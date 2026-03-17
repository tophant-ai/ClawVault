# OpenClaw 集成指南

> [English](../OPENCLAW_INTEGRATION.md)

本指南说明如何将 ClawVault 与 [OpenClaw](https://github.com/tophant-ai/openclaw) 对接，使 OpenClaw 的所有 AI API 流量自动被拦截和保护。

## 工作原理

```
OpenClaw IDE  →  HTTP_PROXY  →  ClawVault 代理 (:8765)  →  AI 提供商 API
                                      │
                                 检测引擎
                                 （敏感数据、注入攻击、危险命令）
                                      │
                                 仪表盘 (:8766)
```

ClawVault 作为透明 HTTP 代理运行。通过为 OpenClaw 设置 `HTTP_PROXY` / `HTTPS_PROXY` 环境变量，所有出站 AI API 请求都会经过 ClawVault 进行检测。

## 前置要求

- ClawVault 已安装并正常运行（[生产部署](./INSTALL_PRODUCTION.md) 或 [开发环境](./INSTALL_DEV.md)）
- OpenClaw 已安装在同一台服务器上

## 自动配置

`setup.sh` 脚本会自动完成所有配置：

```bash
cd ~/prj/clawvault
source venv/bin/activate
./scripts/setup.sh
```

该脚本会：
1. 验证 ClawVault 已安装
2. 将代理环境变量注入 `openclaw-gateway.service`（systemd）
3. 初始化 ClawVault 配置，设置 `ssl_verify: false`

## 启动

```bash
# 启动 ClawVault，自动重启 openclaw-gateway 并配置代理
./scripts/start.sh

# 或同时启动 ClawVault + OpenClaw TUI
./scripts/start.sh --with-openclaw
```

## 手动配置

如果不使用 systemd 或需要手动配置：

### 1. 启动 ClawVault

```bash
cd ~/prj/clawvault
source venv/bin/activate
clawvault start --dashboard-host 0.0.0.0
```

### 2. 设置代理环境变量

在启动 OpenClaw 之前设置：

```bash
export HTTP_PROXY=http://127.0.0.1:8765
export HTTPS_PROXY=http://127.0.0.1:8765
export NO_PROXY=localhost,127.0.0.1
export NODE_TLS_REJECT_UNAUTHORIZED=0
```

### 3. 启动 OpenClaw

```bash
openclaw
```

此后 OpenClaw 的所有 AI API 调用都会经过 ClawVault。

## 验证集成

1. 打开 ClawVault 仪表盘：`http://<服务器IP>:8766`
2. 使用 OpenClaw 向 AI 提供商发送一条消息
3. 查看 **Events** 标签页 — 应能看到被拦截的请求
4. 尝试发送包含测试密钥的消息（如 `sk-proj-test123`），观察检测结果

## OpenClaw 推荐安全模式

| 环境 | 安全模式 | 自动脱敏 | 说明 |
|------|---------|---------|------|
| 开发 | `permissive` | 关 | 仅记录日志，不干预 |
| 预发布 | `interactive` | 开 | 自动脱敏敏感信息，对用户透明 |
| 生产 | `strict` | — | 拦截所有威胁 |

通过仪表盘 Config 页面或 API 切换：

```bash
curl -X POST http://localhost:8766/api/config/guard \
  -H 'Content-Type: application/json' \
  -d '{"mode": "interactive", "auto_sanitize": true}'
```

## 支持的 AI 提供商

默认拦截以下域名（可在 `config.yaml` 中配置）：

- `api.openai.com`
- `api.anthropic.com`
- `api.siliconflow.cn`
- `*.openai.azure.com`
- `generativelanguage.googleapis.com`

添加更多域名，编辑 `~/.ClawVault/config.yaml`：

```yaml
proxy:
  intercept_hosts:
    - "api.openai.com"
    - "api.anthropic.com"
    - "your-custom-endpoint.com"
```

## 故障排查

**OpenClaw 没有使用代理**：确保在 OpenClaw 启动前设置了代理环境变量。对于 systemd 服务，运行 `./scripts/setup.sh` 注入变量。

**SSL/TLS 错误**：在配置中设置 `ssl_verify: false`，并在 OpenClaw 环境中设置 `NODE_TLS_REJECT_UNAUTHORIZED=0`。

**代理不可达**：确认 ClawVault 正在运行：
```bash
curl -s http://127.0.0.1:8766/api/health
```

**配置变更后重启 OpenClaw**：
```bash
systemctl --user restart openclaw-gateway
```
