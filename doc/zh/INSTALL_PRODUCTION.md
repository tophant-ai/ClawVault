# 生产环境部署

> [English](../INSTALL_PRODUCTION.md)

## 前置要求

- Linux 服务器（Debian/Ubuntu 或 CentOS/RHEL）
- Python 3.10+
- SSH 访问权限（root 或 sudo）

## 一键部署

在你的**本地机器**（源码所在的机器）上执行：

```bash
./scripts/deploy.sh <服务器IP> [用户名]
# 示例：./scripts/deploy.sh 123.45.67.89 root
```

该脚本会：
1. 打包项目（排除 `__pycache__`、`.pyc`）
2. 通过 SCP 上传到服务器
3. 在服务器上创建 Python 虚拟环境
4. 在虚拟环境中安装 ClawVault

## 首次配置（在服务器上）

```bash
ssh root@<服务器IP>
cd ~/prj/clawvault
source venv/bin/activate

# 初始化配置（创建 ~/.ClawVault/config.yaml）
clawvault config init
```

### 推荐的生产配置

编辑 `~/.ClawVault/config.yaml`：

```yaml
proxy:
  port: 8765
  ssl_verify: false        # 如有正规 CA 证书可设为 true

guard:
  mode: "interactive"      # 或 "strict" 以获得最高安全防护
  auto_sanitize: true

monitor:
  daily_token_budget: 100000
  monthly_token_budget: 3000000
  cost_alert_usd: 100.0

dashboard:
  enabled: true
  host: "127.0.0.1"        # 绑定本地；通过 SSH 隧道远程访问
  port: 8766
```

## 启动 / 停止

```bash
./scripts/start.sh         # 后台启动 ClawVault
./scripts/stop.sh          # 停止所有服务
```

启动后的服务：
- **代理**: `http://127.0.0.1:8765`
- **仪表盘**: `http://127.0.0.1:8766`
- **日志**: `/tmp/clawvault.log`

## 远程访问仪表盘

仪表盘默认绑定 `127.0.0.1`（安全考虑）。使用 SSH 隧道远程访问：

```bash
# 在本地机器上执行
ssh -L 8766:localhost:8766 root@<服务器IP>
# 然后访问 http://localhost:8766
```

## 更新代码

```bash
# 在本地机器上：重新部署
./scripts/deploy.sh <服务器IP> root

# 在服务器上：重启
./scripts/stop.sh && ./scripts/start.sh
```

## 验证

```bash
./scripts/test.sh          # 运行 CLI + API 测试
```

或通过仪表盘 Web UI 测试：打开 **Test** 标签页，运行任意测试用例。

## 卸载

```bash
./scripts/uninstall.sh               # 完全清理
./scripts/uninstall.sh --keep-config  # 保留配置文件
```

## 脚本参考

| 脚本 | 说明 |
|------|------|
| `scripts/deploy.sh <ip> [user]` | 打包、上传、安装到服务器 |
| `scripts/start.sh` | 启动 ClawVault（加 `--with-openclaw` 同时启动 OpenClaw） |
| `scripts/stop.sh` | 停止所有服务 |
| `scripts/test.sh` | 运行 CLI + API 测试 |
| `scripts/setup.sh` | 配置 OpenClaw 代理集成 |
| `scripts/uninstall.sh` | 卸载并恢复 |

## 故障排查

**pip install 失败（代理冲突）**：
```bash
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy
pip install -e .
```

**HTTPS/SSL 错误**：在 `~/.ClawVault/config.yaml` 中设置 `ssl_verify: false`。

**仪表盘无法远程访问**：使用 SSH 隧道（见上方说明）。

**查看日志**：
```bash
tail -f /tmp/clawvault.log
```
