# ClawVault 快速入门

**[English](./QUICKSTART.md)** | **[中文](./QUICKSTART.zh-CN.md)**

## 1. 部署到服务器

```bash
# 在本地机器上 — 一键打包、上传、安装
./scripts/deploy.sh <服务器IP> root
```

## 2. 首次配置（在服务器上）

```bash
ssh root@<服务器IP>
cd ~/prj/clawvault
source venv/bin/activate

# 配置 OpenClaw 代理集成
./scripts/setup.sh
```

## 3. 启动

```bash
./scripts/start.sh                  # 仅启动 ClawVault
./scripts/start.sh --with-openclaw  # 启动 ClawVault + OpenClaw
```

服务：
- **代理**: `http://127.0.0.1:8765`
- **仪表盘**: `http://<服务器IP>:8766`
- **日志**: `/tmp/clawvault.log`

## 4. 测试

```bash
./scripts/test.sh
```

或在仪表盘 Web UI 中测试：进入 **Test** 标签页，点击任意测试用例。

## 5. 停止

```bash
./scripts/stop.sh
```

## 6. 更新代码

```bash
# 在本地机器上
./scripts/deploy.sh <服务器IP> root

# 在服务器上：重启
./scripts/stop.sh && ./scripts/start.sh
```

## 7. 卸载

```bash
./scripts/uninstall.sh              # 完全清理
./scripts/uninstall.sh --keep-config # 保留配置文件
```

---

## CLI 命令

```bash
clawvault --version          # 版本
clawvault start              # 启动代理 + 仪表盘
clawvault scan "text"        # 扫描文本中的威胁
clawvault demo               # 交互式演示
clawvault config show        # 显示配置
clawvault skill list         # 列出 Skill
```

## 故障排查

**pip install 失败（代理冲突）**：
```bash
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy
pip install -e .
```

**HTTPS/SSL 错误**：在 `~/.ClawVault/config.yaml` 中设置 `ssl_verify: false`

**OpenClaw 没有使用代理**：设置环境变量后重启 OpenClaw：
```bash
source ~/.openclaw/.env && openclaw
```

**仪表盘无法远程访问**：使用 SSH 隧道：
```bash
ssh -L 8766:localhost:8766 root@<服务器IP>
# 然后访问 http://localhost:8766
```

---

**最后更新**: 2026-03-09
