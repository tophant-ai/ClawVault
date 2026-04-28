# ClawVault OpenClaw Skill 指南

> [English](../OPENCLAW_SKILL.md)

在 OpenClaw 中安装、配置和使用 ClawVault skill 的完整指南。

## 概述

ClawVault skill 使得可以直接从 OpenClaw 中通过 AI 引导来安装、配置和管理 ClawVault 安全系统。它提供完整的工具套件来保护 AI 代理免受提示词注入、数据泄露和危险命令的威胁。

**核心功能：**
- **AI 引导安装** - 多模式设置，智能默认配置
- **规则生成** - 从自然语言创建安全规则
- **场景模板** - 常见用例的预配置策略
- **健康监控** - 实时服务状态和诊断
- **检测测试** - 内置测试套件用于验证
- **生命周期管理** - 完整的安装/配置/卸载工作流

## 安装方法

### 方法 1: 作为 OpenClaw Skill 安装（推荐）

将 skill 复制到 OpenClaw skills 目录：

**方式 1：从 ClawHub 安装（推荐）**

```bash
# 从 ClawHub 安装专用安装器
openclaw skills install tophant-clawvault-installer --version=0.2.9 --force

# 或使用 clawhub CLI
clawhub install tophant-clawvault-installer --version 0.2.9
```

**ClawHub 地址:** https://clawhub.ai/Martin2877/tophant-clawvault-installer

**方式 2：从本地仓库安装**

```bash
# 复制 skill 目录
cp -r skills/tophant-clawvault-installer ~/.openclaw/skills/

# 或创建符号链接（推荐用于开发）
ln -s /path/to/ClawVault/skills/tophant-clawvault-installer ~/.openclaw/skills/tophant-clawvault-installer
```

重启 OpenClaw 以加载 skill：

```bash
openclaw restart
```

验证 skill 已加载：

```bash
openclaw skills list
# 应显示：tophant-clawvault-installer
```

### 方法 2: 作为内置 Skill 使用

如果已安装 ClawVault，skill 会自动可用：

```python
from claw_vault.skills.registry import SkillRegistry

registry = SkillRegistry()
registry.register_builtins()

# clawvault skill 现已可用
result = registry.invoke("clawvault_installer", "check_health")
```

### 方法 3: 独立脚本

无需 OpenClaw 即可下载并使用独立脚本：

```bash
# 下载脚本
curl -O https://raw.githubusercontent.com/tophant-ai/ClawVault/main/skills/tophant-clawvault-installer/clawvault_manager.py

# 直接使用
python clawvault_manager.py install --mode quick
python clawvault_manager.py health
```

## 命令参考

### /clawvault install

通过 AI 引导安装 ClawVault。

**用法：**
```bash
/clawvault install --mode quick
/clawvault install --mode standard
/clawvault install --mode advanced
```

**安装模式：**

- **quick** - 一键安装，使用推荐默认配置
  - 从 PyPI 安装（失败时降级到 GitHub）
  - 创建默认配置
  - 启用所有检测功能
  - 设置交互式防护模式
  
- **standard** - 交互式配置
  - 提示常用设置
  - 允许端口自定义
  - 选择防护模式
  - 选择检测功能
  
- **advanced** - 完全自定义
  - 完全控制所有设置
  - 自定义检测模式
  - 高级代理配置
  - 预算和监控设置

**安装过程：**
1. 检查前置条件（Python 3.10+, pip）
2. 安装 ClawVault 包
3. 创建配置目录（`~/.ClawVault/`）
4. 生成默认 config.yaml
5. 运行健康检查
6. 报告安装状态

### /clawvault start

启动 ClawVault 代理和仪表盘服务。

**用法：**
```bash
# 使用默认设置启动（仅本地访问）
clawvault start

# 启动时允许从任何 IP 访问仪表盘
clawvault start --dashboard-host 0.0.0.0

# 使用自定义端口启动
clawvault start --port 8765 --dashboard-port 8766

# 使用特定防护模式启动
clawvault start --mode strict

# 不启动仪表盘
clawvault start --no-dashboard

# 组合选项
clawvault start --dashboard-host 0.0.0.0 --dashboard-port 8080 --mode interactive
```

**命令行选项：**
- `--port <PORT>` - 代理监听端口（默认：8765）
- `--dashboard-port <PORT>` - 仪表盘 Web UI 端口（默认：8766）
- `--dashboard-host <HOST>` - 仪表盘绑定地址：
  - `127.0.0.1`（默认）- 仅本地访问（安全）
  - `0.0.0.0` - 允许从任何 IP 远程访问
  - 特定 IP - 绑定到特定网络接口
- `--mode <MODE>` - 防护模式：`permissive`、`interactive` 或 `strict`
- `--no-dashboard` - 禁用 Web 仪表盘
- `--config <PATH>` - 自定义 config.yaml 路径

**仪表盘访问：**
- 仅本地：`http://127.0.0.1:8766`（默认，安全）
- 远程访问：`http://0.0.0.0:8766` 或 `http://<服务器IP>:8766`

**安全注意事项：**
- 仅在受信任网络或防火墙后使用 `0.0.0.0`
- 仪表盘显示敏感检测数据
- 生产环境建议使用反向代理配置 HTTPS

### /clawvault health

检查 ClawVault 服务健康状况和配置状态。

**用法：**
```bash
/clawvault health
```

**返回信息：**
- 安装状态（已安装/未安装）
- 版本信息
- 服务运行状态（代理、仪表盘）
- 配置有效性
- 端口可用性（8765、8766）
- 整体健康状态

### /clawvault generate-rule

从自然语言生成安全规则或应用预配置场景。

**用法：**
```bash
/clawvault generate-rule "拦截所有 AWS 凭证和 API 密钥"
/clawvault generate-rule --scenario customer_service --apply
/clawvault generate-rule --scenario development
```

**可用场景：**
- `customer_service` - PII 检测 + 客服支持的自动脱敏
- `development` - API 密钥保护 + 危险命令检测
- `production` - 严格模式，拦截高风险内容
- `finance` - 金融合规 + 全面 PII 检测

**选项：**
- `--apply` - 自动将生成的规则应用到 ClawVault
- `--scenario <name>` - 使用预配置的安全场景

**自然语言示例：**
```bash
# 检测特定威胁
/clawvault generate-rule "检测并拦截所有数据库密码"

# 多条件规则
/clawvault generate-rule "拦截风险评分超过 8.0 的 AWS 凭证"

# 合规导向
/clawvault generate-rule "检测所有 PII 以符合 GDPR 合规"
```

### /clawvault status

获取当前 ClawVault 运行状态和统计信息。

**用法：**
```bash
/clawvault status
```

**返回信息：**
- 服务运行时间
- 检测统计（总请求数、已拦截、已脱敏）
- 活动规则数量
- 仪表盘 URL
- Token 使用量和成本

### /clawvault test

运行内置检测测试以验证 ClawVault 能力。

**用法：**
```bash
/clawvault test --category all
/clawvault test --category sensitive
/clawvault test --category injection
/clawvault test --category commands
```

**测试类别：**
- `all` - 运行所有检测测试
- `sensitive` - 测试 PII 和凭证检测
- `injection` - 测试提示词注入检测
- `commands` - 测试危险命令检测

**测试覆盖：**
- 敏感数据：API 密钥、信用卡、邮箱、电话号码
- 注入攻击：提示词注入、角色劫持、越狱尝试
- 危险命令：rm -rf、curl|bash、系统漏洞利用

### /clawvault uninstall

从系统中移除 ClawVault。

**用法：**
```bash
/clawvault uninstall
/clawvault uninstall --keep-config
```

**选项：**
- `--keep-config` - 保留配置文件以便将来重新安装

**将被移除的内容：**
- ClawVault Python 包
- 服务文件（如果使用 systemd）
- 可选：配置目录（`~/.ClawVault/`）

## 配置

### 配置文件

创建 `~/.ClawVault/config.yaml` 用于持久化设置：

```yaml
# 代理配置
proxy:
  host: "127.0.0.1"
  port: 8765

# 仪表盘配置
dashboard:
  enabled: true
  host: "0.0.0.0"  # 允许远程访问
  port: 8766

# 防护模式
guard:
  mode: "interactive"  # permissive | interactive | strict

# 检测设置
detection:
  check_sensitive: true
  check_injection: true
  check_commands: true
  
# 审计设置
audit:
  enabled: true
  store_path: "~/.ClawVault/audit.db"
```

加载自定义配置：
```bash
clawvault start --config /path/to/config.yaml
```

### 环境变量

```bash
# OpenAI API 密钥（用于规则生成）
export OPENAI_API_KEY="sk-..."

# 自定义配置路径
export CLAWVAULT_CONFIG="~/.ClawVault/config.yaml"

# 日志级别
export CLAWVAULT_LOG_LEVEL="DEBUG"  # DEBUG | INFO | WARNING | ERROR
```

### 防护模式

**宽松模式（Permissive）：**
- 记录所有检测
- 从不拦截请求
- 适合测试和开发

**交互模式（Interactive，推荐）：**
- 拦截前询问用户
- 显示检测详情
- 允许覆盖决策
- 适合有人工监督的生产环境

**严格模式（Strict）：**
- 自动拦截高风险内容
- 无用户交互
- 适合自动化系统

## 安全场景模板

### 客服场景

**用例：** 保护客服对话中的客户 PII

**功能：**
- 检测电话号码、身份证、邮箱、地址
- 自动脱敏敏感数据（替换为 `[已脱敏]`）
- 拦截提示词注入攻击
- 交互模式（拦截前询问）

**应用：**
```bash
/clawvault generate-rule --scenario customer_service --apply
```

**生成的策略：**
```
为客服人员检测并自动脱敏所有 PII 数据，包括电话号码、身份证、
邮箱、地址。拦截提示词注入。使用交互模式。
```

### 开发场景

**用例：** 保护开发环境中的密钥

**功能：**
- 检测 API 密钥、令牌、密码、私钥
- 检测危险 shell 命令
- 自动脱敏密钥
- 宽松模式（仅记录，不拦截）

**应用：**
```bash
/clawvault generate-rule --scenario development --apply
```

**生成的策略：**
```
为开发环境检测 API 密钥、令牌、密码和危险命令。
自动脱敏密钥。允许其他所有内容。
```

### 生产场景

**用例：** 生产系统的严格安全

**功能：**
- 拦截所有高风险内容（评分 >= 7.0）
- 检测所有威胁类型
- 严格模式（立即拦截）
- 不自动脱敏（保留证据）

**应用：**
```bash
/clawvault generate-rule --scenario production --apply
```

**生成的策略：**
```
为生产环境拦截所有风险评分超过 7.0 的威胁。
严格模式。不自动脱敏。
```

### 金融场景

**用例：** 金融合规和数据保护

**功能：**
- 检测信用卡、银行账户、SSN、路由号码
- 检测所有 PII 类型
- 拦截高风险内容
- 严格合规模式

**应用：**
```bash
/clawvault generate-rule --scenario finance --apply
```

**生成的策略：**
```
为金融应用检测信用卡、银行账户、SSN 和所有 PII。
拦截高风险内容。严格合规模式。
```

## 高级配置

### 仪表盘远程访问

**开发/测试环境：**
```bash
# 允许从任何 IP 访问默认端口
clawvault start --dashboard-host 0.0.0.0

# 自定义端口用于远程访问
clawvault start --dashboard-host 0.0.0.0 --dashboard-port 8080

# 从浏览器访问
http://<服务器IP>:8766
```

**防火墙配置：**
```bash
# 允许端口 8766
sudo ufw allow 8766

# 或针对特定 IP 范围
sudo ufw allow from 192.168.1.0/24 to any port 8766
```

**验证监听：**
```bash
netstat -tlnp | grep 8766
# 应显示：0.0.0.0:8766
```

### Docker 部署

**Dockerfile：**
```dockerfile
FROM python:3.10-slim

RUN pip install clawvault

EXPOSE 8765 8766

CMD ["clawvault", "start", "--dashboard-host", "0.0.0.0"]
```

**构建和运行：**
```bash
# 构建镜像
docker build -t clawvault .

# 运行容器
docker run -p 8765:8765 -p 8766:8766 clawvault

# 访问仪表盘
http://localhost:8766
```

### Systemd 服务（Linux）

创建 `/etc/systemd/system/clawvault.service`：

```ini
[Unit]
Description=ClawVault AI Security Service
After=network.target

[Service]
Type=simple
User=clawvault
WorkingDirectory=/opt/clawvault
Environment="OPENAI_API_KEY=sk-..."
ExecStart=/usr/local/bin/clawvault start --dashboard-host 0.0.0.0
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

启用并启动：
```bash
sudo systemctl enable clawvault
sudo systemctl start clawvault
sudo systemctl status clawvault
```

## 故障排除

### 安装问题

**问题：** 安装失败，网络错误

**解决方案：**
1. 检查网络连接
2. 尝试从 GitHub 安装：`pip install git+https://github.com/tophant-ai/ClawVault.git`
3. 使用独立脚本 `--mode quick`

**问题：** Python 版本过旧

**解决方案：**
```bash
# 检查 Python 版本
python3 --version

# 应为 3.10 或更高
# 安装 Python 3.10+ 或使用虚拟环境
python3.10 -m venv venv
source venv/bin/activate
```

### 服务问题

**问题：** 安装后服务未运行

**解决方案：**
```bash
# 手动启动 ClawVault
clawvault start

# 检查状态
clawvault status

# 查看日志
tail -f ~/.ClawVault/logs/clawvault.log
```

**问题：** 端口已被占用

**解决方案：**
```bash
# 查找占用端口的进程
lsof -i :8765
lsof -i :8766

# 终止进程
kill -9 <PID>

# 或使用不同端口
clawvault start --port 8767 --dashboard-port 8768
```

### 仪表盘问题

**问题：** 无法远程访问仪表盘

**解决方案：**
1. **检查绑定地址：**
   ```bash
   clawvault start --dashboard-host 0.0.0.0
   ```

2. **检查防火墙：**
   ```bash
   sudo ufw allow 8766
   ```

3. **验证监听：**
   ```bash
   netstat -tlnp | grep 8766
   # 应显示：0.0.0.0:8766
   ```

### 规则生成问题

**问题：** 规则生成返回错误

**解决方案：**
1. 确保 ClawVault 正在运行：`clawvault status`
2. 检查 `OPENAI_API_KEY` 已设置：`echo $OPENAI_API_KEY`
3. 验证仪表盘可访问：`http://localhost:8766`
4. 检查 API 配额和计费

**问题：** 生成的规则未按预期工作

**解决方案：**
1. 在仪表盘中查看生成的 YAML
2. 使用具体示例测试
3. 调整风险阈值
4. 使用更具体的自然语言描述

### 检测问题

**问题：** 测试意外失败

**解决方案：**
1. 检查 config.yaml 中的检测配置
2. 验证模式已启用
3. 查看检测日志：`~/.ClawVault/logs/detection.log`
4. 运行特定类别测试以隔离问题

**问题：** 误报/漏报

**解决方案：**
1. 调整风险评分阈值
2. 自定义检测模式
3. 使用适合您用例的防护模式
4. 定期审查和更新规则

## 与 OpenClaw 集成

### 自动代理配置

Skill 会自动配置 OpenClaw 使用 ClawVault 代理：

1. 设置环境变量（`HTTP_PROXY`、`HTTPS_PROXY`）
2. 配置 systemd 服务（如果可用）
3. 验证集成成功

### 手动代理设置

如果自动配置不工作：

```bash
# 设置代理环境变量
export HTTP_PROXY=http://127.0.0.1:8765
export HTTPS_PROXY=http://127.0.0.1:8765

# 对于 OpenClaw systemd 服务
sudo systemctl edit openclaw-gateway

# 添加：
[Service]
Environment="HTTP_PROXY=http://127.0.0.1:8765"
Environment="HTTPS_PROXY=http://127.0.0.1:8765"

# 重启 OpenClaw
sudo systemctl restart openclaw-gateway
```

### 验证

检查流量是否通过 ClawVault：

1. 启动 ClawVault：`clawvault start`
2. 打开仪表盘：`http://localhost:8766`
3. 在 OpenClaw 中发起 AI 请求
4. 验证请求出现在仪表盘中

## 最佳实践

### 1. 从快速模式开始

首次使用时，使用快速模式开始：

```bash
/clawvault install --mode quick
```

### 2. 生产前测试

部署到生产环境前始终运行测试：

```bash
/clawvault test --category all
```

### 3. 使用场景模板

利用预定义场景处理常见用例：

```bash
/clawvault generate-rule --scenario customer_service --apply
```

### 4. 定期监控健康状况

定期检查健康状态：

```bash
/clawvault health
```

### 5. 保留配置

卸载时保留配置以便轻松重新安装：

```bash
/clawvault uninstall --keep-config
```

### 6. 查看检测日志

定期查看日志以调优检测：

```bash
tail -f ~/.ClawVault/logs/detection.log
```

### 7. 更新规则

保持安全规则最新：

```bash
# 使用最新模式重新生成规则
/clawvault generate-rule --scenario production --apply
```

## CLI 参考

### 帮助命令

```bash
# 显示主帮助
clawvault --help
clawvault -h

# 显示版本
clawvault --version
clawvault -v

# 显示特定命令帮助
clawvault start --help
clawvault install --help
```

### 常用命令

```bash
# 启动服务
clawvault start
clawvault start --dashboard-host 0.0.0.0 --mode strict

# 检查状态
clawvault status

# 查看日志
clawvault logs
clawvault logs --follow

# 停止服务
clawvault stop

# 重启服务
clawvault restart
```

## 支持

- **文档**: https://github.com/tophant-ai/ClawVault/tree/main/doc
- **问题**: https://github.com/tophant-ai/ClawVault/issues
- **仓库**: https://github.com/tophant-ai/ClawVault

## 许可证

MIT © 2026 Tophant SPAI Lab
