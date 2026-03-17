# ClawVault 安装器 Skill

> [English](../SKILL_CLAWVAULT_INSTALLER.md)

ClawVault 安装器 Skill 使得可以直接从 OpenClaw 中通过 AI 引导来安装、配置和管理 ClawVault 安全系统。

## 概述

此 Skill 提供完整的工具套件用于：
- **安装** ClawVault，采用智能多源策略
- **配置** 安全策略和检测规则
- **生成** 从自然语言创建自定义安全规则
- **测试** 使用内置测试用例检测能力
- **监控** 系统健康状况和统计信息
- **管理** ClawVault 的完整生命周期

## 安装

### 作为内置 Skill（推荐）

安装 ClawVault 后，Skill 会自动可用：

```python
from claw_vault.skills.registry import SkillRegistry

registry = SkillRegistry()
registry.register_builtins()

# clawvault_installer skill 现已可用
```

### 作为独立脚本

下载并使用独立脚本：

```bash
# 下载
curl -O https://raw.githubusercontent.com/tophant-ai/ClawVault/main/scripts/skills/clawvault_manager.py

# 添加执行权限
chmod +x clawvault_manager.py

# 直接使用
python clawvault_manager.py install --mode quick
```

## 在 OpenClaw 中使用

### 快速安装

```
用户：安装 ClawVault
AI：[调用 clawvault_installer__install_clawvault(mode="quick")]
```

AI 将会：
1. 检查前置条件（Python 3.10+, pip）
2. 从 PyPI 安装 ClawVault（失败时降级到 GitHub）
3. 使用默认配置初始化
4. 运行健康检查
5. 报告安装状态

### 带场景的自定义安装

```
用户：为客服场景安装 ClawVault，需要 PII 保护
AI：[调用 clawvault_installer__install_clawvault(mode="standard")]
    [调用 clawvault_installer__generate_rule(scenario="customer_service", apply=true)]
```

### 生成安全规则

```
用户：生成一个检测和拦截数据库密码的规则
AI：[调用 clawvault_installer__generate_rule(
      policy="检测并拦截所有数据库连接字符串和密码",
      apply=true
    )]
```

### 检查健康状态

```
用户：检查 ClawVault 状态
AI：[调用 clawvault_installer__check_health()]
```

返回：
- 安装状态
- 版本信息
- 服务状态（代理、仪表盘）
- 配置状态

### 运行检测测试

```
用户：测试 ClawVault 检测能力
AI：[调用 clawvault_installer__test_detection(category="all")]
```

测试包括：
- 敏感数据检测（API 密钥、信用卡、邮箱）
- 注入攻击检测（提示词注入、角色劫持）
- 危险命令检测（rm -rf、curl|bash）

## 可用工具

### 1. install_clawvault

使用指定模式安装 ClawVault。

**参数：**
- `mode` (string): 安装模式 - `quick`、`standard` 或 `advanced`
- `config` (object, 可选): 配置覆盖

**模式：**
- **quick**: 一键安装，使用推荐默认值
- **standard**: 交互式配置常用选项
- **advanced**: 完全自定义所有设置

**示例：**
```python
result = skill.invoke("install_clawvault", mode="quick")
```

### 2. check_health

检查 ClawVault 健康状态和配置。

**返回：**
- 安装状态
- 版本
- 配置文件状态
- 服务状态（代理、仪表盘）
- 整体健康状态

**示例：**
```python
result = skill.invoke("check_health")
```

### 3. configure

配置 ClawVault 设置。

**参数：**
- `settings` (object): 要应用的配置设置

**示例：**
```python
result = skill.invoke("configure", settings={
    "guard": {"mode": "strict"},
    "detection": {"check_sensitive": True}
})
```

### 4. generate_rule

从自然语言或场景模板生成安全规则。

**参数：**
- `policy` (string, 可选): 自然语言安全策略
- `scenario` (string, 可选): 预定义场景模板
- `apply` (boolean): 自动应用生成的规则

**可用场景：**
- `customer_service`: PII 检测 + 自动脱敏
- `development`: API 密钥保护 + 危险命令
- `production`: 严格模式 + 高风险拦截
- `finance`: 金融数据 + 合规检测

**示例：**
```python
# 从自然语言
result = skill.invoke("generate_rule", 
    policy="拦截所有风险评分高于 8.0 的 AWS 凭证",
    apply=True
)

# 从场景模板
result = skill.invoke("generate_rule",
    scenario="customer_service",
    apply=True
)
```

### 5. test_detection

使用内置测试用例运行检测测试。

**参数：**
- `category` (string): 测试类别 - `all`、`sensitive`、`injection` 或 `commands`

**示例：**
```python
result = skill.invoke("test_detection", category="all")
```

### 6. get_status

获取 ClawVault 运行状态和统计信息。

**返回：**
- 服务状态
- 统计信息（拦截次数、令牌、成本）
- 版本信息

**示例：**
```python
result = skill.invoke("get_status")
```

### 7. uninstall

卸载 ClawVault 并清理配置。

**参数：**
- `keep_config` (boolean): 保留配置文件

**示例：**
```python
result = skill.invoke("uninstall", keep_config=False)
```

## 独立脚本使用

### 安装 ClawVault

```bash
# 快速安装
python clawvault_manager.py install --mode quick

# 标准安装
python clawvault_manager.py install --mode standard

# 输出 JSON
python clawvault_manager.py install --mode quick --json
```

### 检查健康

```bash
python clawvault_manager.py health
```

### 生成安全规则

```bash
# 从自然语言
python clawvault_manager.py generate-rule "拦截所有 AWS 凭证"

# 从场景模板
python clawvault_manager.py generate-rule --scenario customer_service

# 自动应用
python clawvault_manager.py generate-rule "检测 PII 数据" --apply
```

### 获取状态

```bash
python clawvault_manager.py status
```

### 运行测试

```bash
# 所有测试
python clawvault_manager.py test --category all

# 特定类别
python clawvault_manager.py test --category sensitive
```

### 卸载

```bash
# 完全卸载
python clawvault_manager.py uninstall

# 保留配置
python clawvault_manager.py uninstall --keep-config
```

## 安全场景模板

### 客服场景

**用例：** 保护客服对话中的客户 PII

**特性：**
- 检测手机号、身份证号、邮箱
- 自动脱敏敏感数据
- 拦截提示词注入攻击
- 交互模式（拦截前询问）

**策略：**
```
对于客服代理，检测并自动脱敏所有 PII 数据，包括手机号、身份证号、
邮箱。拦截提示词注入。使用交互模式。
```

### 开发场景

**用例：** 保护开发环境中的密钥

**特性：**
- 检测 API 密钥、令牌、密码
- 检测危险 shell 命令
- 自动脱敏密钥
- 宽松模式（仅记录）

**策略：**
```
对于开发环境，检测 API 密钥、令牌、密码和危险命令。
自动脱敏密钥。允许其他所有内容。
```

### 生产场景

**用例：** 生产系统的严格安全

**特性：**
- 拦截所有高风险内容（评分 >= 7.0）
- 检测所有威胁类型
- 严格模式（立即拦截）
- 不自动脱敏

**策略：**
```
对于生产环境，拦截所有风险评分高于 7.0 的威胁。
严格模式。不自动脱敏。
```

### 金融场景

**用例：** 金融合规和数据保护

**特性：**
- 检测信用卡、银行账户、社保号
- 检测所有 PII 类型
- 拦截高风险内容
- 严格合规模式

**策略：**
```
对于金融应用，检测信用卡、银行账户、社保号和所有 PII。
拦截高风险内容。严格合规模式。
```

## 与 OpenClaw 集成

### 自动代理配置

Skill 会自动配置 OpenClaw 使用 ClawVault 代理：

1. 设置环境变量（`HTTP_PROXY`、`HTTPS_PROXY`）
2. 配置 systemd 服务（如果可用）
3. 验证集成成功

### Skill 注册

在 OpenClaw 中注册 Skill：

```python
from claw_vault.skills.clawvault_installer import ClawVaultInstallerSkill
from claw_vault.skills.base import SkillContext

# 创建 skill 实例
ctx = SkillContext()
skill = ClawVaultInstallerSkill(ctx)

# 在 OpenClaw 中注册
# (OpenClaw 特定的注册代码)
```

## 错误处理

Skill 提供全面的错误处理：

### 安装错误

- **Python 版本过旧**：需要 Python 3.10+
- **pip 不可用**：先安装 pip
- **网络问题**：自动降级到 GitHub
- **已安装**：报告当前版本

### 配置错误

- **无效设置**：应用前验证配置
- **文件权限错误**：报告具体文件问题
- **YAML 语法错误**：提供有用的错误消息

### 运行时错误

- **服务未运行**：提供启动说明
- **API 连接失败**：检查网络和服务状态
- **规则生成失败**：报告 OpenAI API 问题

## 最佳实践

### 1. 从快速模式开始

首次使用时，使用快速模式开始：

```python
skill.invoke("install_clawvault", mode="quick")
```

### 2. 生产前测试

部署到生产环境前始终运行测试：

```python
skill.invoke("test_detection", category="all")
```

### 3. 使用场景模板

利用预定义场景处理常见用例：

```python
skill.invoke("generate_rule", scenario="customer_service", apply=True)
```

### 4. 定期监控健康

定期检查健康状态：

```python
skill.invoke("check_health")
```

### 5. 保留配置

卸载时保留配置以便轻松重新安装：

```python
skill.invoke("uninstall", keep_config=True)
```

## 故障排除

### 安装失败

**问题：** 安装因网络错误失败

**解决方案：**
1. 检查互联网连接
2. 尝试 GitHub 安装：`pip install git+https://github.com/tophant-ai/ClawVault.git`
3. 使用独立脚本 `--mode quick`

### 服务未运行

**问题：** 健康检查显示服务已停止

**解决方案：**
```bash
# 启动 ClawVault
clawvault start

# 检查状态
python clawvault_manager.py status
```

### 规则生成失败

**问题：** 规则生成返回错误

**解决方案：**
1. 确保 ClawVault 正在运行
2. 检查 `OPENAI_API_KEY` 已设置
3. 验证仪表盘可访问：`http://localhost:8766`

### 测试失败

**问题：** 检测测试显示意外结果

**解决方案：**
1. 检查检测配置
2. 验证模式已启用
3. 查看检测日志

## 发布到 ClawHub

### 准备包

```bash
# 创建包目录
mkdir clawvault-installer-skill
cd clawvault-installer-skill

# 复制独立脚本
cp scripts/skills/clawvault_manager.py .

# 创建 skill.json
cat > skill.json << EOF
{
  "name": "clawvault-installer",
  "version": "1.0.0",
  "description": "安装和管理 ClawVault 安全系统",
  "author": "SPAI Lab",
  "homepage": "https://github.com/tophant-ai/ClawVault",
  "main": "clawvault_manager.py",
  "permissions": ["execute_command", "write_files", "read_files", "network"],
  "tags": ["security", "installation", "clawvault"]
}
EOF
```

### 发布到 ClawHub

```bash
# 打包 skill
tar -czf clawvault-installer-skill.tar.gz .

# 上传到 ClawHub
clawhub publish clawvault-installer-skill.tar.gz
```

## 示例

### 示例 1：快速设置

```python
# 使用默认值安装
result = skill.invoke("install_clawvault", mode="quick")
print(f"已安装版本：{result.data['version']}")

# 运行健康检查
health = skill.invoke("check_health")
print(f"状态：{health.data['overall_status']}")

# 运行测试
tests = skill.invoke("test_detection", category="all")
print(f"测试通过：{tests.data['summary']['passed']}/{tests.data['summary']['total']}")
```

### 示例 2：自定义配置

```python
# 使用自定义配置安装
result = skill.invoke("install_clawvault", 
    mode="standard",
    config={
        "guard": {"mode": "strict"},
        "monitor": {"daily_token_budget": 100000}
    }
)

# 生成自定义规则
rule = skill.invoke("generate_rule",
    policy="拦截所有包含数据库凭证的请求",
    apply=True
)
print(f"生成了 {len(rule.data['rules'])} 条规则")
```

### 示例 3：基于场景的设置

```python
# 为客服安装
skill.invoke("install_clawvault", mode="quick")

# 应用客服场景
skill.invoke("generate_rule", 
    scenario="customer_service",
    apply=True
)

# 测试 PII 检测
tests = skill.invoke("test_detection", category="sensitive")
print(f"PII 检测：{tests.data['summary']['passed']} 通过")
```

## API 参考

详细的 API 文档请参见 [OpenClaw 集成指南](./OPENCLAW_INTEGRATION.md)。

## 许可证

MIT © 2026 SPAI Lab

## 支持

- [GitHub Issues](https://github.com/tophant-ai/ClawVault/issues)
- [文档](https://github.com/tophant-ai/ClawVault/tree/main/doc)
- [ClawHub](https://clawhub.ai/skills/clawvault-installer)
