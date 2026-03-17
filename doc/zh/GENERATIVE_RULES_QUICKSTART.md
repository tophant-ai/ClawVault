# 生成式规则快速开始指南

## 5分钟快速上手

### 1. 环境准备

```bash
# 设置 OpenAI API Key
export OPENAI_API_KEY="sk-your-api-key"

# 启动 ClawVault
cd /root/prj/clawvault
./scripts/start.sh
```

### 2. 生成第一个规则

**方式一：使用 API**

```bash
curl -X POST http://localhost:8766/api/rules/generate \
  -H 'Content-Type: application/json' \
  -d '{
    "policy": "阻止所有包含 AWS 凭证的请求"
  }'
```

**方式二：使用 OpenClaw Skill**

```bash
cd /root/prj/clawvault/examples
python openclaw-skill-generate-rule.py "阻止所有包含 AWS 凭证的请求"
```

### 3. 应用规则

**自动应用：**
```bash
python openclaw-skill-generate-rule.py "阻止所有包含 AWS 凭证的请求" --apply
```

**手动应用：**
1. 复制生成的 YAML 规则
2. 编辑 `~/.ClawVault/rules.yaml`
3. 粘贴规则并保存
4. 重启 ClawVault

### 4. 验证规则

访问 Dashboard: `http://<server-ip>:8766`

1. 进入 **Configuration** 标签
2. 查看 **Custom Rules** 部分
3. 点击 **Run Test** 测试规则

## 常用场景示例

### 场景 1: 客服 Agent 保护

```bash
python openclaw-skill-generate-rule.py \
  "对于客服场景，自动脱敏中国身份证号、手机号和邮箱地址" \
  --apply
```

**效果：**
- 输入："我的身份证是 110101199001011234"
- 输出："我的身份证是 1101***1234"

### 场景 2: 开发环境安全

```bash
python openclaw-skill-generate-rule.py \
  "在开发环境中，阻止文件删除和系统修改命令" \
  --apply
```

**效果：**
- 阻止 `rm -rf /`
- 阻止 `sudo systemctl stop`

### 场景 3: API 密钥分级

```bash
python openclaw-skill-generate-rule.py \
  "高风险 API 密钥（评分≥8.0）直接阻止，中风险（评分5.0-7.9）自动脱敏" \
  --multiple --apply
```

**效果：**
- OpenAI API Key (风险9.0) → 阻止
- Slack Token (风险7.5) → 脱敏

### 场景 4: Prompt 注入防护

```bash
python openclaw-skill-generate-rule.py \
  "阻止所有 Prompt 注入和越狱尝试" \
  --apply
```

**效果：**
- 阻止 "Ignore all previous instructions..."
- 阻止 "You are now DAN..."

### 场景 5: 金融应用保护

```bash
python openclaw-skill-generate-rule.py \
  "阻止包含信用卡号、以太坊私钥或助记词的请求" \
  --apply
```

**效果：**
- 阻止信用卡号 "4532 1234 5678 9010"
- 阻止私钥 "private_key = 0x4c0883a..."

## 远程部署

### 部署到生产服务器

```bash
# 1. 部署代码
./scripts/deploy.sh <server-ip> root

# 2. SSH 到服务器
ssh root@<server-ip>

# 3. 设置环境变量
echo 'export OPENAI_API_KEY="sk-your-api-key"' >> ~/.bashrc
source ~/.bashrc

# 4. 启动服务
cd /root/prj/clawvault
./scripts/start.sh

# 5. 测试生成规则
curl -X POST http://localhost:8766/api/rules/generate \
  -H 'Content-Type: application/json' \
  -d '{"policy": "阻止所有 AWS 凭证"}'
```

### 从本地生成规则到远程服务器

```bash
# 使用 --url 参数指定远程服务器
python openclaw-skill-generate-rule.py \
  "阻止所有 AWS 凭证" \
  --url http://<server-ip>:8766 \
  --apply
```

## API 快速参考

### 生成规则

```bash
POST /api/rules/generate
{
  "policy": "自然语言策略描述",
  "model": "gpt-4o-mini",
  "temperature": 0.1,
  "multiple": false
}
```

### 验证规则

```bash
POST /api/rules/validate
{
  "rule": {
    "id": "my-rule",
    "name": "My Rule",
    "action": "block",
    "when": {"has_injections": true}
  }
}
```

### 获取当前规则

```bash
GET /api/config/rules
```

### 更新规则

```bash
POST /api/config/rules
{
  "rules": [...]
}
```

## 故障排查

### 问题：规则生成失败

**检查：**
```bash
# 1. 验证 API Key
echo $OPENAI_API_KEY

# 2. 测试 OpenAI 连接
curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer $OPENAI_API_KEY"

# 3. 查看 ClawVault 日志
journalctl --user -u clawvault -f
```

### 问题：规则不生效

**检查：**
```bash
# 1. 查看规则文件
cat ~/.ClawVault/rules.yaml

# 2. 验证规则已启用
# enabled: true

# 3. 重启 ClawVault
systemctl --user restart clawvault
```

### 问题：无法连接到服务器

**检查：**
```bash
# 1. 验证服务运行
curl http://localhost:8766/api/health

# 2. 检查端口
netstat -tlnp | grep 8766

# 3. 查看防火墙
firewall-cmd --list-ports
```

## 下一步

- 📖 阅读完整文档: [GENERATIVE_RULES.md](./GENERATIVE_RULES.md)
- 🔌 OpenClaw 集成: [OPENCLAW_INTEGRATION.md](./OPENCLAW_INTEGRATION.md)
- 🎯 更多示例: [examples/README.md](../examples/README.md)
- 🐛 问题反馈: GitHub Issues

## 技术支持

- 文档: `/root/prj/clawvault/doc/`
- 示例: `/root/prj/clawvault/examples/`
- 日志: `journalctl --user -u clawvault -f`
- Dashboard: `http://<server-ip>:8766`
