# ClawVault 安全模式说明

> [English](../GUARD_MODE.md)

ClawVault 提供三种安全模式，可在仪表盘 Config 页面（`:8766`）实时切换，切换后立即生效。

## 模式说明

### Strict（严格模式）

**所有威胁全部拦截** — 敏感数据、注入攻击、危险命令。

- 返回 HTTP 403，仅包含安全摘要，不回显敏感值
- 响应格式兼容 OpenAI error（TUI 客户端可直接显示）
- 推荐用于安全要求最高的生产环境

### Interactive（交互模式）

**智能处理** — 脱敏敏感数据、拦截注入、警告危险命令。

- `auto_sanitize=true`：敏感数据自动替换为占位符（如 `[API_KEY_1]`），响应时还原
- `auto_sanitize=false`：返回安全提醒（伪 LLM 响应），提示用户修改后重发
- 提示词注入：始终拦截
- 危险命令：返回警告提醒

### Permissive（宽松模式）

**全部放行，仅记录日志。** 可选开启自动脱敏。

- 不拦截任何内容
- 所有检测结果记录到仪表盘 Events 中
- 推荐用于开发和测试环境

## 行为对比

| 威胁类型 | Strict | Interactive (自动脱敏) | Interactive (不脱敏) | Permissive |
| -------- | ------ | ---------------------- | -------------------- | ---------- |
| 敏感数据 | 拦截   | 自动脱敏               | 安全提醒             | 放行+日志  |
| 注入攻击 | 拦截   | 拦截                   | 拦截                 | 放行+日志  |
| 危险命令 | 拦截   | 警告                   | 警告                 | 放行+日志  |

## 响应格式

### Strict 拦截 (HTTP 403)

```json
{
	"error": {
		"message": "[ClawVault] Strict mode: threat blocked\n\nSensitive data detected:\n  • AWS Access Key ID",
		"type": "claw_vault_block",
		"code": "content_blocked"
	}
}
```

### Interactive 警告 (HTTP 200，伪 LLM 响应)

```json
{
	"id": "claw-vault-xxxx",
	"object": "chat.completion",
	"choices": [
		{
			"message": {
				"role": "assistant",
				"content": "⚠️ [ClawVault Security Alert]\n\nSensitive data detected — enable auto-sanitize for masking\n\nSensitive data detected:\n  • AWS Access Key ID\n\nPlease modify your message and resend, or contact an administrator to adjust the security policy."
			}
		}
	]
}
```

## 会话连续性

当某条消息被拦截后，后续请求会自动移除该消息及对应的 ClawVault 错误响应，保证会话可以继续进行。

## 配置方式

### 仪表盘 UI

访问 `http://<server-ip>:8766` → **Config** 标签页 → 选择 Guard Mode 和 Auto-Sanitize 开关。

### 配置文件

编辑 `~/.ClawVault/config.yaml`：

```yaml
guard:
  mode: strict # strict | interactive | permissive
  auto_sanitize: true
```

### REST API

```bash
# 查看当前模式
curl http://localhost:8766/api/config/guard

# 切换模式
curl -X POST http://localhost:8766/api/config/guard \
  -H 'Content-Type: application/json' \
  -d '{"mode": "interactive", "auto_sanitize": true}'
```

## Events 页面

- 所有代理事件（拦截、脱敏、放行）显示在 Events 标签页
- 每个事件包含：消息摘要、检测详情（已脱敏）、风险等级
- 支持按 Agent 名称筛选
- 测试页面产生的扫描不会出现在 Events 中
