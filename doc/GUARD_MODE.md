# ClawVault Guard Modes

> [中文版](./zh/GUARD_MODE.md)

ClawVault provides three guard modes. Switch them in real-time via the Dashboard Config tab (`:8766`) — changes take effect immediately.

## Modes

### Strict

**Block all detected threats** — sensitive data, injection attacks, dangerous commands.

- Returns HTTP 403 with safe detection summaries only
- OpenAI-compatible error format (works with TUI clients)
- Recommended for production environments with high security requirements

### Interactive

**Smart handling** — sanitize sensitive data, block injections, warn on dangerous commands.

- `auto_sanitize=true`: Sensitive data auto-replaced with placeholders (e.g. `[API_KEY_1]`), restored in response
- `auto_sanitize=false`: Returns a safety reminder (pseudo LLM response) asking user to revise
- Prompt injection: always blocked
- Dangerous commands: warning reminder

### Permissive

**Pass-through with logging only.** Optionally auto-sanitize if enabled.

- No blocking
- All detections logged to Dashboard Events
- Recommended for development and testing

## Behavior Matrix

| Threat Type       | Strict | Interactive (auto_sanitize) | Interactive (no sanitize) | Permissive |
| ----------------- | ------ | --------------------------- | ------------------------- | ---------- |
| Sensitive data    | Block  | Auto-sanitize               | Safety reminder           | Pass + log |
| Injection attack  | Block  | Block                       | Block                     | Pass + log |
| Dangerous command | Block  | Warning                     | Warning                   | Pass + log |

## Response Formats

### Strict Block (HTTP 403)

```json
{
	"error": {
		"message": "[ClawVault] Strict mode: threat blocked\n\nSensitive data detected:\n  • AWS Access Key ID",
		"type": "claw_vault_block",
		"code": "content_blocked"
	}
}
```

### Interactive Warning (HTTP 200, pseudo LLM response)

```json
{
  "id": "clawvault-xxxx",
  "object": "chat.completion",
  "choices": [{
    "message": {
      "role": "assistant",
      "content": "[ClawVault] Sensitive data detected:\n  - AWS Access Key ID: AKIA***MPLE\n\nPlease revise your message and resend."
    }
  }]
}
```

## Session Continuity

When a message is blocked, subsequent requests automatically strip the blocked message and its ClawVault error response, so the conversation can continue without interference.

## Configuration

### Dashboard UI

Visit `http://<server-ip>:8766` → **Config** tab → select Guard Mode and Auto-Sanitize toggle.

### Config File

Edit `~/.ClawVault/config.yaml`:

```yaml
guard:
  mode: strict # strict | interactive | permissive
  auto_sanitize: true
```

### REST API

```bash
# Get current mode
curl http://localhost:8766/api/config/guard

# Switch mode
curl -X POST http://localhost:8766/api/config/guard \
  -H 'Content-Type: application/json' \
  -d '{"mode": "interactive", "auto_sanitize": true}'
```

## Events Page

- All proxy events (blocked, sanitized, passed) appear in the Events tab
- Each event includes: message excerpt, detection details (masked), risk level
- Filter by agent name
- Test-tab scans are excluded from Events
