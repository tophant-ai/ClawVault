# OpenClaw Integration Guide

> [中文版](./zh/OPENCLAW_INTEGRATION.md)

This guide explains how to connect ClawVault with [OpenClaw](https://github.com/tophant-ai/openclaw) so that all AI API traffic from OpenClaw is automatically intercepted and protected.

## How It Works

```
OpenClaw IDE  →  HTTP_PROXY  →  ClawVault Proxy (:8765)  →  AI Provider APIs
                                      │
                                 Detection Engine
                                 (sensitive data, injection, commands)
                                      │
                                 Dashboard (:8766)
```

ClawVault runs as a transparent HTTP proxy. By setting `HTTP_PROXY` / `HTTPS_PROXY` environment variables for OpenClaw, all outgoing AI API requests pass through ClawVault for inspection.

## Prerequisites

- ClawVault installed and working ([Production](./INSTALL_PRODUCTION.md) or [Development](./INSTALL_DEV.md))
- OpenClaw installed on the same server

## Automatic Setup

The `setup.sh` script configures everything automatically:

```bash
cd ~/prj/clawvault
source venv/bin/activate
./scripts/setup.sh
```

This script will:

1. Verify ClawVault is installed
2. Inject proxy environment variables into `openclaw-gateway.service` (systemd)
3. Initialize ClawVault config with `ssl_verify: false`

## Start with OpenClaw

```bash
# Start ClawVault, then auto-restart openclaw-gateway with proxy configured
./scripts/start.sh

# Or start ClawVault + launch OpenClaw TUI together
./scripts/start.sh --with-openclaw
```

## Manual Setup

If you prefer manual configuration or don't use systemd:

### 1. Start ClawVault

```bash
cd ~/prj/clawvault
source venv/bin/activate
clawvault start --dashboard-host 0.0.0.0
```

### 2. Set Proxy Environment Variables

Before starting OpenClaw, set these environment variables:

```bash
export HTTP_PROXY=http://127.0.0.1:8765
export HTTPS_PROXY=http://127.0.0.1:8765
export NO_PROXY=localhost,127.0.0.1
export NODE_TLS_REJECT_UNAUTHORIZED=0
```

### 3. Start OpenClaw

```bash
openclaw
```

All AI API calls from OpenClaw will now pass through ClawVault.

## Verify Integration

1. Open the ClawVault Dashboard: `http://<server-ip>:8766`
2. Use OpenClaw to send a message to an AI provider
3. Check the **Events** tab — you should see the intercepted request
4. Try sending a message containing a test secret (e.g. `sk-proj-test123`) and observe the detection

## Guard Mode for OpenClaw

Recommended modes:

| Environment | Guard Mode    | Auto-Sanitize | Notes                               |
| ----------- | ------------- | ------------- | ----------------------------------- |
| Development | `permissive`  | off           | Log only, no interference           |
| Staging     | `interactive` | on            | Auto-sanitize secrets transparently |
| Production  | `strict`      | —             | Block all threats                   |

Switch via Dashboard Config tab or API:

```bash
curl -X POST http://localhost:8766/api/config/guard \
  -H 'Content-Type: application/json' \
  -d '{"mode": "interactive", "auto_sanitize": true}'
```

## Supported AI Providers

ClawVault intercepts traffic to these hosts by default (configurable in `config.yaml`):

- `api.openai.com`
- `api.anthropic.com`
- `api.siliconflow.cn`
- `*.openai.azure.com`
- `generativelanguage.googleapis.com`

Add more hosts in `~/.ClawVault/config.yaml`:

```yaml
proxy:
  intercept_hosts:
    - "api.openai.com"
    - "api.anthropic.com"
    - "your-custom-endpoint.com"
```

## Troubleshooting

**OpenClaw not using proxy**: Ensure proxy env vars are set before OpenClaw starts. For systemd services, run `./scripts/setup.sh` to inject them.

**SSL/TLS errors**: Set `ssl_verify: false` in config and `NODE_TLS_REJECT_UNAUTHORIZED=0` in the OpenClaw environment.

**Proxy not reachable**: Confirm ClawVault is running:

```bash
curl -s http://127.0.0.1:8766/api/health
```

The health payload now includes `openclaw_session_redaction.enabled`,
`openclaw_session_redaction.running`, `openclaw_session_redaction.watch_roots`,
and `openclaw_session_redaction.last_watch_error`.
`enabled` and `running` must both be `true` if transcript cleanup is expected to work.
`watch_roots` must include the actual OpenClaw transcript root, especially when OpenClaw is
running under `/root` or another home directory.

**Restart OpenClaw after config changes**:

```bash
systemctl --user restart openclaw-gateway
```

## Generative Rules for OpenClaw

ClawVault provides a powerful generative rule engine that allows you to create custom security policies using natural language. This is particularly useful for OpenClaw deployments where you need to enforce specific security requirements.

### Quick Start

**1. Generate a rule via API:**

```bash
curl -X POST http://localhost:8766/api/rules/generate \
  -H 'Content-Type: application/json' \
  -d '{
    "policy": "Block all requests containing OpenAI API keys with risk score above 8.0"
  }'
```

**2. Apply the generated rule:**

The API returns a complete rule definition. Save it to your rules file or apply via the dashboard.

### Common OpenClaw Use Cases

#### Use Case 1: Protect API Keys in Development

**Policy:** "Auto-sanitize all API keys and tokens in development environment"

**Generated Rule:**

```yaml
- id: dev-sanitize-api-keys
  name: Development API Key Sanitization
  description: Automatically masks all API keys and tokens in development
  enabled: true
  action: sanitize
  when:
    has_sensitive: true
    pattern_types:
      - openai_api_key
      - anthropic_api_key
      - github_token
      - generic_secret
  source: user
```

**Integration:**

```bash
# Generate and apply
curl -X POST http://localhost:8766/api/rules/generate \
  -H 'Content-Type: application/json' \
  -d '{"policy": "Auto-sanitize all API keys and tokens in development environment"}' \
  | jq '.rules' > /tmp/new_rule.json

# Add to existing rules
curl -X GET http://localhost:8766/api/config/rules > /tmp/current_rules.yaml
# Merge and upload back
curl -X POST http://localhost:8766/api/config/rules \
  -H 'Content-Type: application/json' \
  -d @merged_rules.json
```

#### Use Case 2: Block Prompt Injection Attacks

**Policy:** "Block all prompt injection and jailbreak attempts"

**Generated Rule:**

```yaml
- id: block-injection-attacks
  name: Block All Injection Attempts
  description: Prevents prompt injection and jailbreak attacks
  enabled: true
  action: block
  when:
    has_injections: true
  source: user
```

#### Use Case 3: Tiered Security for Production

**Policy:** "For production environment, block high-risk content (score >= 8.0), sanitize medium-risk (score 5.0-7.9), and allow low-risk"

**Generated Rules:**

```yaml
- id: prod-block-high-risk
  name: Production Block High Risk
  description: Blocks all content with risk score >= 8.0
  enabled: true
  action: block
  when:
    min_risk_score: 8.0
  source: user

- id: prod-sanitize-medium-risk
  name: Production Sanitize Medium Risk
  description: Auto-masks content with risk score 5.0-7.9
  enabled: true
  action: sanitize
  when:
    has_sensitive: true
    min_risk_score: 5.0
  source: user
```

### OpenClaw Skill Integration

You can create a ClawVault Skill for OpenClaw that allows generating rules directly from the IDE:

**Example Skill: `generate-security-rule.py`**

```python
#!/usr/bin/env python3
"""
ClawVault Rule Generator Skill for OpenClaw
Usage: Generate security rules from natural language
"""

import requests
import sys

def generate_rule(policy: str, claw_vault_url: str = "http://localhost:8766"):
    """Generate a security rule from natural language policy."""

    response = requests.post(
        f"{claw_vault_url}/api/rules/generate",
        json={
            "policy": policy,
            "model": "gpt-4o-mini",
            "temperature": 0.1
        }
    )

    if response.status_code == 200:
        result = response.json()
        if result["success"]:
            print("✓ Rule generated successfully!\n")
            print("Explanation:")
            print(result["explanation"])
            print("\nGenerated YAML:")
            import yaml
            print(yaml.dump(result["rules"], sort_keys=False))

            if result["warnings"]:
                print("\n⚠ Warnings:")
                for warning in result["warnings"]:
                    print(f"  - {warning}")

            return result["rules"]
        else:
            print(f"✗ Failed to generate rule: {result.get('error')}")
            return None
    else:
        print(f"✗ API request failed: {response.status_code}")
        return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: generate-security-rule.py '<policy description>'")
        print("Example: generate-security-rule.py 'Block all AWS credentials'")
        sys.exit(1)

    policy = " ".join(sys.argv[1:])
    generate_rule(policy)
```

**Usage in OpenClaw:**

```bash
# From OpenClaw terminal
openclaw skill run generate-security-rule "Block all requests with AWS credentials"
```

### API Reference for OpenClaw Integration

#### Generate Rule

```http
POST /api/rules/generate
Content-Type: application/json

{
  "policy": "Your security policy in natural language",
  "model": "gpt-4o-mini",
  "temperature": 0.1,
  "multiple": false
}
```

**Response:**

```json
{
  "success": true,
  "rules": [{ "id": "...", "name": "...", ... }],
  "warnings": [],
  "explanation": "Human-readable explanation"
}
```

#### Validate Rule

```http
POST /api/rules/validate
Content-Type: application/json

{
  "rule": {
    "id": "my-rule",
    "name": "My Rule",
    "action": "block",
    "when": { "has_injections": true }
  }
}
```

#### Get Current Rules

```http
GET /api/config/rules
```

Returns YAML string of current rules.

#### Update Rules

```http
POST /api/config/rules
Content-Type: application/json

{
  "rules": [
    { "id": "rule-1", ... },
    { "id": "rule-2", ... }
  ]
}
```

### Best Practices for OpenClaw

1. **Start with Permissive Mode**: Test rules in `permissive` mode first to see what would be detected without blocking
2. **Use Specific Patterns**: Instead of broad rules, target specific pattern types for better accuracy
3. **Layer Your Rules**: Use multiple rules with different risk thresholds for tiered security
4. **Monitor Dashboard**: Regularly check the Events tab to see what's being detected
5. **Test Before Deploy**: Use the Quick Test feature to validate rules before enabling them

### Environment-Specific Configurations

**Development:**

```bash
# Generate permissive rules for development
curl -X POST http://localhost:8766/api/rules/generate \
  -d '{"policy": "In development, log all detections but allow everything except prompt injections"}'
```

**Staging:**

```bash
# Generate interactive rules for staging
curl -X POST http://localhost:8766/api/rules/generate \
  -d '{"policy": "In staging, auto-sanitize sensitive data and block injections"}'
```

**Production:**

```bash
# Generate strict rules for production
curl -X POST http://localhost:8766/api/rules/generate \
  -d '{"policy": "In production, block all threats with risk score above 7.0"}'
```

### Troubleshooting

**Rule not generating:**

- Ensure `OPENAI_API_KEY` is set in ClawVault environment
- Check ClawVault logs: `journalctl --user -u clawvault -f`

**Rule not taking effect:**

- Verify rule is enabled: `enabled: true`
- Check rule order in `~/.ClawVault/rules.yaml`
- Restart ClawVault: `systemctl --user restart clawvault`

**False positives:**

- Adjust `min_risk_score` threshold
- Use more specific `pattern_types`
- Review detection patterns in Dashboard

For more details, see [Generative Rules Documentation](./zh/GENERATIVE_RULES.md).
