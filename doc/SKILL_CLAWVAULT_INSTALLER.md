# ClawVault Installer Skill

> [中文文档](./zh/SKILL_CLAWVAULT_INSTALLER.md)

The ClawVault Installer Skill enables AI-guided installation, configuration, and management of ClawVault security system directly from OpenClaw.

## Overview

This Skill provides a complete suite of tools for:
- **Installing** ClawVault with intelligent multi-source strategy
- **Configuring** security policies and detection rules
- **Generating** custom security rules from natural language
- **Testing** detection capabilities with built-in test cases
- **Monitoring** system health and statistics
- **Managing** the complete lifecycle of ClawVault

## Installation

### As Built-in Skill (Recommended)

The Skill is automatically available when ClawVault is installed:

```python
from claw_vault.skills.registry import SkillRegistry

registry = SkillRegistry()
registry.register_builtins()

# The clawvault_installer skill is now available
```

### As Standalone Script

Download and use the standalone script:

```bash
# Download
curl -O https://raw.githubusercontent.com/tophant-ai/ClawVault/main/scripts/skills/clawvault_manager.py

# Make executable
chmod +x clawvault_manager.py

# Use directly
python clawvault_manager.py install --mode quick
```

## Usage in OpenClaw

### Quick Installation

```
User: Install ClawVault
AI: [Calls clawvault_installer__install_clawvault(mode="quick")]
```

The AI will:
1. Check prerequisites (Python 3.10+, pip)
2. Install ClawVault from PyPI (or GitHub as fallback)
3. Initialize configuration with defaults
4. Run health check
5. Report installation status

### Custom Installation with Scenario

```
User: Install ClawVault for customer service with PII protection
AI: [Calls clawvault_installer__install_clawvault(mode="standard")]
    [Calls clawvault_installer__generate_rule(scenario="customer_service", apply=true)]
```

### Generate Security Rules

```
User: Generate a rule to detect and block database passwords
AI: [Calls clawvault_installer__generate_rule(
      policy="Detect and block all database connection strings and passwords",
      apply=true
    )]
```

### Check Health Status

```
User: Check ClawVault status
AI: [Calls clawvault_installer__check_health()]
```

Returns:
- Installation status
- Version information
- Service status (proxy, dashboard)
- Configuration status

### Run Detection Tests

```
User: Test ClawVault detection capabilities
AI: [Calls clawvault_installer__test_detection(category="all")]
```

Tests include:
- Sensitive data detection (API keys, credit cards, emails)
- Injection attack detection (prompt injection, role hijacking)
- Dangerous command detection (rm -rf, curl|bash)

## Available Tools

### 1. install_clawvault

Install ClawVault with specified mode.

**Parameters:**
- `mode` (string): Installation mode - `quick`, `standard`, or `advanced`
- `config` (object, optional): Configuration overrides

**Modes:**
- **quick**: One-click install with recommended defaults
- **standard**: Interactive configuration with common options
- **advanced**: Full customization of all settings

**Example:**
```python
result = skill.invoke("install_clawvault", mode="quick")
```

### 2. check_health

Check ClawVault health status and configuration.

**Returns:**
- Installation status
- Version
- Configuration file status
- Service status (proxy, dashboard)
- Overall health status

**Example:**
```python
result = skill.invoke("check_health")
```

### 3. configure

Configure ClawVault settings.

**Parameters:**
- `settings` (object): Configuration settings to apply

**Example:**
```python
result = skill.invoke("configure", settings={
    "guard": {"mode": "strict"},
    "detection": {"check_sensitive": True}
})
```

### 4. generate_rule

Generate security rule from natural language or scenario template.

**Parameters:**
- `policy` (string, optional): Natural language security policy
- `scenario` (string, optional): Pre-defined scenario template
- `apply` (boolean): Automatically apply the generated rule

**Available Scenarios:**
- `customer_service`: PII detection + auto-sanitization
- `development`: API key protection + dangerous commands
- `production`: Strict mode + high-risk blocking
- `finance`: Financial data + compliance detection

**Example:**
```python
# From natural language
result = skill.invoke("generate_rule", 
    policy="Block all AWS credentials with risk score above 8.0",
    apply=True
)

# From scenario template
result = skill.invoke("generate_rule",
    scenario="customer_service",
    apply=True
)
```

### 5. test_detection

Run detection tests with built-in test cases.

**Parameters:**
- `category` (string): Test category - `all`, `sensitive`, `injection`, or `commands`

**Example:**
```python
result = skill.invoke("test_detection", category="all")
```

### 6. get_status

Get ClawVault running status and statistics.

**Returns:**
- Service status
- Statistics (interceptions, tokens, cost)
- Version information

**Example:**
```python
result = skill.invoke("get_status")
```

### 7. uninstall

Uninstall ClawVault and clean up configuration.

**Parameters:**
- `keep_config` (boolean): Keep configuration files

**Example:**
```python
result = skill.invoke("uninstall", keep_config=False)
```

## Standalone Script Usage

### Install ClawVault

```bash
# Quick install
python clawvault_manager.py install --mode quick

# Standard install
python clawvault_manager.py install --mode standard

# Output JSON
python clawvault_manager.py install --mode quick --json
```

### Check Health

```bash
python clawvault_manager.py health
```

### Generate Security Rule

```bash
# From natural language
python clawvault_manager.py generate-rule "Block all AWS credentials"

# From scenario template
python clawvault_manager.py generate-rule --scenario customer_service

# Apply automatically
python clawvault_manager.py generate-rule "Detect PII data" --apply
```

### Get Status

```bash
python clawvault_manager.py status
```

### Run Tests

```bash
# All tests
python clawvault_manager.py test --category all

# Specific category
python clawvault_manager.py test --category sensitive
```

### Uninstall

```bash
# Complete uninstall
python clawvault_manager.py uninstall

# Keep configuration
python clawvault_manager.py uninstall --keep-config
```

## Security Scenario Templates

### Customer Service

**Use Case:** Protect customer PII in support conversations

**Features:**
- Detect phone numbers, ID cards, emails
- Auto-sanitize sensitive data
- Block prompt injection attacks
- Interactive mode (ask before blocking)

**Policy:**
```
For customer service agents, detect and auto-sanitize all PII data 
including phone numbers, ID cards, emails. Block prompt injections. 
Use interactive mode.
```

### Development

**Use Case:** Protect secrets in development environment

**Features:**
- Detect API keys, tokens, passwords
- Detect dangerous shell commands
- Auto-sanitize secrets
- Permissive mode (log only)

**Policy:**
```
For development environment, detect API keys, tokens, passwords, 
and dangerous commands. Auto-sanitize secrets. Allow everything else.
```

### Production

**Use Case:** Strict security for production systems

**Features:**
- Block all high-risk content (score >= 7.0)
- Detect all threat types
- Strict mode (block immediately)
- No auto-sanitization

**Policy:**
```
For production environment, block all threats with risk score above 7.0. 
Strict mode. No auto-sanitization.
```

### Finance

**Use Case:** Financial compliance and data protection

**Features:**
- Detect credit cards, bank accounts, SSN
- Detect all PII types
- Block high-risk content
- Strict compliance mode

**Policy:**
```
For financial applications, detect credit cards, bank accounts, SSN, 
and all PII. Block high-risk content. Strict compliance mode.
```

## Integration with OpenClaw

### Automatic Proxy Configuration

The Skill automatically configures OpenClaw to use ClawVault proxy:

1. Sets environment variables (`HTTP_PROXY`, `HTTPS_PROXY`)
2. Configures systemd service (if available)
3. Verifies integration success

### Skill Registration

Register the Skill in OpenClaw:

```python
from claw_vault.skills.clawvault_installer import ClawVaultInstallerSkill
from claw_vault.skills.base import SkillContext

# Create skill instance
ctx = SkillContext()
skill = ClawVaultInstallerSkill(ctx)

# Register with OpenClaw
# (OpenClaw-specific registration code)
```

## Error Handling

The Skill provides comprehensive error handling:

### Installation Errors

- **Python version too old**: Requires Python 3.10+
- **pip not available**: Install pip first
- **Network issues**: Automatically falls back to GitHub
- **Already installed**: Reports current version

### Configuration Errors

- **Invalid settings**: Validates configuration before applying
- **File permission errors**: Reports specific file issues
- **YAML syntax errors**: Provides helpful error messages

### Runtime Errors

- **Service not running**: Provides start instructions
- **API connection failed**: Checks network and service status
- **Rule generation failed**: Reports OpenAI API issues

## Best Practices

### 1. Start with Quick Mode

For first-time users, use quick mode to get started:

```python
skill.invoke("install_clawvault", mode="quick")
```

### 2. Test Before Production

Always run tests before deploying to production:

```python
skill.invoke("test_detection", category="all")
```

### 3. Use Scenario Templates

Leverage pre-defined scenarios for common use cases:

```python
skill.invoke("generate_rule", scenario="customer_service", apply=True)
```

### 4. Monitor Health Regularly

Check health status periodically:

```python
skill.invoke("check_health")
```

### 5. Keep Configuration

When uninstalling, keep configuration for easy reinstall:

```python
skill.invoke("uninstall", keep_config=True)
```

## Troubleshooting

### Installation Failed

**Problem:** Installation fails with network error

**Solution:**
1. Check internet connection
2. Try GitHub install: `pip install git+https://github.com/tophant-ai/ClawVault.git`
3. Use standalone script with `--mode quick`

### Services Not Running

**Problem:** Health check shows services stopped

**Solution:**
```bash
# Start ClawVault
clawvault start

# Check status
python clawvault_manager.py status
```

### Rule Generation Failed

**Problem:** Rule generation returns error

**Solution:**
1. Ensure ClawVault is running
2. Check `OPENAI_API_KEY` is set
3. Verify dashboard is accessible: `http://localhost:8766`

### Tests Failing

**Problem:** Detection tests show unexpected results

**Solution:**
1. Check detection configuration
2. Verify patterns are enabled
3. Review detection logs

## Publishing to ClawHub

### Prepare Package

```bash
# Create package directory
mkdir clawvault-installer-skill
cd clawvault-installer-skill

# Copy standalone script
cp scripts/skills/clawvault_manager.py .

# Create skill.json
cat > skill.json << EOF
{
  "name": "clawvault-installer",
  "version": "1.0.0",
  "description": "Install and manage ClawVault security system",
  "author": "SPAI Lab",
  "homepage": "https://github.com/tophant-ai/ClawVault",
  "main": "clawvault_manager.py",
  "permissions": ["execute_command", "write_files", "read_files", "network"],
  "tags": ["security", "installation", "clawvault"]
}
EOF
```

### Publish to ClawHub

```bash
# Package skill
tar -czf clawvault-installer-skill.tar.gz .

# Upload to ClawHub
clawhub publish clawvault-installer-skill.tar.gz
```

## Examples

### Example 1: Quick Setup

```python
# Install with defaults
result = skill.invoke("install_clawvault", mode="quick")
print(f"Installed version: {result.data['version']}")

# Run health check
health = skill.invoke("check_health")
print(f"Status: {health.data['overall_status']}")

# Run tests
tests = skill.invoke("test_detection", category="all")
print(f"Tests passed: {tests.data['summary']['passed']}/{tests.data['summary']['total']}")
```

### Example 2: Custom Configuration

```python
# Install with custom config
result = skill.invoke("install_clawvault", 
    mode="standard",
    config={
        "guard": {"mode": "strict"},
        "monitor": {"daily_token_budget": 100000}
    }
)

# Generate custom rule
rule = skill.invoke("generate_rule",
    policy="Block all requests containing database credentials",
    apply=True
)
print(f"Generated {len(rule.data['rules'])} rule(s)")
```

### Example 3: Scenario-Based Setup

```python
# Install for customer service
skill.invoke("install_clawvault", mode="quick")

# Apply customer service scenario
skill.invoke("generate_rule", 
    scenario="customer_service",
    apply=True
)

# Test PII detection
tests = skill.invoke("test_detection", category="sensitive")
print(f"PII detection: {tests.data['summary']['passed']} passed")
```

## API Reference

See the [OpenClaw Integration Guide](./OPENCLAW_INTEGRATION.md) for detailed API documentation.

## License

MIT © 2026 SPAI Lab

## Support

- [GitHub Issues](https://github.com/tophant-ai/ClawVault/issues)
- [Documentation](https://github.com/tophant-ai/ClawVault/tree/main/doc)
- [ClawHub](https://clawhub.ai/skills/clawvault-installer)
