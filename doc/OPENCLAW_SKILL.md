# ClawVault OpenClaw Skill Guide

> [中文文档](./zh/OPENCLAW_SKILL.md)

Complete guide for installing, configuring, and using the ClawVault skill in OpenClaw.

## Overview

The ClawVault skill enables AI-guided installation, configuration, and management of the ClawVault security system directly from OpenClaw. It provides a complete suite of tools for protecting AI agents from prompt injection, data leakage, and dangerous commands.

**Key Features:**
- **AI-guided installation** - Multi-mode setup with intelligent defaults
- **Rule generation** - Create security rules from natural language
- **Scenario templates** - Pre-configured policies for common use cases
- **Health monitoring** - Real-time service status and diagnostics
- **Detection testing** - Built-in test suites for validation
- **Lifecycle management** - Complete install/configure/uninstall workflow

## Installation Methods

### Method 1: Install as OpenClaw Skill (Recommended)

Copy the skill to your OpenClaw skills directory:

**Option 1: Install from ClawHub (Recommended)**

```bash
# Install from ClawHub
openclaw skills install tophant-clawvault-installer

# Or use clawhub CLI
clawhub install tophant-clawvault-installer
```

**ClawHub:** https://clawhub.ai/Martin2877/tophant-clawvault-installer

**Option 2: Install from Local Repository**

```bash
# Copy skill directory
cp -r skills/tophant-clawvault-installer ~/.openclaw/skills/

# Or create symbolic link (recommended for development)
ln -s /path/to/ClawVault/skills/tophant-clawvault-installer ~/.openclaw/skills/tophant-clawvault-installer
```

Restart OpenClaw to load the skill:

```bash
openclaw restart
```

Verify the skill is loaded:

```bash
openclaw skills list
# Should show: tophant-clawvault-installer
```

### Method 2: Use as Built-in Skill

If ClawVault is already installed, the skill is automatically available:

```python
from claw_vault.skills.registry import SkillRegistry

registry = SkillRegistry()
registry.register_builtins()

# The clawvault skill is now available
result = registry.invoke("clawvault_installer", "check_health")
```

### Method 3: Standalone Script

Download and use the standalone script without OpenClaw:

```bash
# Download script
curl -O https://raw.githubusercontent.com/tophant-ai/ClawVault/main/skills/tophant-clawvault-installer/clawvault_manager.py

# Use directly
python clawvault_manager.py install --mode quick
python clawvault_manager.py health
```

## Command Reference

### /clawvault install

Install ClawVault with AI-guided setup.

**Usage:**
```bash
/clawvault install --mode quick
/clawvault install --mode standard
/clawvault install --mode advanced
```

**Installation Modes:**

- **quick** - One-click install with recommended defaults
  - Installs from PyPI (fallback to GitHub)
  - Creates default configuration
  - Enables all detection features
  - Sets interactive guard mode
  
- **standard** - Interactive configuration
  - Prompts for common settings
  - Allows port customization
  - Choose guard mode
  - Select detection features
  
- **advanced** - Full customization
  - Complete control over all settings
  - Custom detection patterns
  - Advanced proxy configuration
  - Budget and monitoring settings

**What Happens During Installation:**
1. Checks prerequisites (Python 3.10+, pip)
2. Installs ClawVault package
3. Creates configuration directory (`~/.ClawVault/`)
4. Generates default config.yaml
5. Runs health check
6. Reports installation status

### /clawvault start

Start ClawVault proxy and dashboard services.

**Usage:**
```bash
# Start with default settings (localhost only)
clawvault start

# Start with dashboard accessible from any IP
clawvault start --dashboard-host 0.0.0.0

# Start with custom ports
clawvault start --port 8765 --dashboard-port 8766

# Start with specific guard mode
clawvault start --mode strict

# Start without dashboard
clawvault start --no-dashboard

# Combine options
clawvault start --dashboard-host 0.0.0.0 --dashboard-port 8080 --mode interactive
```

**Command-line Options:**
- `--port <PORT>` - Proxy listen port (default: 8765)
- `--dashboard-port <PORT>` - Dashboard web UI port (default: 8766)
- `--dashboard-host <HOST>` - Dashboard bind address:
  - `127.0.0.1` (default) - Local access only (secure)
  - `0.0.0.0` - Allow remote access from any IP
  - Specific IP - Bind to specific network interface
- `--mode <MODE>` - Guard mode: `permissive`, `interactive`, or `strict`
- `--no-dashboard` - Disable web dashboard
- `--config <PATH>` - Path to custom config.yaml

**Dashboard Access:**
- Local only: `http://127.0.0.1:8766` (default, secure)
- Remote access: `http://0.0.0.0:8766` or `http://<server-ip>:8766`

**Security Notes:**
- Use `0.0.0.0` only in trusted networks or behind firewall
- Dashboard shows sensitive detection data
- For production, use reverse proxy with HTTPS

### /clawvault health

Check ClawVault service health and configuration status.

**Usage:**
```bash
/clawvault health
```

**Returns:**
- Installation status (installed/not installed)
- Version information
- Service running status (proxy, dashboard)
- Configuration validity
- Port availability (8765, 8766)
- Overall health status

### /clawvault generate-rule

Generate security rules from natural language or apply pre-configured scenarios.

**Usage:**
```bash
/clawvault generate-rule "Block all AWS credentials and API keys"
/clawvault generate-rule --scenario customer_service --apply
/clawvault generate-rule --scenario development
```

**Available Scenarios:**
- `customer_service` - PII detection + auto-sanitization for customer support
- `development` - API key protection + dangerous command detection
- `production` - Strict mode with high-risk content blocking
- `finance` - Financial compliance + comprehensive PII detection

**Options:**
- `--apply` - Automatically apply the generated rule to ClawVault
- `--scenario <name>` - Use a pre-configured security scenario

**Natural Language Examples:**
```bash
# Detect specific threats
/clawvault generate-rule "Detect and block all database passwords"

# Multi-condition rules
/clawvault generate-rule "Block AWS credentials with risk score above 8.0"

# Compliance-focused
/clawvault generate-rule "Detect all PII for GDPR compliance"
```

### /clawvault status

Get current ClawVault running status and statistics.

**Usage:**
```bash
/clawvault status
```

**Returns:**
- Service uptime
- Detection statistics (total requests, blocked, sanitized)
- Active rules count
- Dashboard URL
- Token usage and cost

### /clawvault test

Run built-in detection tests to verify ClawVault capabilities.

**Usage:**
```bash
/clawvault test --category all
/clawvault test --category sensitive
/clawvault test --category injection
/clawvault test --category commands
```

**Test Categories:**
- `all` - Run all detection tests
- `sensitive` - Test PII and credential detection
- `injection` - Test prompt injection detection
- `commands` - Test dangerous command detection

**Test Coverage:**
- Sensitive data: API keys, credit cards, emails, phone numbers
- Injection attacks: Prompt injection, role hijacking, jailbreak attempts
- Dangerous commands: rm -rf, curl|bash, system exploits

### /clawvault uninstall

Remove ClawVault from the system.

**Usage:**
```bash
/clawvault uninstall
/clawvault uninstall --keep-config
```

**Options:**
- `--keep-config` - Preserve configuration files for future reinstallation

**What Gets Removed:**
- ClawVault Python package
- Service files (if using systemd)
- Optionally: Configuration directory (`~/.ClawVault/`)

## Configuration

### Configuration File

Create `~/.ClawVault/config.yaml` for persistent settings:

```yaml
# Proxy Configuration
proxy:
  host: "127.0.0.1"
  port: 8765

# Dashboard Configuration
dashboard:
  enabled: true
  host: "0.0.0.0"  # Allow remote access
  port: 8766

# Guard Mode
guard:
  mode: "interactive"  # permissive | interactive | strict

# Detection Settings
detection:
  check_sensitive: true
  check_injection: true
  check_commands: true
  
# Audit Settings
audit:
  enabled: true
  store_path: "~/.ClawVault/audit.db"
```

Load custom config:
```bash
clawvault start --config /path/to/config.yaml
```

### Environment Variables

```bash
# OpenAI API Key (for rule generation)
export OPENAI_API_KEY="sk-..."

# Custom config path
export CLAWVAULT_CONFIG="~/.ClawVault/config.yaml"

# Log level
export CLAWVAULT_LOG_LEVEL="DEBUG"  # DEBUG | INFO | WARNING | ERROR
```

### Guard Modes

**Permissive Mode:**
- Logs all detections
- Never blocks requests
- Good for testing and development

**Interactive Mode (Recommended):**
- Asks user before blocking
- Shows detection details
- Allows override decisions
- Good for production with human oversight

**Strict Mode:**
- Automatically blocks high-risk content
- No user interaction
- Good for automated systems

## Security Scenario Templates

### Customer Service Scenario

**Use Case:** Protect customer PII in support conversations

**Features:**
- Detect phone numbers, ID cards, emails, addresses
- Auto-sanitize sensitive data (replace with `[REDACTED]`)
- Block prompt injection attacks
- Interactive mode (ask before blocking)

**Apply:**
```bash
/clawvault generate-rule --scenario customer_service --apply
```

**Generated Policy:**
```
For customer service agents, detect and auto-sanitize all PII data 
including phone numbers, ID cards, emails, addresses. Block prompt 
injections. Use interactive mode.
```

### Development Scenario

**Use Case:** Protect secrets in development environment

**Features:**
- Detect API keys, tokens, passwords, private keys
- Detect dangerous shell commands
- Auto-sanitize secrets
- Permissive mode (log only, don't block)

**Apply:**
```bash
/clawvault generate-rule --scenario development --apply
```

**Generated Policy:**
```
For development environment, detect API keys, tokens, passwords, 
and dangerous commands. Auto-sanitize secrets. Allow everything else.
```

### Production Scenario

**Use Case:** Strict security for production systems

**Features:**
- Block all high-risk content (score >= 7.0)
- Detect all threat types
- Strict mode (block immediately)
- No auto-sanitization (preserve evidence)

**Apply:**
```bash
/clawvault generate-rule --scenario production --apply
```

**Generated Policy:**
```
For production environment, block all threats with risk score above 7.0. 
Strict mode. No auto-sanitization.
```

### Finance Scenario

**Use Case:** Financial compliance and data protection

**Features:**
- Detect credit cards, bank accounts, SSN, routing numbers
- Detect all PII types
- Block high-risk content
- Strict compliance mode

**Apply:**
```bash
/clawvault generate-rule --scenario finance --apply
```

**Generated Policy:**
```
For financial applications, detect credit cards, bank accounts, SSN, 
and all PII. Block high-risk content. Strict compliance mode.
```

## Advanced Configuration

### Dashboard Remote Access

**For Development/Testing:**
```bash
# Allow access from any IP on default port
clawvault start --dashboard-host 0.0.0.0

# Custom port for remote access
clawvault start --dashboard-host 0.0.0.0 --dashboard-port 8080

# Access from browser
http://<server-ip>:8766
```

**Firewall Configuration:**
```bash
# Allow port 8766
sudo ufw allow 8766

# Or for specific IP range
sudo ufw allow from 192.168.1.0/24 to any port 8766
```

**Verify Listening:**
```bash
netstat -tlnp | grep 8766
# Should show: 0.0.0.0:8766
```

### Docker Deployment

**Dockerfile:**
```dockerfile
FROM python:3.10-slim

RUN pip install clawvault

EXPOSE 8765 8766

CMD ["clawvault", "start", "--dashboard-host", "0.0.0.0"]
```

**Build and Run:**
```bash
# Build image
docker build -t clawvault .

# Run container
docker run -p 8765:8765 -p 8766:8766 clawvault

# Access dashboard
http://localhost:8766
```

### Systemd Service (Linux)

Create `/etc/systemd/system/clawvault.service`:

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

Enable and start:
```bash
sudo systemctl enable clawvault
sudo systemctl start clawvault
sudo systemctl status clawvault
```

## Troubleshooting

### Installation Issues

**Problem:** Installation fails with network error

**Solution:**
1. Check internet connection
2. Try GitHub install: `pip install git+https://github.com/tophant-ai/ClawVault.git`
3. Use standalone script with `--mode quick`

**Problem:** Python version too old

**Solution:**
```bash
# Check Python version
python3 --version

# Should be 3.10 or higher
# Install Python 3.10+ or use virtual environment
python3.10 -m venv venv
source venv/bin/activate
```

### Service Issues

**Problem:** Services not running after installation

**Solution:**
```bash
# Start ClawVault manually
clawvault start

# Check status
clawvault status

# View logs
tail -f ~/.ClawVault/logs/clawvault.log
```

**Problem:** Port already in use

**Solution:**
```bash
# Find process using port
lsof -i :8765
lsof -i :8766

# Kill process
kill -9 <PID>

# Or use different ports
clawvault start --port 8767 --dashboard-port 8768
```

### Dashboard Issues

**Problem:** Cannot access dashboard remotely

**Solutions:**
1. **Check bind address:**
   ```bash
   clawvault start --dashboard-host 0.0.0.0
   ```

2. **Check firewall:**
   ```bash
   sudo ufw allow 8766
   ```

3. **Verify listening:**
   ```bash
   netstat -tlnp | grep 8766
   # Should show: 0.0.0.0:8766
   ```

### Rule Generation Issues

**Problem:** Rule generation returns error

**Solution:**
1. Ensure ClawVault is running: `clawvault status`
2. Check `OPENAI_API_KEY` is set: `echo $OPENAI_API_KEY`
3. Verify dashboard is accessible: `http://localhost:8766`
4. Check API quota and billing

**Problem:** Generated rules don't work as expected

**Solution:**
1. Review generated YAML in dashboard
2. Test with specific examples
3. Adjust risk thresholds
4. Use more specific natural language descriptions

### Detection Issues

**Problem:** Tests failing unexpectedly

**Solution:**
1. Check detection configuration in config.yaml
2. Verify patterns are enabled
3. Review detection logs: `~/.ClawVault/logs/detection.log`
4. Run specific category tests to isolate issue

**Problem:** False positives/negatives

**Solution:**
1. Adjust risk score thresholds
2. Customize detection patterns
3. Use guard mode appropriate for your use case
4. Review and update rules regularly

## Integration with OpenClaw

### Automatic Proxy Configuration

The skill automatically configures OpenClaw to use ClawVault proxy:

1. Sets environment variables (`HTTP_PROXY`, `HTTPS_PROXY`)
2. Configures systemd service (if available)
3. Verifies integration success

### Manual Proxy Setup

If automatic configuration doesn't work:

```bash
# Set proxy environment variables
export HTTP_PROXY=http://127.0.0.1:8765
export HTTPS_PROXY=http://127.0.0.1:8765

# For OpenClaw systemd service
sudo systemctl edit openclaw-gateway

# Add:
[Service]
Environment="HTTP_PROXY=http://127.0.0.1:8765"
Environment="HTTPS_PROXY=http://127.0.0.1:8765"

# Restart OpenClaw
sudo systemctl restart openclaw-gateway
```

### Verification

Check that traffic is flowing through ClawVault:

1. Start ClawVault: `clawvault start`
2. Open dashboard: `http://localhost:8766`
3. Make an AI request in OpenClaw
4. Verify request appears in dashboard

## Best Practices

### 1. Start with Quick Mode

For first-time users, use quick mode to get started:

```bash
/clawvault install --mode quick
```

### 2. Test Before Production

Always run tests before deploying to production:

```bash
/clawvault test --category all
```

### 3. Use Scenario Templates

Leverage pre-defined scenarios for common use cases:

```bash
/clawvault generate-rule --scenario customer_service --apply
```

### 4. Monitor Health Regularly

Check health status periodically:

```bash
/clawvault health
```

### 5. Keep Configuration

When uninstalling, keep configuration for easy reinstall:

```bash
/clawvault uninstall --keep-config
```

### 6. Review Detection Logs

Regularly review logs to tune detection:

```bash
tail -f ~/.ClawVault/logs/detection.log
```

### 7. Update Rules

Keep security rules up-to-date:

```bash
# Regenerate rules with latest patterns
/clawvault generate-rule --scenario production --apply
```

## CLI Reference

### Help Commands

```bash
# Show main help
clawvault --help
clawvault -h

# Show version
clawvault --version
clawvault -v

# Show command-specific help
clawvault start --help
clawvault install --help
```

### Common Commands

```bash
# Start services
clawvault start
clawvault start --dashboard-host 0.0.0.0 --mode strict

# Check status
clawvault status

# View logs
clawvault logs
clawvault logs --follow

# Stop services
clawvault stop

# Restart services
clawvault restart
```

## Support

- **Documentation**: https://github.com/tophant-ai/ClawVault/tree/main/doc
- **Issues**: https://github.com/tophant-ai/ClawVault/issues
- **Repository**: https://github.com/tophant-ai/ClawVault

## License

MIT © 2026 Tophant SPAI Lab
