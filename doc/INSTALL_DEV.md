# Development Setup

> [中文版](./zh/INSTALL_DEV.md)

## Prerequisites

- Python 3.10+
- Git

## Clone & Install

```bash
git clone https://github.com/tophant-ai/ClawVault.git
cd ClawVault
python3 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
```

## Verify

```bash
clawvault --version
clawvault demo           # Interactive detection demo
clawvault scan "sk-proj-abc123 password=secret 192.168.1.1"
```

## Run Tests

```bash
pytest
pytest --cov               # With coverage
```

## Start Services (Local)

```bash
clawvault start           # Proxy :8765 + Dashboard :8766
```

- **Proxy**: `http://127.0.0.1:8765`
- **Dashboard**: `http://127.0.0.1:8766`

Default guard mode is `permissive` (pass-through + logging). Change via Dashboard Config tab or:

```bash
clawvault start --mode interactive
```

## Configuration

```bash
clawvault config init     # Create ~/.ClawVault/config.yaml from template
clawvault config show     # Show current settings
clawvault config path     # Show config file location
```

Edit `~/.ClawVault/config.yaml` to customize. See [`config.example.yaml`](../config.example.yaml) for all options.

## Code Style

```bash
ruff check src/            # Lint
ruff format src/           # Format
mypy src/                  # Type check
```

## CLI Reference

```bash
clawvault --help          # All commands
clawvault start --help    # Start options
clawvault scan --help     # Scan options
clawvault skill list      # List available skills
clawvault skill export    # Export skills as OpenAI function-calling JSON
