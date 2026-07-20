#!/bin/bash
# Runtime Action Guard engineering acceptance checks
# Usage: ./scripts/check-runtime-action-guard.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

echo "🛡️ Runtime Action Guard Checks"
echo "================================"
echo ""

echo "[1/4] Python runtime guard regression tests"
.venv/bin/pytest \
  tests/test_runtime_action_guard.py \
  tests/test_openclaw_runtime_action_api.py \
  tests/test_cli_runtime_observability.py \
  tests/test_guard.py \
  tests/test_sanitizer.py \
  -q

echo ""
echo "[2/4] OpenClaw file-guard integration tests"
npm --prefix openclaw-file-guard test -- --run tests/integration.test.ts

echo ""
echo "[3/4] OpenClaw file-guard build"
npm --prefix openclaw-file-guard run build

echo ""
echo "[4/4] Runtime guard lint checks"
.venv/bin/ruff check \
  src/claw_vault/cli.py \
  src/claw_vault/guard/runtime_action.py \
  src/claw_vault/openclaw/runtime_action_api.py \
  src/claw_vault/openclaw/runtime_action_adapter.py \
  tests/test_cli_runtime_observability.py

echo ""
echo "✅ Runtime Action Guard checks passed"
