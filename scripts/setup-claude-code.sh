#!/bin/bash
# Setup Claude Code + ClawVault Runtime Action Guard integration
# Usage: ./scripts/setup-claude-code.sh [--yes] [--settings PATH] [--scope user|project]

set -e

CLAW_VAULT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

YES=""
DRY_RUN="--dry-run"
SETTINGS_ARGS=()

while [ $# -gt 0 ]; do
    case "$1" in
        --yes|-y)
            YES="--yes"
            DRY_RUN=""
            shift
            ;;
        --dry-run)
            DRY_RUN="--dry-run"
            shift
            ;;
        --settings)
            if [ $# -lt 2 ]; then
                echo "❌ --settings requires a path"
                exit 1
            fi
            SETTINGS_ARGS+=("--settings" "$2")
            shift 2
            ;;
        --scope)
            if [ $# -lt 2 ]; then
                echo "❌ --scope requires user or project"
                exit 1
            fi
            SETTINGS_ARGS+=("--scope" "$2")
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [--yes] [--dry-run] [--settings PATH] [--scope user|project]"
            echo ""
            echo "Default mode is dry-run. Pass --yes to modify Claude Code settings."
            exit 0
            ;;
        *)
            echo "❌ Unknown option: $1"
            exit 1
            ;;
    esac
done

VENV=""
for v in venv .venv env; do
    [ -d "$CLAW_VAULT_DIR/$v" ] && VENV="$CLAW_VAULT_DIR/$v" && break
done
[ -z "$VENV" ] && [ -n "$VIRTUAL_ENV" ] && VENV="$VIRTUAL_ENV"

if [ -n "$VENV" ] && [ -x "$VENV/bin/clawvault" ]; then
    CLAWVAULT="$VENV/bin/clawvault"
else
    CLAWVAULT=""
fi

if [ -n "$VENV" ] && [ -x "$VENV/bin/clawvault-claude-code-hook" ]; then
    HOOK_COMMAND="$VENV/bin/clawvault-claude-code-hook"
else
    HOOK_COMMAND="clawvault-claude-code-hook"
fi

if [ -n "$VENV" ] && [ -x "$VENV/bin/clawvault-claude-code-user-prompt-hook" ]; then
    USER_PROMPT_HOOK_COMMAND="$VENV/bin/clawvault-claude-code-user-prompt-hook"
else
    USER_PROMPT_HOOK_COMMAND="clawvault-claude-code-user-prompt-hook"
fi

if [ -z "$CLAWVAULT" ]; then
    if command -v clawvault > /dev/null 2>&1; then
        CLAWVAULT="clawvault"
    else
        echo "❌ clawvault not found. Install first: pip install -e ."
        exit 1
    fi
fi

echo "🔗 Claude Code + ClawVault Setup"
echo "================================"
echo ""
echo "[1/3] Checking ClawVault CLI..."
echo "  ✓ $($CLAWVAULT --version 2>/dev/null || echo installed)"

echo "[2/3] Current Claude Code hook status..."
$CLAWVAULT claude-code status "${SETTINGS_ARGS[@]}" --command "$HOOK_COMMAND" --user-prompt-command "$USER_PROMPT_HOOK_COMMAND"

echo ""
echo "[3/3] Installing Claude Code hook..."
if [ -n "$DRY_RUN" ]; then
    $CLAWVAULT claude-code install "$DRY_RUN" "${SETTINGS_ARGS[@]}" --command "$HOOK_COMMAND" --user-prompt-command "$USER_PROMPT_HOOK_COMMAND"
    echo ""
    echo "Dry-run only. Re-run with --yes to update Claude Code settings."
else
    $CLAWVAULT claude-code install $YES "${SETTINGS_ARGS[@]}" --command "$HOOK_COMMAND" --user-prompt-command "$USER_PROMPT_HOOK_COMMAND"
fi

echo ""
echo "========================"
echo "✅ Claude Code setup check complete"
echo ""
echo "Next steps:"
echo "  1. Start ClawVault:       ./scripts/start.sh"
echo "  2. Restart Claude Code:   open a new Claude Code session"
echo "  3. Check status:          clawvault claude-code status"
