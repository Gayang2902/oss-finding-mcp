#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
SERVER_NAME="oss-finding-mcp"
DEFAULT_TARGET="$HOME/targets"

echo "=== $SERVER_NAME installer ==="

# 1. Create venv if missing
if [ ! -d "$VENV_DIR" ]; then
    echo "[1/3] Creating venv..."
    python3 -m venv "$VENV_DIR"
else
    echo "[1/3] venv already exists."
fi

# 2. Install package
echo "[2/3] Installing $SERVER_NAME..."
"$VENV_DIR/bin/pip" install -q -e "$SCRIPT_DIR"

# 3. Register with claude mcp add
SCOPE="${1:-user}"
TARGET="${2:-$DEFAULT_TARGET}"

echo "[3/3] Registering MCP server (scope=$SCOPE, target=$TARGET)..."

claude mcp remove "$SERVER_NAME" -s "$SCOPE" 2>/dev/null || true

claude mcp add "$SERVER_NAME" \
    -s "$SCOPE" \
    -e "OSS_FINDING_PROJECT_ROOT=$TARGET" \
    -- \
    "$SCRIPT_DIR/run.sh"

echo ""
echo "Done! $SERVER_NAME registered."
echo "  Target: $TARGET"
echo "  Scope:  $SCOPE"
echo ""
echo "Usage:"
echo "  ./install.sh              # user scope, target=$DEFAULT_TARGET"
echo "  ./install.sh project      # project scope"
echo "  ./install.sh user /path   # custom target path"
