#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

if [ ! -d "$VENV_DIR" ]; then
    echo "[oss-finding-mcp] venv not found. Run install.sh first." >&2
    exit 1
fi

exec "$VENV_DIR/bin/python" -m oss_finding.server "$@"
