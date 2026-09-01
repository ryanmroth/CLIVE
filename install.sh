#!/bin/sh
set -eu
SOURCE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
AGENT_DIR="$HOME/.codex/agents"
HOOK_DIR="$HOME/.codex/hooks"
mkdir -p "$AGENT_DIR" "$HOOK_DIR"
cp "$SOURCE_DIR/clive.toml" "$AGENT_DIR/clive.toml"
cp "$SOURCE_DIR/clive_guard.py" "$HOOK_DIR/clive_guard.py"
chmod 700 "$HOOK_DIR/clive_guard.py" 2>/dev/null || true
printf '%s\n' \
  "Installed CLIVE:" \
  "  $AGENT_DIR/clive.toml" \
  "  $HOOK_DIR/clive_guard.py" \
  "" \
  "Restart Codex, then invoke CLIVE from any repository."
