#!/bin/sh
set -eu
rm -f "$HOME/.codex/agents/clive.toml"
rm -f "$HOME/.codex/hooks/clive_guard.py"
printf '%s\n' "Removed CLIVE."
