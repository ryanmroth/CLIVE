$ErrorActionPreference = "Stop"
Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $HOME ".codex\agents\clive.toml")
Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $HOME ".codex\hooks\clive_guard.py")
Write-Host "Removed CLIVE."
