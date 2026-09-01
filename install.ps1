$ErrorActionPreference = "Stop"
$AgentDir = Join-Path $HOME ".codex\agents"
$HookDir = Join-Path $HOME ".codex\hooks"
$SourceDir = Split-Path -Parent $MyInvocation.MyCommand.Path
New-Item -ItemType Directory -Force -Path $AgentDir | Out-Null
New-Item -ItemType Directory -Force -Path $HookDir | Out-Null
Copy-Item -Force (Join-Path $SourceDir "clive.toml") (Join-Path $AgentDir "clive.toml")
Copy-Item -Force (Join-Path $SourceDir "clive_guard.py") (Join-Path $HookDir "clive_guard.py")
Write-Host "Installed CLIVE:"
Write-Host "  $AgentDir\clive.toml"
Write-Host "  $HookDir\clive_guard.py"
Write-Host ""
Write-Host "Restart Codex, then invoke CLIVE from any repository."
