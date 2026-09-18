Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$DataDir = Join-Path $env:LOCALAPPDATA 'FileShare'
$BinDir = Join-Path $env:USERPROFILE 'bin'
Remove-Item -LiteralPath (Join-Path $BinDir 'fs.cmd') -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $BinDir 'fs.ps1') -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $DataDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host '[OK] File Share removed.' -ForegroundColor Green
Write-Host '[INFO] Shared directories were not modified.'
