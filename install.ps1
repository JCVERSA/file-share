param(
    [switch]$Update,
    [switch]$DryRun,
    [switch]$Force,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Repo = 'JCVERSA/file-share'
$Branch = 'main'
$ArchiveUrl = "https://github.com/$Repo/archive/refs/heads/$Branch.zip"
$RawBase = "https://raw.githubusercontent.com/$Repo/$Branch"
$DataDir = Join-Path $env:LOCALAPPDATA 'FileShare'
$InstallDir = Join-Path $DataDir 'current'
$BackupDir = Join-Path $DataDir 'backups'
$BinDir = Join-Path $env:USERPROFILE 'bin'
$TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("file-share-install-" + [guid]::NewGuid().ToString('N'))

function Info($Message) { Write-Host "[INFO] $Message" }
function Ok($Message) { Write-Host "[OK] $Message" -ForegroundColor Green }
function Warn($Message) { Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Fail($Message) { throw $Message }

if ($Help) {
    @"
File Share installer

Install or update:
  irm https://raw.githubusercontent.com/JCVERSA/file-share/main/install.ps1 | iex

Options when running the script directly:
  -Update     Explicit update mode
  -DryRun     Download and validate without installing
  -Force      Reinstall the same version
"@
    exit 0
}

New-Item -ItemType Directory -Force -Path $TempRoot | Out-Null
try {
    $python = Get-Command py -ErrorAction SilentlyContinue
    if (-not $python) { $python = Get-Command python -ErrorAction SilentlyContinue }
    if (-not $python) { Fail 'Python 3 is required. Install Python 3, then run the installer again.' }

    $archive = Join-Path $TempRoot 'file-share.zip'
    $extract = Join-Path $TempRoot 'extracted'
    $stage = Join-Path $TempRoot 'staged'

    Info "Downloading File Share from $Repo/$Branch..."
    Invoke-WebRequest -Uri $ArchiveUrl -OutFile $archive
    Expand-Archive -LiteralPath $archive -DestinationPath $extract -Force

    $project = Get-ChildItem -LiteralPath $extract -Directory | Where-Object {
        (Test-Path (Join-Path $_.FullName 'server.py')) -and
        (Test-Path (Join-Path $_.FullName 'templates\index.html'))
    } | Select-Object -First 1

    if (-not $project) { Fail 'Downloaded archive does not contain a valid File Share project.' }

    $serverText = Get-Content -Raw -LiteralPath (Join-Path $project.FullName 'server.py')
    $match = [regex]::Match($serverText, '(?m)^APP_VERSION\s*=\s*["'']([^"'']+)["'']')
    if (-not $match.Success) { Fail 'Could not determine File Share version.' }
    $remoteVersion = $match.Groups[1].Value

    if ($remoteVersion -notmatch '^\d+\.\d+\.\d+$') { Fail "Invalid File Share version: $remoteVersion" }

    $currentVersion = ''
    $currentServer = Join-Path $InstallDir 'server.py'
    if (Test-Path $currentServer) {
        $currentText = Get-Content -Raw -LiteralPath $currentServer
        $currentMatch = [regex]::Match($currentText, '(?m)^APP_VERSION\s*=\s*["'']([^"'']+)["'']')
        if ($currentMatch.Success) { $currentVersion = $currentMatch.Groups[1].Value }
    }

    if ($currentVersion -and ($currentVersion -eq $remoteVersion) -and (-not $Force) -and (-not $DryRun)) {
        Ok "File Share $currentVersion is already installed."
        return
    }

    if ($currentVersion -and (-not $Force)) {
        if ([version]$currentVersion -gt [version]$remoteVersion) {
            Warn "Installed version $currentVersion is newer than downloaded version $remoteVersion; refusing to downgrade."
            return
        }
    }

    if ($DryRun) {
        Ok "Validated File Share $remoteVersion."
        if ($currentVersion) { Info "Installed version: $currentVersion" }
        return
    }

    New-Item -ItemType Directory -Force -Path $DataDir, $BackupDir, $BinDir, $stage | Out-Null
    Copy-Item -Path (Join-Path $project.FullName '*') -Destination $stage -Recurse -Force
    Remove-Item -LiteralPath (Join-Path $stage '__pycache__') -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath (Join-Path $stage '.git') -Recurse -Force -ErrorAction SilentlyContinue

    & $python.Source -m py_compile (Join-Path $stage 'server.py')
    if ($LASTEXITCODE -ne 0) { Fail 'Python validation failed.' }

    $backup = $null
    if (Test-Path $InstallDir) {
        $suffix = Get-Date -Format 'yyyyMMdd-HHmmss'
        $versionForBackup = if ($currentVersion) { $currentVersion } else { 'unknown' }
        $backup = Join-Path $BackupDir "$suffix-$versionForBackup"
        Move-Item -LiteralPath $InstallDir -Destination $backup -Force
    }
    try {
        Move-Item -LiteralPath $stage -Destination $InstallDir -Force
    } catch {
        if ($backup -and (Test-Path $backup)) {
            Move-Item -LiteralPath $backup -Destination $InstallDir -Force
        }
        throw
    }

    $fsCmd = Join-Path $BinDir 'fs.cmd'
    $fsPs1 = Join-Path $BinDir 'fs.ps1'
    $updatePs1 = Join-Path $InstallDir 'update.ps1'
    $uninstallPs1 = Join-Path $InstallDir 'uninstall.ps1'

    # PowerShell prefers .ps1 scripts over .cmd files when resolving a command.
    # Remove any legacy fs.ps1 launcher so `fs` resolves to fs.cmd instead of
    # trying to execute server.py through Windows file associations (for example VS Code).
    Remove-Item -LiteralPath $fsPs1 -Force -ErrorAction SilentlyContinue

    @"
@echo off
setlocal
set "FILE_SHARE_HOME=$InstallDir"

if /I "%~1"=="update" goto UPDATE
if /I "%~1"=="self-update" goto UPDATE
if /I "%~1"=="uninstall" goto UNINSTALL
if /I "%~1"=="version" goto VERSION
if /I "%~1"=="--version" goto VERSION
if /I "%~1"=="-V" goto VERSION
if /I "%~1"=="help" goto HELP
if /I "%~1"=="--help" goto HELP
if /I "%~1"=="-h" goto HELP

where py >nul 2>nul
if not errorlevel 1 (
    py "%FILE_SHARE_HOME%\server.py" %*
) else (
    where python >nul 2>nul
    if errorlevel 1 (
        echo [ERROR] Python 3 was not found in PATH.
        exit /b 1
    )
    python "%FILE_SHARE_HOME%\server.py" %*
)
exit /b %ERRORLEVEL%

:VERSION
where py >nul 2>nul
if not errorlevel 1 (
    py "%FILE_SHARE_HOME%\server.py" --version
) else (
    python "%FILE_SHARE_HOME%\server.py" --version
)
exit /b %ERRORLEVEL%

:HELP
where py >nul 2>nul
if not errorlevel 1 (
    py "%FILE_SHARE_HOME%\server.py" --help
) else (
    python "%FILE_SHARE_HOME%\server.py" --help
)
exit /b %ERRORLEVEL%

:UPDATE
powershell -NoProfile -ExecutionPolicy Bypass -File "%FILE_SHARE_HOME%\update.ps1"
exit /b %ERRORLEVEL%

:UNINSTALL
powershell -NoProfile -ExecutionPolicy Bypass -File "%FILE_SHARE_HOME%\uninstall.ps1"
exit /b %ERRORLEVEL%
"@ | Set-Content -LiteralPath $fsCmd -Encoding ASCII

    @"
Set-StrictMode -Version Latest
`$ErrorActionPreference = 'Stop'
& ([scriptblock]::Create((Invoke-RestMethod '$RawBase/install.ps1'))) -Update
"@ | Set-Content -LiteralPath $updatePs1 -Encoding UTF8

    @"
Set-StrictMode -Version Latest
`$ErrorActionPreference = 'Stop'
Remove-Item -LiteralPath '$fsCmd' -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath '$fsPs1' -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath '$DataDir' -Recurse -Force -ErrorAction SilentlyContinue
Write-Host '[OK] File Share removed.' -ForegroundColor Green
Write-Host '[INFO] Shared directories were not modified.'
"@ | Set-Content -LiteralPath $uninstallPs1 -Encoding UTF8

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not (($userPath -split ';') -contains $BinDir)) {
        $newPath = if ([string]::IsNullOrWhiteSpace($userPath)) { $BinDir } else { "$userPath;$BinDir" }
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    }
    if (($env:Path -split ';') -notcontains $BinDir) { $env:Path = "$BinDir;$env:Path" }

    Ok "File Share $remoteVersion installed."
    Ok "Command: fs"
    if ($currentVersion) { Ok "Previous version: $currentVersion" }
    Write-Host ''
    Write-Host 'Try: fs --version'
    Write-Host '     fs'
    Write-Host '     fs update'
    Write-Host '     fs uninstall'
}
finally {
    Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
