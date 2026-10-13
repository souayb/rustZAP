<#
.SYNOPSIS
  RustZAP one-line installer for Windows (console CLI binary).

.DESCRIPTION
  Downloads the signed console rustzap.exe from the latest GitHub release,
  verifies its SHA-256 against SHA256SUMS, and installs it to a per-user dir.
  This is the CLI for scripting/CI — NOT the GUI .exe installer.

  Run:
    irm https://raw.githubusercontent.com/souayb/rustZAP/main/scripts/install.ps1 | iex

.PARAMETER Version
  Specific version to install (default: latest release).
.PARAMETER BinDir
  Install location (default: %LOCALAPPDATA%\Programs\rustzap).
.PARAMETER NoVerify
  Skip SHA-256 verification.
#>
[CmdletBinding()]
param(
  [string]$Version = $env:RUSTZAP_VERSION,
  [string]$BinDir  = $env:RUSTZAP_INSTALL_DIR,
  [switch]$NoVerify
)

$ErrorActionPreference = 'Stop'
$repo = 'souayb/rustZAP'

if (-not $Version) {
  Write-Host '==> Resolving latest release'
  $rel = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest"
  $Version = $rel.tag_name -replace '^v', ''
}
if (-not $BinDir) { $BinDir = Join-Path $env:LOCALAPPDATA 'Programs\rustzap' }

$asset = "rustzap-$Version-windows-x64.zip"
$base  = "https://github.com/$repo/releases/download/v$Version"
Write-Host "==> Installing rustzap $Version (windows/x64)"

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("rustzap-install-" + [guid]::NewGuid())
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
try {
  $zip = Join-Path $tmp $asset
  Write-Host "==> Downloading $asset"
  Invoke-WebRequest "$base/$asset" -OutFile $zip

  if (-not $NoVerify) {
    Write-Host '==> Verifying checksum'
    $sumsPath = Join-Path $tmp 'SHA256SUMS'
    Invoke-WebRequest "$base/SHA256SUMS" -OutFile $sumsPath
    $want = (Select-String -Path $sumsPath -Pattern ("\s" + [regex]::Escape($asset) + "$") |
             Select-Object -First 1).Line -replace '\s.*$', ''
    if (-not $want) { throw "no SHA256SUMS entry for $asset" }
    $got = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
    if ($want.ToLower() -ne $got) { throw "checksum mismatch for $asset (expected $want, got $got)" }
    Write-Host '==> Checksum OK'
  }

  Expand-Archive -Path $zip -DestinationPath $tmp -Force
  $exe = Join-Path $tmp 'rustzap.exe'
  if (-not (Test-Path $exe)) { throw "archive did not contain rustzap.exe" }

  New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
  Copy-Item $exe (Join-Path $BinDir 'rustzap.exe') -Force
  Write-Host "==> Installed $(Join-Path $BinDir 'rustzap.exe')"

  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (($userPath -split ';') -notcontains $BinDir) {
    [Environment]::SetEnvironmentVariable('Path', "$userPath;$BinDir", 'User')
    Write-Host "==> Added $BinDir to your user PATH (open a new terminal to pick it up)"
  }
  & (Join-Path $BinDir 'rustzap.exe') --version
  Write-Host "Done. Run 'rustzap --help' to get started."
}
finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
