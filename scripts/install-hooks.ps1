# Install or remove repo-local Git hooks (Windows PowerShell).
# Does not change global git config.
#
# Usage:
#   .\scripts\install-hooks.ps1
#   .\scripts\install-hooks.ps1 -Uninstall

[CmdletBinding()]
param(
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

function Get-RepoRoot {
    $root = git rev-parse --show-toplevel 2>$null
    if (-not $root) {
        throw "Not inside a git working tree (is git on PATH?)."
    }
    return $root.Trim()
}

$root = Get-RepoRoot
Set-Location $root

if ($Uninstall) {
    git config --unset core.hooksPath 2>$null | Out-Null
    Write-Host "Removed local core.hooksPath (Git will use .git/hooks)."
    exit 0
}

if (-not (Test-Path (Join-Path $root ".githooks/pre-commit"))) {
    throw "Missing .githooks/pre-commit — are you in the rustzap repo?"
}

git config core.hooksPath .githooks

if (Get-Command rustup -ErrorAction SilentlyContinue) {
    rustup component add rustfmt clippy | Out-Null
}

Write-Host "Installed Git hooks (local core.hooksPath=.githooks)."
Write-Host "  pre-commit → rustfmt + block generated reports"
Write-Host "  pre-push   → clippy -D warnings + cargo test"
Write-Host "Requires Git for Windows so hooks run under bash: https://gitforwindows.org/"
Write-Host "Uninstall: .\scripts\install-hooks.ps1 -Uninstall"
