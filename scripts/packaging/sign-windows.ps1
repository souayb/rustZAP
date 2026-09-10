# Authenticode-sign Windows artifacts (payload binaries and/or the installer).
# MUST run on Windows (signtool.exe ships with the Windows SDK).
#
# Usage: pwsh scripts/packaging/sign-windows.ps1 <file> [<file> ...]
#
# Env vars (all optional - the script degrades gracefully without them, the
# same way scripts/packaging/build-macos.sh does for Gatekeeper):
#   WINDOWS_PFX_BASE64     Base64-encoded .pfx/.p12 containing the Authenticode
#                          certificate + private key. When unset, signing is
#                          SKIPPED and reported - never faked. The resulting
#                          .exe is unsigned and SmartScreen will warn.
#   WINDOWS_PFX_PASSWORD   Password for that .pfx. Required whenever
#                          WINDOWS_PFX_BASE64 is set; a missing password is a
#                          hard error, not a silent fallback to unsigned.
#   WINDOWS_TIMESTAMP_URL  RFC 3161 timestamp server. Defaults to DigiCert's.
#                          Timestamping is what lets signatures outlive the
#                          certificate's own expiry, so it is never optional.
#
# The decrypted .pfx is never written to disk and the password never appears on
# a process command line: the certificate is loaded in memory, added to the
# CurrentUser\My store for the duration of the run, selected by thumbprint, and
# removed in a finally block that reports failure loudly rather than silencing it.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)]
    [string[]]$Paths
)

$ErrorActionPreference = 'Stop'

$pfxBase64 = $env:WINDOWS_PFX_BASE64
$pfxPassword = $env:WINDOWS_PFX_PASSWORD
$timestampUrl = if ($env:WINDOWS_TIMESTAMP_URL) { $env:WINDOWS_TIMESTAMP_URL } else { 'http://timestamp.digicert.com' }

if ([string]::IsNullOrWhiteSpace($pfxBase64)) {
    Write-Warning 'WINDOWS_PFX_BASE64 not set - skipping Authenticode signing.'
    Write-Warning 'The produced artifacts are UNSIGNED; SmartScreen will warn users.'
    Write-Warning 'See packaging/README.md ("Code signing") for how to configure this.'
    exit 0
}

if ([string]::IsNullOrWhiteSpace($pfxPassword)) {
    Write-Error 'WINDOWS_PFX_BASE64 is set but WINDOWS_PFX_PASSWORD is empty. Refusing to continue: a half-configured signing secret is a misconfiguration, not a reason to ship unsigned.'
}

# signtool.exe is not on PATH by default on GitHub's windows runners; it lives
# in a version-stamped Windows SDK directory. Prefer PATH, then the newest SDK.
$signtool = (Get-Command signtool.exe -ErrorAction SilentlyContinue).Source
if (-not $signtool) {
    $kitsRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    if (Test-Path -LiteralPath $kitsRoot) {
        # Only consider VERSIONED SDK dirs (<kits>\10\bin\10.0.22621.0\x64\).
        # Older SDK installs also leave a legacy unversioned <kits>\10\bin\x64\
        # signtool that predates RFC 3161 `/tr` support. A naive -Recurse with a
        # lexical descending sort would pick that one ('x' sorts above '1'), so
        # match the version directory explicitly and order by parsed [version]
        # rather than by string.
        $signtool = Get-ChildItem -LiteralPath $kitsRoot -Directory -ErrorAction SilentlyContinue |
            ForEach-Object {
                $parsed = $null
                if ([version]::TryParse($_.Name, [ref]$parsed)) {
                    $candidate = Join-Path $_.FullName 'x64\signtool.exe'
                    if (Test-Path -LiteralPath $candidate) {
                        [pscustomobject]@{ Version = $parsed; Path = $candidate }
                    }
                }
            } |
            Sort-Object Version -Descending |
            Select-Object -First 1 -ExpandProperty Path
    }
}
if (-not $signtool) {
    Write-Error 'signtool.exe not found. Install the Windows SDK (or add signtool to PATH) before signing.'
}
Write-Host "==> Using signtool: $signtool"

# Load the certificate from the base64 secret entirely in memory and sign by
# thumbprint (`/sha1`) rather than by file+password (`/f` + `/p`). This keeps
# the decrypted .pfx off disk entirely, and keeps the password off every
# process command line - `/p` would expose it to any local process for the
# duration of the call (Get-CimInstance Win32_Process | select CommandLine).
# PersistKeySet is required because signtool is a separate process and must be
# able to reach the private key through the store.
$keyFlags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]'Exportable, PersistKeySet'
$storeName = [System.Security.Cryptography.X509Certificates.StoreName]::My
$storeLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser

$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
    [System.Convert]::FromBase64String($pfxBase64), $pfxPassword, $keyFlags)
Write-Host "==> Signing certificate: $($cert.Subject) [$($cert.Thumbprint)]"

$store = [System.Security.Cryptography.X509Certificates.X509Store]::new($storeName, $storeLocation)
$store.Open('ReadWrite')
try { $store.Add($cert) } finally { $store.Close() }

try {
    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path)) {
            Write-Error "Cannot sign '$path': file does not exist."
        }
        $resolved = (Resolve-Path -LiteralPath $path).Path

        Write-Host "==> Signing $resolved"
        & $signtool sign /fd SHA256 /tr $timestampUrl /td SHA256 `
            /sha1 $cert.Thumbprint $resolved
        if ($LASTEXITCODE -ne 0) {
            Write-Error "signtool sign failed for '$resolved' (exit $LASTEXITCODE)."
        }

        Write-Host "==> Verifying $resolved"
        & $signtool verify /pa /v $resolved
        if ($LASTEXITCODE -ne 0) {
            Write-Error "signtool verify failed for '$resolved' (exit $LASTEXITCODE)."
        }
    }
}
finally {
    # Never silence a cleanup failure: a signing certificate left behind in the
    # store outlives this script. On an ephemeral CI runner that dies with the
    # VM, but this script is documented for local use too (packaging/README.md),
    # and a cancelled job skips this block entirely - so say so loudly.
    try {
        $cleanup = [System.Security.Cryptography.X509Certificates.X509Store]::new($storeName, $storeLocation)
        $cleanup.Open('ReadWrite')
        try { $cleanup.Remove($cert) } finally { $cleanup.Close() }
        Write-Host "==> Removed signing certificate from $storeLocation\$storeName"
    }
    catch {
        Write-Warning "FAILED to remove signing certificate $($cert.Thumbprint) from $storeLocation\$storeName : $_"
        Write-Warning 'Remove it manually before reusing this machine; the private key is still usable.'
    }
    # PersistKeySet writes the private key into the user key container. Store
    # removal normally takes the key with it, but that is not guaranteed for
    # every CSP/KSP - on a shared or self-hosted machine, confirm with
    # `Get-ChildItem Cert:\CurrentUser\My` after a run.
    $cert.Dispose()
}

Write-Host 'Authenticode signing complete.'
