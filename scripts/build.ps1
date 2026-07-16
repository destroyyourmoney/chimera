# Builds the one chimera.exe you actually want to run: every optional feature
# compiled in (uTLS Chrome ClientHello fingerprint, QUIC/ElasticCC carrier,
# TUN/netstack full-tunnel). There is no reason to pick a smaller tag set for a
# real deployment -- each tag only gates an additional feature, never removes
# one, and a server built with fewer tags than a client (or vice versa) will
# refuse to negotiate the modes it wasn't built with (error: "rebuild with
# -tags chimera_quic"). scripts/windows-verify.ps1's per-tag builds are for
# contributors verifying that each feature still builds/tests in isolation,
# not a menu of build options to choose between. This is the CLI-only
# equivalent of build-app-windows.ps1 (which already builds the Flutter tray
# app with the same full tag set by default).
param(
    [string]$Go = "go"
)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $repo

$cmd = Get-Command $Go -ErrorAction SilentlyContinue
if (-not $cmd) {
    throw "go.exe not found. Pass -Go 'C:\path\to\go.exe' or add Go to PATH."
}

New-Item -ItemType Directory -Force -Path "bin" | Out-Null
$env:CGO_ENABLED = "0"

$tags = "chimera_utls chimera_quic chimera_netstack chimera_ss chimera_dot"
& $Go build -buildvcs=false -tags $tags -o bin\chimera.exe .\cmd\chimera
if ($LASTEXITCODE -ne 0) {
    throw "go build failed with exit code $LASTEXITCODE"
}

Write-Host "Built bin\chimera.exe (tags: $tags)." -ForegroundColor Green
