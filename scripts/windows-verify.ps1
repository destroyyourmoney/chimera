param(
    [string]$Go = "C:\Program Files\Go\bin\go.exe",
    [switch]$SkipFull,
    [switch]$SkipTagged,
    [switch]$Race
)

$ErrorActionPreference = "Stop"

$repo = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $repo

if (-not (Test-Path $Go)) {
    $cmd = Get-Command go -ErrorAction SilentlyContinue
    if ($cmd) {
        $Go = $cmd.Source
    } else {
        throw "go.exe not found. Pass -Go 'C:\path\to\go.exe' or add Go to PATH."
    }
}

$env:GOCACHE = Join-Path $repo ".gocache"
$env:GOPATH = Join-Path $repo ".gopath"
$env:GOMODCACHE = Join-Path $repo ".gomodcache"
$env:CGO_ENABLED = "0"

New-Item -ItemType Directory -Force -Path $env:GOCACHE, $env:GOPATH, $env:GOMODCACHE, "bin" | Out-Null

function Invoke-Go {
    $goArgs = $args
    Write-Host "==> go $($goArgs -join ' ')" -ForegroundColor Cyan
    & $Go @goArgs
    if ($LASTEXITCODE -ne 0) {
        throw "go $($goArgs -join ' ') failed with exit code $LASTEXITCODE"
    }
}

Invoke-Go version

if (-not $SkipFull) {
    $testArgs = @("test")
    if ($Race) { $testArgs += "-race" }
    $testArgs += "./..."
    Invoke-Go @testArgs
}

if (-not $SkipTagged) {
	Invoke-Go test -tags chimera_quic ./cmd/chimera ./internal/quic ./internal/endpoint ./internal/socks ./internal/rudp
	Invoke-Go test -tags chimera_utls ./cmd/chimera ./internal/clienthello ./internal/reality ./internal/server
	Invoke-Go test -tags chimera_netstack ./cmd/chimera ./internal/netstack ./internal/tun ./internal/winnet
}

Invoke-Go build -buildvcs=false -o bin\chimera-windows.exe ./cmd/chimera
Invoke-Go build -buildvcs=false -tags chimera_quic -o bin\chimera-windows-quic.exe ./cmd/chimera
Invoke-Go build -buildvcs=false -tags chimera_utls -o bin\chimera-windows-utls.exe ./cmd/chimera
Invoke-Go build -buildvcs=false -tags "chimera_utls chimera_quic" -o bin\chimera-windows-full.exe ./cmd/chimera
Invoke-Go build -buildvcs=false -tags chimera_netstack -o bin\chimera-windows-netstack.exe ./cmd/chimera
Invoke-Go build -buildvcs=false -tags "chimera_utls chimera_quic chimera_netstack" -o bin\chimera-windows-max.exe ./cmd/chimera

Write-Host "OK: Windows verification completed." -ForegroundColor Green
