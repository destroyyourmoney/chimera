param(
    [string]$Go = "C:\Program Files\Go\bin\go.exe",
    [string]$Gcc,
    [string]$Flutter,
    [string]$Tags = "chimera_utls chimera_quic chimera_netstack"
)

# Builds the CHIMERA Windows tray app end to end:
#   1. chimera.dll     (desktop/cffi, -buildmode=c-shared, needs CGO_ENABLED=1 + gcc)
#   2. chimera.exe     (cmd/chimera CLI, bundled for the network protection toggle)
#   3. chimera-helper.exe (cmd/chimera-helper, the persistent elevated Windows
#      service that gives full-tunnel Connect a one-time UAC prompt instead
#      of one per connect -- see internal/nethelper's doc comment)
#   4. wintun.dll   (staged from third_party/wintun/ -- the driver binary
#      chimera.exe's TUN device needs at runtime; see that directory's README)
#   5. flutter build windows (app/), which picks all four up via
#      app/windows/CMakeLists.txt
#   6. copies the runnable bundle to chimera_tray/ at the repo root
#
# See docs/app/build-runbook.md for the manual step-by-step version and the
# rationale (why c-shared not c-archive, why server/client need matching -Tags).

$ErrorActionPreference = "Stop"

$repo = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $repo

if (-not (Test-Path $Go)) {
    $cmd = Get-Command go -ErrorAction SilentlyContinue
    if ($cmd) { $Go = $cmd.Source } else { throw "go.exe not found. Pass -Go 'C:\path\to\go.exe' or add Go to PATH." }
}

if (-not $Gcc) {
    $cmd = Get-Command gcc -ErrorAction SilentlyContinue
    if ($cmd) {
        $Gcc = $cmd.Source
    } else {
        $winlibs = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet\Packages" -Filter "*WinLibs*" -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($winlibs) { $Gcc = Join-Path $winlibs.FullName "mingw64\bin\gcc.exe" }
    }
}
if (-not $Gcc -or -not (Test-Path $Gcc)) {
    throw "gcc.exe not found (needed for chimera.dll's CGO_ENABLED=1 c-shared build). " +
          "Install a MinGW-w64 toolchain, e.g.: winget install --id BrechtSanders.WinLibs.POSIX.UCRT -e" +
          " -- then re-run, or pass -Gcc 'C:\path\to\gcc.exe'."
}
$gccDir = Split-Path $Gcc -Parent

if (-not $Flutter) {
    $cmd = Get-Command flutter -ErrorAction SilentlyContinue
    if ($cmd) { $Flutter = $cmd.Source } else { throw "flutter not found. Pass -Flutter 'C:\path\to\flutter\bin\flutter.bat' or add it to PATH." }
}

$env:PATH = "$gccDir;$env:PATH"
$env:GOCACHE = Join-Path $repo ".gocache"
$env:GOPATH = Join-Path $repo ".gopath"
$env:GOMODCACHE = Join-Path $repo ".gomodcache"
New-Item -ItemType Directory -Force -Path $env:GOCACHE, $env:GOPATH, $env:GOMODCACHE | Out-Null

function Invoke-Go {
    Write-Host "==> go $($args -join ' ')" -ForegroundColor Cyan
    & $Go @args
    if ($LASTEXITCODE -ne 0) { throw "go $($args -join ' ') failed with exit code $LASTEXITCODE" }
}

Write-Host "==> Building chimera.dll (c-shared, tags: $Tags)" -ForegroundColor Cyan
$env:CGO_ENABLED = "1"
Invoke-Go build -buildvcs=false -buildmode=c-shared -tags $Tags -o app\windows\chimera.dll .\desktop\cffi

Write-Host "==> Building chimera.exe (CLI, tags: $Tags)" -ForegroundColor Cyan
$env:CGO_ENABLED = "0"
Invoke-Go build -buildvcs=false -tags $Tags -o app\windows\chimera.exe .\cmd\chimera

Write-Host "==> Building chimera-helper.exe (network helper service)" -ForegroundColor Cyan
Invoke-Go build -buildvcs=false -o app\windows\chimera-helper.exe .\cmd\chimera-helper

Write-Host "==> Staging wintun.dll (required for chimera tun to create the TUN device)" -ForegroundColor Cyan
Copy-Item (Join-Path $repo "third_party\wintun\amd64\wintun.dll") "app\windows\wintun.dll" -Force

Push-Location (Join-Path $repo "app")
try {
    Write-Host "==> flutter pub get" -ForegroundColor Cyan
    & $Flutter pub get
    if ($LASTEXITCODE -ne 0) { throw "flutter pub get failed" }

    Write-Host "==> flutter build windows" -ForegroundColor Cyan
    & $Flutter build windows
    if ($LASTEXITCODE -ne 0) { throw "flutter build windows failed" }
} finally {
    Pop-Location
}

$release = Join-Path $repo "app\build\windows\x64\runner\Release"
$dist = Join-Path $repo "chimera_tray"
Write-Host "==> Collecting the runnable bundle into $dist" -ForegroundColor Cyan
Remove-Item -Recurse -Force $dist -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $dist | Out-Null
Copy-Item (Join-Path $release "*") $dist -Recurse -Force

Remove-Item -Recurse -Force $env:GOCACHE, $env:GOPATH, $env:GOMODCACHE -ErrorAction SilentlyContinue

Write-Host "OK: $dist\chimera_tray.exe (run it from inside that folder -- it needs the DLLs/data next to it)" -ForegroundColor Green
