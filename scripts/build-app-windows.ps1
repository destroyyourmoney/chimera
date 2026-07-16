param(
    [string]$Go = "C:\Program Files\Go\bin\go.exe",
    [string]$Gcc,
    [string]$Flutter,
    [string]$Iscc,
    [switch]$SkipInstaller,
    [string]$Tags = "chimera_utls chimera_quic chimera_netstack chimera_ss chimera_dot"
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

# Flutter's Windows engine (flutter_windows.dll, chimera_tray.exe itself) is
# built against MSVC and dynamically links the VC++ runtime (MSVCP140.dll,
# VCRUNTIME140.dll, ...). That runtime isn't part of a stock Windows image, so
# a clean/fresh machine fails to launch chimera_tray.exe with "The code
# execution cannot proceed because MSVCP140.dll was not found." Bundle the
# redistributable installer alongside the app so deploying to a clean machine
# is just "run vc_redist.x64.exe once, then chimera_tray.exe".
$vcRedist = Join-Path $dist "vc_redist.x64.exe"
Write-Host "==> Fetching VC++ Redistributable (needed on clean target machines)" -ForegroundColor Cyan
try {
    Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vc_redist.x64.exe" -OutFile $vcRedist -UseBasicParsing
} catch {
    Write-Warning "Could not download vc_redist.x64.exe ($($_.Exception.Message)) -- clean target machines will need it installed manually from https://aka.ms/vs/17/release/vc_redist.x64.exe"
}

Remove-Item -Recurse -Force $env:GOCACHE, $env:GOPATH, $env:GOMODCACHE -ErrorAction SilentlyContinue

Write-Host "OK: $dist\chimera_tray.exe (run it from inside that folder -- it needs the DLLs/data next to it)" -ForegroundColor Green
if (Test-Path $vcRedist) {
    Write-Host "    On a clean/fresh machine, run $dist\vc_redist.x64.exe once first (installs MSVCP140.dll etc.)." -ForegroundColor Yellow
}

# Build the single-.exe installer (scripts/windows-installer.iss) with Inno
# Setup, if available. It bundles the vc_redist prerequisite, copies the app
# to Program Files, and runs `chimera-helper.exe install` to register the
# Windows service -- so running the installer is the only manual step a
# clean machine needs, in place of the folder-copy + vc_redist +
# chimera-helper.exe install dance.
if ($SkipInstaller) {
    Write-Host "==> Skipping installer build (-SkipInstaller)" -ForegroundColor Yellow
} else {
    if (-not $Iscc) {
        $cmd = Get-Command iscc -ErrorAction SilentlyContinue
        if ($cmd) {
            $Iscc = $cmd.Source
        } else {
            # winget's per-user install (JRSoftware.InnoSetup) lands under
            # %LOCALAPPDATA%\Programs, not Program Files -- check both.
            foreach ($candidate in @(
                "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
                "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
            )) {
                if (Test-Path $candidate) { $Iscc = $candidate; break }
            }
        }
    }
    if (-not $Iscc -or -not (Test-Path $Iscc)) {
        Write-Warning "Inno Setup (ISCC.exe) not found -- skipping installer build. Install it (winget install --id JRSoftware.InnoSetup -e) or pass -Iscc 'C:\path\to\ISCC.exe', then re-run, or compile scripts\windows-installer.iss by hand."
    } else {
        Write-Host "==> Building chimera_setup.exe installer" -ForegroundColor Cyan
        New-Item -ItemType Directory -Force -Path (Join-Path $repo "dist") | Out-Null
        & $Iscc (Join-Path $repo "scripts\windows-installer.iss")
        if ($LASTEXITCODE -ne 0) { throw "ISCC.exe failed with exit code $LASTEXITCODE" }
        Write-Host "OK: dist\chimera_setup.exe (run this on a clean machine -- installs the app, VC++ runtime, and the ChimeraNetHelper service)" -ForegroundColor Green
    }
}
