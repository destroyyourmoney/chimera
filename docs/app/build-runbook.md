# CHIMERA app — build runbook

Cross-platform client (Windows/macOS/Linux/Android) + operator console, built on
the Go core via a thin binding surface. iOS is out of scope for this iteration.

## Architecture (decided)

- **UI:** one Flutter project, 4 targets.
- **Core:** existing Go code, called through `mobile/` (gomobile → AAR for Android)
  and `desktop/cffi/` (`dart:ffi` via a `-buildmode=c-shared` `chimera.dll`+`chimera.h`
  pair — see the Build commands note below on why `c-shared`, not `c-archive`, Phase 3,
  Windows done).
- **App modes:** one app, Operator + Subscriber, gated by stored operator creds.
- **Provisioning:** SSH into operator's own VPS, install Docker, run server container.
- **Tunnel scope:** desktop system-wide TUN (+ SOCKS fallback); Android `VpnService` TUN.

## Binding surface (Phase 1 — done)

The **only** Go surface the UI calls is `mobile/bind.go` (`package chimeramobile`),
a facade over `internal/api`. `desktop/cffi/main.go` (Phase 3 groundwork, done —
see below) is a thin cgo wrapper exposing this exact same `Tunnel` lifecycle as a
C ABI for `dart:ffi`, so Android and desktop share one lifecycle and one JSON
state-snapshot shape; only the FFI mechanism differs:

| Method | Purpose |
|---|---|
| `NewTunnel(subscriptionText, signKeyHex)` | Build from a `#!chimera-subscription-v1` doc; verifies HMAC if signed |
| `NewTunnelFromLink(uri)` | Build from a single `chimera://` link (QR-scan path) |
| `Connect()` | Set up endpoint pool + verify reachability (fast, non-blocking) |
| `StartFD(fd, mtu)` | **Blocks**: full-device VPN over an OS TUN fd (Android/desktop helper) |
| `StartSocks(listen)` | **Blocks**: TUN-less SOCKS5 fallback |
| `Stop()` | Cancel runner + tear down; reusable afterwards |
| `StateJSON()` | Poll-friendly JSON snapshot (state, transport, bytes, per-endpoint health) |
| `ParseLink(uri)` | Parse a link → JSON for the "add server" UI |

`StartFD`/`StartSocks` block by design (they match the platform VPN thread model);
run them on a background thread and drive the UI off `StateJSON()` polled ~1s.

gomobile rules honored: only primitives + the package's own pointer types cross
the boundary; rich state travels as JSON.

## Build commands

**`c-archive` vs `c-shared` note**: a `c-archive` (`.a`/`.lib`) is a *static*
archive meant to be linked into a C/C++ host binary at compile time — it is
not something `dart:ffi`'s `DynamicLibrary.open()` can load at runtime. The
Flutter app loads `chimera.dll`, built with `-buildmode=c-shared` (same
`desktop/cffi/main.go` source, different flag). `c-archive` is kept as a
build-verification artifact (what the Docker/native-Windows checks below
build) and would matter again only if a native C++ Flutter plugin wrapper is
ever built instead of dart:ffi.

```bash
export PATH="$HOME/.local-go/go/bin:$PATH"; export GOTOOLCHAIN=local   # go not on PATH

# Sanity: default, tagged, and netstack builds
CGO_ENABLED=0 go build ./...
CGO_ENABLED=0 go build -tags "chimera_utls chimera_quic" ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags "chimera_utls chimera_quic chimera_netstack" ./...
go test -race ./internal/api/...

# Android AAR (needs Android SDK+NDK + gomobile)
go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init
gomobile bind -target=android \
  -tags "chimera_utls chimera_quic chimera_netstack" \
  -o app/android/libs/chimera.aar ./mobile

# Desktop c-archive (needs a C compiler; CGO_ENABLED=1 — with CGO_ENABLED=0
# `desktop/cffi` is silently excluded from `go build ./...`, so this doesn't
# break the CGO_ENABLED=0 sanity builds above)
CGO_ENABLED=1 go build -buildmode=c-archive \
  -tags "chimera_utls chimera_quic chimera_netstack" \
  -o desktop/cffi/chimera.a ./desktop/cffi   # produces chimera.a + chimera.h

# Desktop c-shared (what the Flutter Windows app actually loads via
# dart:ffi's DynamicLibrary.open -- a c-archive is a static-link artifact,
# not something dart:ffi can open at runtime; same desktop/cffi/main.go
# source, just a different `go build` flag)
CGO_ENABLED=1 go build -buildmode=c-shared \
  -tags "chimera_utls chimera_quic chimera_netstack" \
  -o app/windows/chimera.dll ./desktop/cffi   # produces chimera.dll + chimera.h

# Flutter Windows tray app (app/) -- needs Flutter SDK + VS Build Tools
# "Desktop development with C++" workload (Microsoft.VisualStudio.Workload.VCTools
# for the standalone BuildTools SKU specifically, not .Workload.NativeDesktop --
# that ID is for the full VS IDE product and silently no-ops on BuildTools)
cd app && flutter pub get && flutter build windows
# -> build/windows/x64/runner/Release/chimera_tray.exe (+ chimera.dll copied
#    alongside via windows/CMakeLists.txt's install(FILES ...) rule)
```

Boot client builds with `-tags "chimera_utls chimera_quic chimera_netstack"`:
real Chrome ClientHello + TLS-1.3 takeover, QUIC/ElasticCC carrier, gVisor TUN.

### ⚠ Pitfall: server and client MUST share the same `chimera_utls` build tag

`internal/carrier/transport_reality.go` (`//go:build chimera_utls`) and
`transport_plain.go` (`//go:build !chimera_utls`) are two genuinely different
wire protocols on the same TCP port: the tagged build does a real uTLS-driven
TLS 1.3 Reality handshake; the untagged build does a plaintext byte-splice
with just the auth tag embedded in `SessionID`. The server's byte-splice auth
check (SessionID tag) succeeds either way — a `chimera_utls`-tagged client
against an **untagged** server (or vice versa) logs `"auth ok -> tunnel"` on
the server side, then the client hangs forever inside `Session.Connect()`
waiting for TLS records the server never sends. There is no error, no
timeout, no log line on the client side — it just blocks indefinitely.

This is easy to hit by accident: e.g. building a quick local test server with
plain `go build ./cmd/chimera` (no tags) and then pointing a
`chimera_utls`-tagged client (`desktop/cffi`'s `chimera.dll`, or any
`gomobile`/CLI build using the tags above) at it. **Always build the test
server with the exact same `-tags` as the client you're testing against.**
If `ChimeraConnect`/`chimera health`/`carrier.Ping` hangs with no error and
the server log shows the peer authenticated, this mismatch is the first
thing to check — not a cgo/dart:ffi bug (confirmed by reproducing the same
hang with a pure-C harness calling the DLL directly, bypassing Dart
entirely, then fixing it purely by rebuilding the server with matching tags).

### `chimera.exe` bundling (DNS-leak-guard toggle)

`app/windows/CMakeLists.txt` optionally bundles a `chimera.exe` (same tags as
above) next to `chimera.dll` and `chimera_tray.exe` if present at
`app/windows/chimera.exe` at build time — the tray app's DNS-leak-guard
toggle (`app/lib/dns_leak_guard.dart`) shells out to it (`chimera tun
-setup-elevate -setup-os -setup-firewall` / `-setup-restore`) rather than
reimplementing `internal/winnet`'s firewall/elevation logic in Dart. Build it
the same way as the desktop c-shared step above, just without `-buildmode`:

```bash
CGO_ENABLED=0 go build -tags "chimera_utls chimera_quic chimera_netstack" \
  -o app/windows/chimera.exe ./cmd/chimera
```

## Decided (operator answers, 2026-06-24)

1. **Server image**: built **on the VPS** from GitHub sources during provisioning —
   implemented in `internal/provision.SSHDeployer` (clone → `docker build` → run). No
   CI registry needed.
2. **Killswitch**: required in MVP. Spec in `docs/app/platform-features.md` §1.
3. **Split tunneling**: On/Off + include/exclude app list + templates. Spec in
   `docs/app/platform-features.md` §2.

## Next phases

2. Subscriber MVP, Android first: Kotlin `VpnService` plugin → `establish()` fd →
   `StartFD`. Foreground service + notification, **killswitch** (fail-closed) and
   **split-tunnel** (`addAllowed/DisallowedApplication`) configured on the Builder.
   Flutter Connect/Disconnect + status.
3. Subscriber desktop:
   ✅ **`desktop/cffi` (Go side, done)** — cgo wrapper over `mobile.Tunnel`, same
   9-function surface as the binding-surface table above, `runtime/cgo.Handle`-based
   lifecycle; verified via a real native Windows build (MinGW-w64) linked and run
   against a throwaway C harness, plus a Docker/Linux build+`go test` pass — both
   green, 0 failures.
   ✅ **Minimal Windows tray app (`app/`), done and functionally verified end-to-end.**
   Flutter SDK + VS Build Tools (`Workload.VCTools` + Windows 11 SDK) installed;
   `flutter create --platforms=windows` scaffolded `app/`; `chimera.dll` built via
   `-buildmode=c-shared` (not `c-archive` -- see the note above); `app/lib/chimera_bindings.dart`
   (typed dart:ffi signatures for all 9 exports) + `app/lib/chimera_service.dart`
   (owns the handle lifecycle, runs the blocking `StartSocks` call on a spawned
   `Isolate` since dart:ffi calls block their calling isolate, polls `StateJSON`
   every 1s) + `app/lib/main.dart` (`tray_manager` icon/context-menu, `window_manager`
   hidden-by-default settings window, `path_provider`-persisted pasted link).
   `flutter analyze`: 0 issues. `flutter build windows`: succeeds, `chimera.dll`
   lands next to `chimera_tray.exe` via a `windows/CMakeLists.txt install(FILES ...)`
   rule. **Real e2e proof** (not just "it launches"): built a real `chimera.exe`,
   ran a real `chimera server` on loopback, drove the *exact* `ChimeraService` class
   the tray UI uses (via a throwaway `dart run` script exercising the same code
   path, since this sandbox has no GUI-automation tool to literally click the tray
   menu) through `NewTunnelFromLink` → `Connect` → `StartSocks`, then issued a real
   `curl --socks5-hostname` HTTPS request through the resulting SOCKS5 listener:
   `http_code=200`, 201 KB of real content — the full chain (Flutter/Dart → dart:ffi
   → `desktop/cffi` → `mobile.Tunnel` → `internal/api` → real carrier → real server)
   works, reproducible across two consecutive connect/disconnect cycles.
   ⚠ Still open (later phases, matches the doc's own ordering): elevated TUN helper
   for full-device tunneling on Windows (today's tray only drives the TUN-less SOCKS5
   fallback — `internal/api.Session.ConnectTUN` is gated to linux/darwin, a
   pre-existing `internal/api` limitation this task didn't touch), firewall-based
   killswitch, per-app routing, macOS/Linux targets, code signing.
4. Operator wizard UI over `internal/provision.SSHDeployer` (Go side done): host/key/steal
   inputs, progress stream, signed-subscription + QR output, fleet management.
5. Polish: subscription auto-refresh, code-signing/notarization, CI matrix.

## Open items

- gVisor/quic-go AAR size — verify it fits the APK budget on first `gomobile bind`.
- macOS desktop split-tunnel needs a NetworkExtension; v1 ships full-tunnel only there.
