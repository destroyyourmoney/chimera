# CHIMERA app — platform feature spec (killswitch + split tunneling)

Implementation spec for two cross-cutting client features. Both are **platform-layer**
(VpnService on Android, the elevated TUN helper on desktop) — they configure how the
OS routes packets into the tunnel *before* the fd reaches the Go core, so the Go
binding (`mobile/bind.go`) stays unchanged. This environment has no Flutter/Android
SDK, so the code lands in Phase 2/3; this doc is the build contract.

## 1. Killswitch (required, MVP)

Goal: when the tunnel is meant to be up, no packet escapes outside it — including
during reconnect, failover, and process death.

### Android
- `VpnService` already routes `0.0.0.0/0` into the TUN; while the service holds the
  fd, traffic that the Go runner is not forwarding is **dropped**, not leaked. That is
  fail-closed by construction.
- Strengthen it:
  - Keep the `VpnService` (foreground service) alive across reconnects; do **not**
    tear down the fd on a carrier failover — the Go `AutoPool` re-races endpoints
    under the same fd.
  - Offer "Block connections without VPN" → guide the user to Android **Always-on VPN
    + Lockdown mode** (system setting; an app cannot fully force it, but we deep-link
    to it and detect its state).
  - On `onRevoke()` / unexpected stop: surface a blocking notification, do not silently
    fall back to direct.
- Killswitch toggle in UI maps to: (on) never call `Builder` without the default route
  and never allow `addDisallowedApplication(ownPackage)` bypass; (off) allow graceful
  teardown to direct on disconnect.

### Desktop (elevated helper)
- The helper owns routing. Killswitch = install firewall rules that **deny all egress
  except** (a) the carrier's destination IPs:443 and (b) the TUN interface:
  - Linux: `nftables`/`iptables` `OUTPUT` drop policy + allow to endpoint IPs + allow `lo`.
  - macOS: `pf` anchor with `block out` + `pass` to endpoint IPs and `utunN`.
  - Windows: **implemented** — `internal/winnet.Config.Killswitch` renders
    `Set-NetFirewallProfile -All -DefaultOutboundAction Block` plus explicit `Allow` rules
    (loopback `127.0.0.0/8`, the TUN interface alias, each resolved endpoint IP) in the
    `CHIMERA killswitch` firewall group; `tun -setup-killswitch` flag; wired into the tray's
    `NetworkProtection.enable(mode: NetworkProtectionMode.killswitch)`
    (`app/lib/network_protection.dart`) via `VpnSettingsPage`. `Restore` unconditionally
    resets `DefaultOutboundAction` to `NotConfigured` regardless of what a given `Config`
    requested, so the recovery path never depends on remembering what was turned on.
- Rules are added when the tunnel comes up and **removed only** on a clean user-initiated
  Disconnect. If the helper or app crashes with killswitch on, egress stays blocked
  (fail-closed); a recovery path ("restore networking") clears the anchor.
- Endpoint IP set is the resolved `Servers` from the active pool; update the allow-set
  on endpoint rotation (telemetry/provision hook). *(Windows: currently the snapshot taken
  at enable-time, not yet live-updated on rotation — same gap the rest of this doc's
  "later" items share.)*

## 2. Split tunneling (On/Off + app list / template)

Goal: route only chosen apps through CHIMERA (or everything-except chosen apps), with
reusable templates (pre-filled app sets).

### Data model (shared, lives in the Flutter app, persisted in secure storage)
```jsonc
{
  "splitTunnel": {
    "enabled": true,
    "mode": "include" | "exclude",   // include = only these apps tunnel; exclude = all but these
    "apps": ["com.brave.browser", "org.telegram.messenger"],
    "template": "messengers"          // optional name; templates are app-set presets
  }
}
```
Templates ship as named presets (e.g. *Messengers*, *Browsers*, *Streaming*), editable
by the user; selecting a template populates `apps`.

### Android (native, exact API)
Configure on `VpnService.Builder` **before** `establish()`:
- `mode = include` → `builder.addAllowedApplication(pkg)` for each app (only these tunnel).
- `mode = exclude` → `builder.addDisallowedApplication(pkg)` for each app (all but these).
- These are mutually exclusive per Android; never mix. Always
  `addDisallowedApplication(ownPackage)` is **not** used in include mode (would exclude us).
- Enumerate installed apps via `PackageManager.getInstalledApplications` for the picker.
- Changing the set requires re-`establish()` (new fd) → call `Stop()` then `StartFD(newFd)`.

### Desktop (elevated helper)
Per-app routing is OS-specific and harder than Android:
- Linux: cgroup v2 net_cls / `ip rule` by cgroup, or nftables `meta cgroup` marking +
  policy routing — put chosen apps' processes in a cgroup whose traffic is (include) the
  only thing routed to TUN, or (exclude) bypasses it.
- Windows: WFP app-id filters (`FWPM_CONDITION_ALE_APP_ID`) to steer per-binary.
- macOS: no clean per-app VPN routing without a NetworkExtension; desktop split-tunnel on
  macOS is **deferred** — document as best-effort/unsupported in v1, full-tunnel only.
- Helper accepts the split-tunnel JSON over its IPC and translates to the platform rules
  at tunnel-up; rebuilds rules on config change without dropping the tunnel where possible.

### UI (Mullvad-style app picker)

Reference: Mullvad's split-tunneling screen (desktop settings pane + Android app list) —
same interaction model on both platforms, adapted to Flutter for all four targets.

Layout, top to bottom:
1. Header + master **Enable** toggle (whole feature off = full-tunnel, no per-app logic
   evaluated at all — cheapest and safest default).
2. Short description line + a one-line warning that split tunneling is a privacy
   trade-off (apps outside the tunnel are **not** protected) — always visible, not just
   on first run.
3. Segmented control **Include / Exclude** bound to `splitTunnel.mode`. Switching modes
   does not clear `apps` (a user's picked set is mode-agnostic; only the routing
   direction changes).
4. Search field ("Search for…") that filters the app list below by display name as you
   type; no separate submit step.
5. Two collapsible sections, in this order:
   - **Excluded apps** / **Included apps** (label follows the active mode) — the apps
     currently in `splitTunnel.apps`, each row: icon + name + a **remove** (`−`) button.
     Section header shows a live counter, e.g. `36 out of 128` (desktop) so the user has
     a sense of scope without opening the full list.
   - **All apps** — every enumerated app not yet in the set, each row: icon + name + an
     **add** (`+`) button. Same row height/shape as the excluded list so toggling an app
     just moves its row between sections instead of restyling.
   Rows use the OS-reported app icon; fall back to a generic glyph if none.
6. Template chips (Messengers / Browsers / Streaming / custom) above or below the list —
   tapping one replaces `apps` with the preset and switches to its section view.

Android-only addition: a **Show system apps** toggle above the list (off by default) —
system packages are noisy and rarely what a user wants to split; toggling it re-runs
`PackageManager.getInstalledApplications` with `MATCH_SYSTEM_ONLY` included/excluded.

Behavioral notes:
- Add/remove is optimistic in the UI list immediately; the actual re-`establish()`
  (Android) or helper rule rebuild (desktop) is debounced (e.g. 500 ms after the last
  edit) so ticking several apps in a row doesn't restart the tunnel per-tap.
- Empty search + empty "All apps" (everything already added) collapses that section
  with an empty-state line instead of an empty box.
- macOS desktop: the whole picker still renders (for consistency and future-proofing)
  but is disabled with an inline note pointing at the §2 limitation, not hidden —
  a user should be able to see the feature exists rather than wonder if it's missing.

## 3. Operator provisioning (implemented, Go)

`internal/provision.SSHDeployer` (done): over SSH it installs git+docker, clones the
sources from GitHub (`Repo`/`Ref`), `docker build -f docker/Dockerfile --build-arg
TAGS="chimera_utls chimera_quic"`, generates the keypair **on the VPS** (private key
never leaves the box — only `CHIMERA_PUB=` is returned), runs the server container
(`--restart unless-stopped`, tcp+udp/:443), and returns chimera:// links + an
optionally HMAC-signed subscription. Shell-injection-safe (single-quoted, rejects `'`).
Host-key verification is mandatory in `SSHRunner`.

UI (Operator wizard, Phase 4) collects: VPS host, SSH user + key, steal-host, port,
short-ID count, repo/ref; streams progress; shows QR + copy/export of the subscription.
