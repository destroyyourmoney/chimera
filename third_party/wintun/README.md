# Wintun

`amd64/wintun.dll` is the official Wintun driver binary from
<https://www.wintun.net>, version 0.14.1 (`wintun-0.14.1.zip`,
`wintun/bin/amd64/wintun.dll`). It is loaded at runtime by
`golang.zx2c4.com/wireguard/tun` (used from `internal/tun`, build tag
`chimera_netstack`) to create the TUN device `chimera tun` needs for
full-tunnel mode -- without it next to `chimera.exe`, TUN creation fails
immediately at the Windows DLL-loader level, before any application code
(and therefore before any of `chimera.exe`'s own logging) runs.

Same driver WireGuard's own Windows client, Tailscale, and other
Wintun-based VPN clients ship. See `LICENSE.txt` in this directory for its
license (LGPLv2.1, per the upstream distribution).

`scripts/build-app-windows.ps1` copies `amd64/wintun.dll` into
`app/windows/wintun.dll` at build time, from where
`app/windows/CMakeLists.txt` bundles it into `chimera_tray/` alongside
`chimera.exe`/`chimera-helper.exe`.

To update: download a newer `wintun-<version>.zip` from
<https://www.wintun.net/builds/>, replace `amd64/wintun.dll` with the file
at `wintun/bin/amd64/wintun.dll` inside it, and update this file's version
note above.
