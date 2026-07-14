# Design Spec — gVisor Userspace-Netstack Data Path (TUN + TUN-less hardening)

> Status: **PARTLY IMPLEMENTED**. The build-gate (§4.1) PASSED on Go 1.26.4 — gVisor
> pinned at `v0.0.0-20260618175711-3c8c9b1c498a`. The netstack + TCP/UDP forwarders
> (§2, §5) are implemented in `internal/netstack` (build tag `chimera_netstack`) with
> channel-endpoint tests (§6.1–6.2). **Done:** stack, forwarders→carrier, Inject/
> ReadOutbound, tests. **Remaining:** real `wireguard/tun` device + `cmd` subcommand
> (§5, privileged), and VPN-status masking (platform shims, toolchain-blocked).
> Vendoring was removed and the ElasticCC quic-go patch moved to `third_party/quic-go`
> via `replace` (a `go mod vendor` would otherwise wipe the patch when adding gVisor).

## 1. Why these items are the same work

A TUN device hands the process **raw IP packets**, not connections. To proxy them
through CHIMERA's carrier (which speaks `CONNECT host:port` and UDP associations,
not IP), something must turn IP packets into TCP/UDP flows — i.e. a **userspace
TCP/IP stack**. Hand-rolling that is absurd; the standard answer is **gVisor's
`netstack`** (`gvisor.dev/gvisor/pkg/tcpip`). So:

- "TUN framing" = TUN device → netstack → per-flow → carrier.
- "TUN-less + VPN-status masking" = the *same* netstack fed from a userspace packet
  source (or a TUN whose presence is masked), with the SOCKS path as today.

The flow-dispatch layer reuses **exactly the carrier APIs that already exist**:
`carrier.DialConnect` (TCP) and `carrier.UDPCarrier`/`QUICDialUDP` (UDP, built this
session). The netstack only adds packet→flow translation in front of them.

## 2. Architecture

```
TUN device (utun/wintun)        ┐
  or userspace packet fd        ├─► gVisor netstack (stack.Stack + link endpoint)
                                ┘        │
                            tcp.Forwarder│  udp.Forwarder
                                         ▼
                          flow (dstHost, dstPort, proto)
                                         ▼
        TCP → carrier.DialConnect(host,port)  → io.Copy both ways
        UDP → carrier.UDPCarrier.OpenAssoc/Send/Receive (FEC datagrams)
```

- **Link endpoint:** `channel.Endpoint` (test/userspace) or an fd endpoint bound to
  the TUN device. Packets in/out as `[]byte` IP frames.
- **TCP:** `tcp.NewForwarder(stack, rcvWnd, maxInFlight, handler)`. The handler
  reads the requested `id.LocalAddress:LocalPort` (the original destination),
  `r.CreateEndpoint`, wraps as `gonet.TCPConn`, dials `carrier.DialConnect`, relays.
- **UDP:** `udp.NewForwarder` similarly; each flow maps to a `carrier.UDPCarrier`
  association keyed by destination (the multiplexer built in `udpclient.go`).
- **Routing:** install a default route + a NIC; enable SACK; set a sensible MTU
  (≤ carrier path MTU minus QUIC/datagram overhead).

## 3. VPN-status masking (Этап 5 criterion)

RU app-side VPN detection typically checks for: a default-route TUN/utun interface,
`NEPacketTunnelProvider`/`VpnService` presence, or a SOCKS proxy env. The TUN-less
SOCKS path (today) already avoids a system VPN interface. The netstack lets us go
further when a TUN *is* used: bind the netstack to a packet fd without marking a
system-wide default-route VPN where the platform allows, and keep per-app/split
routing so the device does not look like a full-tunnel VPN. Concrete masking tactics
are platform-specific and belong in the platform shims (Этап 4 mobile/desktop),
which are toolchain-blocked here.

## 4. Dependency risk — the real blocker

`gvisor.dev/gvisor` is **large and build-fragile**: heavy use of build tags,
generated code, and sensitivity to the Go toolchain version. This repo currently
runs **Go 1.26.4** (very new); gVisor upstream may not yet support it cleanly. This
is the dominant risk and must be de-risked FIRST:

1. **Spike:** in a throwaway branch, `go get gvisor.dev/gvisor@<pinned>` and build a
   minimal `stack.Stack` + `channel.Endpoint` + `tcp.Forwarder` that dials a local
   echo. Confirm it compiles and passes under Go 1.26.4. **Pin the exact version.**
2. If upstream gVisor fails on Go 1.26.x: either pin a Go version for a build tag, or
   vendor a patched gVisor (precedent: we vendor quic-go) — expensive; reconsider.
3. Only after the spike compiles do we wire the forwarders to the carrier.

`wireguard/tun` (for the actual device) is small and low-risk; it is the gVisor link
side, not the stack.

## 5. Integration points

- New package `internal/netstack` (build tag, e.g. `chimera_netstack`, so the
  default binary never imports gVisor — same isolation pattern as `chimera_quic`).
  - `Stack` constructor: NIC + routes + TCP/UDP forwarders.
  - TCP handler → `carrier.DialConnect`; UDP handler → `carrier.UDPCarrier`.
- New `internal/tun` (build-tagged): `wireguard/tun` device open + read/write loop
  feeding the netstack link endpoint. Device creation needs privileges (root/utun on
  macOS, CAP_NET_ADMIN on Linux) — so device-level e2e is a privileged/CI concern.
- `cmd/chimera`: a `tun` subcommand (or `-mode tun`) gated behind the build tag.
- Reuses `endpoint.Pool`/`AutoPool` as the carrier dialer (failover/transport auto).

## 6. Test plan (no privileges, no real device)

The netstack is fully testable WITHOUT a TUN device by driving the `channel.Endpoint`
directly:

1. **TCP forward:** craft/drive a TCP flow into the channel endpoint to a virtual
   dst; assert the handler dials the carrier and relays bytes to a loopback echo
   (use gVisor's `gonet` client helpers to avoid hand-crafting packets).
2. **UDP forward:** same against a UDP echo, asserting datagrams traverse the
   `carrier.UDPCarrier` association (reuses this session's UDP e2e shape).
3. **MTU/edge:** oversized payloads, half-open close, simultaneous flows.
4. Device-level (TUN) relay tested only in a privileged CI lane; logic tested via
   the channel endpoint above. Run all under `-race`.

## 7. Effort & risk

| Item | Effort | Risk |
|---|---|---|
| gVisor build spike on Go 1.26.4 (gate) | Low–Med | **High** (toolchain compat) |
| netstack TCP/UDP forwarders → carrier | Med | Med |
| `wireguard/tun` device + read/write loop | Med | Med (privileges for e2e) |
| channel-endpoint test harness | Med | Low |
| VPN-status masking (platform shims) | High | Blocked (mobile/desktop toolchains) |

## 8. Recommended order (when approved)

1. **gVisor spike + version pin** (gate — do not proceed if it won't build on 1.26.4).
2. `internal/netstack` TCP forwarder → `carrier.DialConnect`; channel-endpoint test.
3. UDP forwarder → `carrier.UDPCarrier`; channel-endpoint test.
4. `internal/tun` device + `cmd` subcommand (logic tested via channel endpoint;
   device e2e in privileged CI).
5. VPN-status masking — defer to the platform shims (Этап 4, toolchain-blocked).
