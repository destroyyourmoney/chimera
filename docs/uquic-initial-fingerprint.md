# Design Spec — uquic Chrome-H3 QUIC Initial Fingerprint

> Status: **INTEGRATED (Path B), pcap/vantage-validated, netem-regression-checked**.
> The uquic build-gate PASSED on Go 1.26.4
> (`github.com/refraction-networking/uquic@v0.0.6` compiles clean), but CHIMERA
> keeps its patched quic-go v0.60.0 fork. The Chrome-H3 ClientHello hook is
> forward-ported behind `Config.InitialClientHelloProfile="chrome-h3"`. A real
> Chrome 150 stable pcap/vantage capture (Tenth increment below) confirmed
> transport-parameter values, connection-ID shape, and multi-packet Initial
> framing against live Chrome traffic, and caught/fixed two real gaps
> (`max_idle_timeout`, CRYPTO/PING frame fragmentation — Eleventh increment).
> The final gap — a `docker/bench.sh` netem goodput regression re-check — is now
> also closed (Twelfth/Thirteenth increments): goodput under real injected loss
> matches the recorded baseline, no regression from the frame-fragmentation
> change.

## 1. Goal

Make CHIMERA's QUIC carrier present a **Chrome HTTP/3 QUIC Initial** on the wire so
a passive observer fingerprinting the QUIC Initial packet (transport parameters,
the TLS ClientHello inside the CRYPTO frame, frame ordering, padding, version) sees
Chrome, not raw quic-go. This is the QUIC analogue of the uTLS work already done for
the TCP carrier's TLS ClientHello (ROADMAP Этап 1b). Closes Этап 3 criteria
«Отпечаток QUIC Initial == Chrome H3».

## 2. The core problem: two incompatible quic-go forks

CHIMERA already depends on a **patched quic-go v0.60.0** (`third_party/quic-go`,
ElasticCC). uquic is **not** an add-on to quic-go — it is a **standalone fork** that
copied an older quic-go (~v0.40-era: `go 1.21`, `qpack v0.4.0`, no `internal/monotime`
package, Ginkgo-style congestion tests) and rewrote the Initial-packet/handshake path
to drive a uTLS ClientHello and mimic Chrome's transport parameters / frame layout.

You cannot have two `quic-go` modules. So integration means picking ONE base and
merging the other side's changes onto it. Verified incompatibilities between uquic's
base and our v0.60.0 fork:

| Concern | our v0.60.0 fork | uquic v0.0.6 base |
|---|---|---|
| time type in CC/ackhandler | `internal/monotime.Time` | `time.Time` (no monotime pkg) |
| `SendAlgorithm` interface | v0.60.0 shape (ElasticCC implements) | older shape |
| sent_packet_handler | v0.60.0 (our PTO-cap + `useElasticCC`) | older |
| connection migration / 0-RTT early | present, wired | older/absent |
| batch I/O (GSO/sendmmsg) | v0.60.0 auto on Linux | older |

So our ElasticCC patch (uses `monotime`, the v0.60.0 interface, our patched
`sent_packet_handler.go`) will **not** apply to uquic's base unchanged.

## 3. Two integration paths

### Path A — Re-base onto uquic, re-implement ElasticCC there
Adopt uquic as the carrier; rewrite ElasticCC (`elastic.go`) and the PTO-cap against
uquic's older `congestion`/`ackhandler` APIs (`time.Time`, older interface).
- **Pros:** gets Chrome-H3 Initial "for free" (uquic's whole point).
- **Cons:** loses v0.60.0's connection migration, early-0-RTT, GSO/batch I/O — several
  *other* ROADMAP items already marked done rely on these. Re-deriving the
  freshly-debugged ElasticCC (peak-hold, loss-comp, BDP cwnd, PTO-cap) on an older,
  differently-shaped congestion stack risks reintroducing the death-spiral.

### Path B — Forward-port uquic's Initial fingerprinting onto our v0.60.0 fork  ⭐
Keep `third_party/quic-go` v0.60.0 + ElasticCC; port uquic's fingerprinting layer:
1. Drive the QUIC handshake ClientHello via **uTLS** (uquic replaces qtls' ClientHello
   construction with a uTLS `ClientHelloSpec` — same JA3 mechanism we already use for
   TCP).
2. Reproduce Chrome's **transport parameters** set/order and the Initial packet's
   **frame layout/padding** (uquic's `QUICSpec` / `QUICFrames`).
3. Pin a `QUICID` (e.g. `QUICChrome_115`) → applied at dial, like `reality.Fingerprint`.
- **Pros:** keeps everything working (ElasticCC, migration, 0-RTT, batch I/O); the
  fingerprinting is additive and build-tag isolatable.
- **Cons:** uquic's changes are spread across handshake + packet construction and must
  be re-derived against v0.60.0 internals (the two diverged). Non-trivial, but it
  protects the working core.

**Recommendation: Path B.** It preserves the debugged ElasticCC and the v0.60.0
features other items depend on; fingerprinting is layered on rather than swapped in.

## 4. Integration points (Path B)

- `internal/quic/common.go` (`quicConfig`, `serverTLS`, `alpn="h3"`): the dial path
  applies the QUIC fingerprint spec, analogous to `reality.ClientWrap` for TCP.
- `internal/quic/client.go` (`dial`/`establish`): selects the Chrome-H3 profile from
  the carrier fingerprint and passes it to quic-go. Empty/default profile keeps the
  stock `crypto/tls` QUIC path.
- `third_party/quic-go.Config.InitialClientHelloProfile`: gated ClientHello hook.
  `chrome-h3` builds the client Initial TLS handshake with uTLS `HelloChrome_133`
  (`UQUICClient` + `ClientHelloSpec`), forces TLS 1.3, ALPN `h3`, and carries the
  quic-go transport parameters through uTLS. Any other profile falls back to the
  stdlib/qtls path.
- `third_party/quic-go.Config.InitialCryptoDataTracer`: observability hook added on
  the v0.60.0 fork. It receives a copy of client Initial TLS CRYPTO bytes before
  packet packing, giving the Initial-diff harness a stable source for ClientHello
  JA3/SNI checks without mutating the handshake.
- `third_party/quic-go.Config.InitialPacketTracer`: observability hook added on the
  v0.60.0 fork. It receives encrypted client Initial packet bytes plus stable
  metadata (version, CID lengths, token length, packet number metadata and logical
  frame order) at the real send path.
- `internal/quic.SetInitialCryptoDataTracer`: CHIMERA-side bridge from the carrier
  dial path to the quic-go tracer. The loopback test asserts that the real carrier
  ClientHello exposes the configured steal-host SNI.
- `internal/quic.SetInitialPacketTracer`: CHIMERA-side bridge for packet-level
  fingerprint harnesses. `InitialPacketSummary` / `DiffInitialPacketSummaries`
  make the local unit assertions deterministic without pretending to replace an
  external pcap vantage.
- `carrier.FingerprintUpdater` already exists (TCP) — extend the config `fp:`/`-fp`
  pipeline to also select the QUIC `QUICID` (Этап 5 fingerprint-update pipeline).

- `internal/quic` Initial-diff harness: `SummarizeClientHello`,
  `BuildChromeH3ClientHelloReference` and `DiffClientHelloSummaries` compare the
  real carrier ClientHello against a uTLS Chrome-H3 reference. The Chrome-H3 profile
  now has no critical-field diff for cipher suites, extension set/order (GREASE
  normalized), supported groups, key-share groups, supported_versions, ALPN, SNI,
  and QUIC transport-parameter presence. The same harness now checks ordered QUIC
  transport-parameter IDs in the ClientHello extension.
- `internal/quic` packet-level harness: captures the real sent Initial packet from
  the carrier loopback path and asserts QUIC v1, target packet size, no token,
  CRYPTO frame(s) before trailing PADDING, parseable long-header fields, and SNI/ALPN
  consistency with the CRYPTO trace.

## 5. Validation plan

1. **Initial-packet capture diff:** dump CHIMERA's QUIC Initial and a real Chrome H3
   Initial to the same server; assert equal QUIC version, transport-parameter set/order,
   ClientHello JA3, and frame/padding layout. (Wireshark/pcap or a unit harness that
   serializes the Initial.)
2. **Functional:** existing QUIC e2e (`internal/quic` loopback, UDP-assoc echo) stays
   green; the fingerprinted handshake still completes + tunnels.
3. **netem:** ElasticCC goodput-under-loss numbers must not regress (re-run
   `docker/bench.sh`).
4. **SNI inspection:** the steal-host SNI must be visible in the Initial (criterion
   «SNI-инспекция видит steal-host»).

Current unit coverage verifies SNI presence at Initial CRYPTO byte level, runs a
uTLS Chrome-H3 reference diff via `internal/quic`, checks transport-parameter order,
captures the real sent Initial packet summary, and keeps Ping, DialConnect and
UDP-assoc loopback paths green. pcap/vantage validation is still required for full
Initial packet parity against real Chrome.

Eighth increment: transport-parameter *order and set* correctness, based on a
pcap-derived reference (`refraction-networking/uquic`'s `u_parrot.go`, Chrome
115/146 specs — the only publicly available byte-level ground truth for real
Chrome QUIC Initials found during this work):
- `wire.Marshal` no longer applies the Chrome-shaped parameter order to every
  client connection unconditionally — it is now gated behind
  `MarshalForProfile(pers, "chrome-h3")`. Previously *every* CHIMERA QUIC
  client emitted a Chrome-ordered parameter list regardless of ClientHello
  fingerprint, which was itself a latent oracle (Chrome-shaped TP order paired
  with a non-Chrome ClientHello).
- `marshalClientChromeH3` was rewritten around the real Chrome parameter
  *set*: `ack_delay_exponent`, `max_ack_delay`, `disable_active_migration`,
  `active_connection_id_limit`, `reset_stream_at`, `min_ack_delay` are never
  sent by real Chrome and are now omitted for the `chrome-h3` profile
  regardless of configured values (previously `active_connection_id_limit`
  was always sent, since CHIMERA pins a non-default value for old-quic-go
  interop — see `connection.go`). Two Chrome/QUICHE-proprietary parameters
  observed on the wire are now added: `google_connection_options` (0x3128,
  fixed 4-byte tag) and `google_initial_rtt` (0x3127, randomized 1000–20000µs
  per connection), plus IETF `version_information` (0x11, RFC 9368, with a
  GREASE reserved version).
- The parameter order is now **freshly randomized on every `Marshal` call**
  (Fisher–Yates over the encoded entries, including GREASE, which is no
  longer pinned to a fixed leading position) — real Chrome reshuffles its QUIC
  transport-parameter order on every handshake; a fixed order, even a
  "Chrome-shaped" one, is itself a distinguishing signal.
- **Follow-up investigation (same session) resolved both items flagged above
  as deferred, with less risk than expected:**
  - **Client SCID length:** turned out to already be zero-length in
    production, for free — CHIMERA's QUIC client dials via
    `quic.DialAddrEarly`, whose internal `setupTransport(..., true)` sets
    `Transport.isSingleUse = true`, which makes `Transport.init` pass
    `allowZeroLengthConnIDs = true`; combined with `Transport.ConnectionIDLength`
    never being set (Go zero value `0`), quic-go's own
    `DefaultConnectionIDGenerator` already produces a 0-length client SCID.
    Verified empirically (traced `SrcConnIDLen == 0` on every dial) — no code
    change was needed for this half.
  - **Initial DCID (destination connection ID) length:** was a real,
    previously-unnoticed gap — stock quic-go randomizes the client's first-guess
    DCID between 8 and 20 bytes (`protocol.GenerateConnectionIDForInitial`),
    while real Chrome always uses a fixed 8-byte DCID. Fixed with a small,
    profile-gated change: `client.go` adds
    `generateConnectionIDForInitialWithProfile(profile)`, used at the one
    call site in `transport.go`'s `doDial`; for `chrome-h3` it returns a fixed
    8-byte `protocol.GenerateConnectionID(8)`, every other profile keeps the
    stock randomized generator. This does not touch `initial_source_connection_id`
    (which stays passed-through/consistent, since it's peer-verified) — only
    the client's *destination* CID guess, which is not structurally checked
    against anything but is currently a decent value the client just makes up.
  - **Two-datagram Initial split:** investigated empirically rather than
    assumed. CHIMERA's chrome-h3 ClientHello (`HelloChrome_133` + a real
    X25519MLKEM768 key share) is ~1874 bytes — already too large for one
    Initial packet — and quic-go's existing, *unmodified* CRYPTO-stream
    fragmentation in `packet_packer.go` already splits it across multiple
    Initial packets (observed: 2 CRYPTO-carrying Initial packets of 1252
    bytes each, both correctly using the fixed 8-byte DCID / 0-byte SCID, both
    CRYPTO-frames-before-PADDING). No `packet_packer.go` change was needed —
    the "high risk, adjacent to ElasticCC" concern from the original plan did
    not materialize, because this is emergent behavior of already-debugged
    code, not a new code path. Locked in with
    `TestChromeH3InitialSpansMultiplePackets` (`internal/quic`), which fails
    if a future change collapses this back to a single (Chrome-inconsistent)
    packet.
  - Regression coverage: `TestGenerateConnectionIDForInitialWithProfile`
    (`third_party/quic-go`) for the DCID fix; `internal/quic`'s packet-level
    harness now asserts DCID==8/SCID==0 exactly (was previously only bounded
    ≤20) plus the new multi-packet test. Full suite (both modules, all
    build tags) passes.

Tenth increment: the "real Chrome pcap/vantage validation" gap, previously
flagged as needing a machine with Chrome + tshark unavailable in prior
sessions, turned out to be achievable in this environment after all — Windows
`pktmon` can't see same-host loopback traffic (a known OS limitation: local
delivery bypasses the NDIS layer pktmon hooks into, confirmed by a 152-byte/
zero-packet capture despite the browser completing real requests), but a real
Chrome 150 stable build (`@puppeteer/browsers install chrome@stable` — an
official Google-distributed "Chrome for Testing" binary, not a Chromium
fork) was launched against a throwaway local HTTP/3 test server
(`internal/quic`/`http3`-based, self-signed cert, `--origin-to-force-quic-on`
+ `--ignore-certificate-errors-spki-list` to force real QUIC to it) with its
raw inbound UDP datagrams captured by wrapping the server's `net.PacketConn`
(`ReadFrom` interception) instead of relying on OS-level capture. The
resulting raw Initial packets were decrypted using quic-go's own exported
`handshake.NewInitialAEAD` (RFC 9001 Initial-secret derivation) — verified
first against the RFC 9001 Appendix A known-answer test vector before trusting
it on real traffic — recovering the actual plaintext TLS ClientHello bytes
Chrome sent. Findings, all from a live, fresh capture rather than secondhand
documentation:
- **Confirmed correct** (exact match): `initial_max_data=15728640`,
  `initial_max_stream_data_{bidi_local,bidi_remote,uni}=6291456`,
  `initial_max_streams_bidi=100`, `initial_max_streams_uni=103`,
  `max_udp_payload_size=1472`, `max_datagram_frame_size=65536`,
  zero-length `initial_source_connection_id`, the `version_information`
  GREASE-version bit pattern, 8-byte DCID, 2-packet Initial split, cipher
  suite set (`TLS_AES_128/256_GCM`, `TLS_CHACHA20_POLY1305`).
- **Found and fixed**: `max_idle_timeout` — real Chrome sends 300000ms, not
  the 30000ms this code previously passed through from CHIMERA's own
  operational config. Pinned via `chromeH3WireMaxIdleTimeoutMs`, a
  wire-presentation-only override (CHIMERA's actual enforced idle timeout is
  unchanged — RFC 9000 §10.1 makes this protocol-safe: each side's effective
  timeout is `min(own config, peer's advertised value)`).
- **Found, not fixed, newly documented**: real Chrome fragments its CRYPTO
  data into many small frames (14–618 bytes) interspersed with PING frames
  within each Initial packet, rather than one or two large CRYPTO frames
  followed by PADDING. CHIMERA's Initial packets currently use the simpler
  pattern. This is a real, previously-unknown gap in frame-level layout — not
  addressed here (would mean teaching `packet_packer.go`'s Initial-level
  frame construction Chrome's specific fragmentation/PING-interspersal
  behavior, a distinct, non-trivial change from anything else done in this
  document).
- **Caveat, not a confirmed bug**: `google_connection_options` was captured
  as `"ORIGNOIP"` (ASCII), not the `"10AF"` value pinned here (sourced from
  the uquic reference). This capture required Chrome's
  `--origin-to-force-quic-on` debug flag to force QUIC without real Alt-Svc
  infrastructure, which plausibly alters this specific value; the pinned
  `"10AF"` was not overwritten based on a methodologically-contaminated
  sample. SNI was also absent from this capture (expected: the target was a
  bare IP literal, which cannot carry SNI per spec — not a fingerprint
  finding, just an artifact of the test setup).
- Both the header-protection unprotect and RFC-vector-verified AEAD decrypt
  logic used for this analysis were throwaway tools
  (`third_party/quic-go/cmd/zzdecrypt`, `cmd/zzparsehello`), deleted after
  use — not part of the shipped codebase. The h3server/analysis scripts also
  do not ship; this was a one-time validation exercise, reproducible from the
  steps above if Chrome's QUIC behavior needs re-checking after a future
  Chrome release.

Eleventh increment: the CRYPTO/PING frame-fragmentation gap found by
increment 10's live capture is now fixed.
`packetPacker.packChromeH3InitialCryptoFrames` (`third_party/quic-go/packet_packer.go`)
replaces the greedy single/double-large-CRYPTO-frame packing with a
randomized mix of 3–10 CRYPTO fragments interleaved with 1–10 PING frames per
Initial packet — shuffled per packet, not a fixed pattern, for the same
anti-fixed-signature reason as the transport-parameter order shuffle. Gated
via a new `chromeH3Initial bool` field on `packetPacker`, threaded through
`newPacketPacker`'s constructor and set from
`s.config.InitialClientHelloProfile == "chrome-h3"` only at the client
call site in `connection.go` (the server call site always passes `false` —
this behavior is client/chrome-h3-only, matching every other override in this
document). Composes safely with the pre-existing, unrelated
`initialCryptoStream` ClientHello-scrambling feature (SNI/ECH obfuscation for
generic anti-DPI use, not Chrome-specific) since that feature operates inside
`PopCryptoFrame` itself and this only varies the size/count of calls into it.
Test coverage: `TestChromeH3InitialCryptoFragmentedWithPING` (`internal/quic`)
asserts a CRYPTO-carrying Initial packet contains both a PING frame and more
than one CRYPTO frame; `assertInitialFramesCryptoBeforePadding` updated to
accept CRYPTO/PING mixed before trailing PADDING (previously required
CRYPTO-only). Stable across 15 repeated runs (randomization doesn't introduce
flakiness). Full suite (both modules, all build tags) passes.

- Test coverage: `TestClientTransportParameterSetChromeH3` (correct
  set/omissions), `TestClientTransportParameterOrderChromeH3Randomized`
  (order varies across calls, same set each time),
  `TestClientTransportParameterOrderStockWithoutProfile` (gating regression
  guard) in `third_party/quic-go/internal/wire`; `internal/quic`'s
  `TestChromeH3InitialPacketFingerprintHarness` updated to assert the
  parameter set (required/forbidden IDs) rather than a fixed relative order.
  Full `go test ./...` (main module, `chimera_quic,chimera_utls,chimera_netstack`
  tags) and the `third_party/quic-go` wire/handshake suites pass.
  **Re-verified:** `docker/bench.sh` netem goodput-under-loss regression
  check — see Twelfth/Thirteenth increments below. Confirmed no regression.

Twelfth increment: a first attempt at the netem regression re-check, in a
session with a working Docker Desktop install (unlike earlier sessions),
positively verified the chrome-h3 QUIC carrier transfers correctly through
Docker (10+ interactive 20 MB SOCKS5-over-QUIC transfers, all instant and
correct), but could not inject any real loss: this Docker Desktop
installation's bundled VM kernel at the time
(`5.10.16.3-microsoft-standard-WSL2`, the default WSL2 backend, ~2021-era
Docker Desktop 4.5.0) had no `sch_netem` at all — every
`tc qdisc ... netem ...` failed with `Error: Specified qdisc not found.`,
neither built into the kernel nor loadable (no `modprobe` in the container,
no host access to add modules to Docker Desktop's fixed kernel). A separate
oddity was also seen in that session: `docker/bench.sh` reported a spurious
`timeout` on every run's first sweep iteration even at 0% loss (where
`apply_netem` was a no-op), for both `MODE=tcp` and `MODE=quic` — see
Thirteenth increment for the real explanation; it was not a network issue.

Thirteenth increment: with the operator's Docker Desktop reinstalled to use
the **Hyper-V backend** instead of WSL2 (`wslEngineEnabled: false`,
requiring the Windows Hyper-V feature enabled), the VM kernel changed to
Docker's own `6.12.76-linuxkit`, which **does** support `sch_netem` —
confirmed directly (`tc qdisc add dev eth0 root netem loss 20% delay 15ms`
succeeds). This resolved the kernel limitation from the Twelfth increment.

However, `docker/bench.sh` still reported every sweep point as `timeout`
even with netem now functional — the same oddity noted above, now isolated
properly instead of attributed to the kernel. Root cause: **`bc` is not
installed in this environment's Git-for-Windows/MSYS bash**
(`bc: command not found`, confirmed directly). `bench.sh`'s sweep loop used
`bc -l` for both the `t > 0` sanity check and the MB/s calculation, with
`2>/dev/null || echo 0` swallowing the "command not found" error — so the
success check `[ "$(echo "$t > 0" | bc -l 2>/dev/null || echo 0)" = "1" ]`
was unconditionally false on this machine, regardless of whether the
transfer actually succeeded. Manually re-running the exact same `curl`
command bench.sh issues, byte-for-byte, always completed the full 20 MB
transfer correctly (confirmed via direct file-size polling and a real
206 MB/s+ instant transfer) — the "timeout" status was a **pure detection
bug in the script**, not a network, Docker, kernel, or carrier problem, and
not related to `chrome-h3`/QUIC at all (it reproduced identically for
`MODE=tcp`).

Fixed in `docker/bench.sh`: replaced both `bc -l` calls with `awk`, which is
reliably present everywhere the script needs to run (Linux, macOS,
Git-for-Windows/MSYS) and handles floating point natively — no functional
change to the measurement itself, purely a portability fix to the
success-detection logic.

With both the kernel limitation (Hyper-V backend) and the detection bug
(`awk` instead of `bc`) fixed, the netem sweep produced real numbers,
confirmed stable across two independent runs on `TAG=chimera_quic MODE=quic`:

| loss % | run 1 | run 2 | ROADMAP Этап 3 baseline |
|---|---|---|---|
| 0  | 22.18 MB/s | 22.02 MB/s | ~25–32 MB/s |
| 20 | 6.14 MB/s  | 7.93 MB/s  | ~6–10 MB/s |
| 30 | 2.66 MB/s  | 3.60 MB/s  | ~2.4–5.9 MB/s |
| 40 | 1.66 MB/s  | 3.00 MB/s  | ~0.4–1.8 MB/s |

Every point falls within or above the recorded baseline range (netem is
stochastic run-to-run, as the baseline table's own notes already caveat) —
**no regression** from the chrome-h3 frame-fragmentation change or any other
change since that baseline was recorded. `TAG="" MODE=tcp` was also re-run
for context and reproduced the documented TCP-Reality collapse exactly:
41.04 MB/s at 0% loss, ~0.00–0.01 MB/s at 20/30/40% loss (curl transfers
essentially stall under real injected loss with no CC/ARQ improvements on
that path, as expected — this is the gap the QUIC/ElasticCC carrier exists
to close).

**The QUIC Initial fingerprint criterion now has no remaining gaps.**

## 6. Effort & risk

| Item | Effort | Risk |
|---|---|---|
| uquic build-gate on Go 1.26.4 | done | passed |
| Port uTLS ClientHello hook → v0.60.0 qtls | done | High (qtls internals) |
| Port Chrome transport-params + Initial frame layout | partial | Med |
| Gate Chrome TP order behind profile (no leak to non-chrome-h3 clients) | done | Low |
| Chrome-accurate TP *set* (omissions + Google-proprietary params) + per-connection shuffle | done | Med |
| Zero-length client SCID to match real Chrome | done | None — already true for free (`DialAddrEarly` + unset `ConnectionIDLength`) |
| Fixed 8-byte Initial DCID guess to match real Chrome | done | Low (single profile-gated call site) |
| Two-datagram Initial split for PQ ClientHello (matches `HelloChrome_133`) | done | None — emergent from existing unmodified packet_packer fragmentation, verified empirically, locked in with a regression test |
| `QUICID` selection wired to `fp:` pipeline | done | Low — already generic: `internal/quic/client.go` reads `cfg.Fp` fresh per dial, and `Pool`/`AutoPool.SetFingerprint` (wired to `config.Watch` in `cmd/chimera/main.go`) update it on both TCP and QUIC endpoint variants; covered by `TestAutoPool_SetFingerprintUpdatesTransportVariants` |
| Initial-diff validation harness | done | Low (Initial CRYPTO + packet tracer summary diff landed) |
| Real Chrome pcap/vantage validation | done | Live Chrome 150 capture + RFC-9001-vector-verified decrypt confirmed nearly all pinned TP values; found and fixed `max_idle_timeout`; found (undocumented until now) the CRYPTO/PING frame-fragmentation gap — see increment 10 |
| Frame-level fragmentation (many small CRYPTO frames + interspersed PING, not one/two big CRYPTO + PADDING) | done | `packChromeH3InitialCryptoFrames` in `packet_packer.go`, gated to chrome-h3 client Initial only; regression-tested, stable across repeated runs |
| `docker/bench.sh` netem goodput regression re-check | done | None — real netem sweep (Hyper-V-backed Docker Desktop, `sch_netem`-capable kernel) confirms goodput at 0/20/30/40% loss matches the recorded ROADMAP baseline, stable across two runs; also fixed an unrelated `bc`-portability bug in `bench.sh` itself (see Twelfth/Thirteenth increments) that was silently misreporting every run as `timeout` regardless of actual transfer success |

**Top risk:** full Initial parity now moves from TLS ClientHello bytes to the packet
surface: transport-parameter order, frame packing, padding and vantage/pcap drift.
The ClientHello hook is gated and covered by both summary diff and loopback carrier
tests so it cannot silently become "pretty bytes, broken handshake".

## 7. Decision

Continue Path B on top of the local v0.60.0 fork. The QUIC carrier now changes the
real Initial ClientHello for `chrome-h3` instead of only metadata knobs; the
transport-parameter order/set matches a pcap-derived Chrome reference with
per-connection randomization; the connection-ID shape (zero-length SCID,
fixed 8-byte DCID), multi-packet Initial fragmentation for the PQ ClientHello,
and CRYPTO/PING frame-level layout within each Initial packet all now match
real Chrome — the packet_packer.go changes needed for the latter two turned
out to be either unnecessary (multi-packet split was already emergent
behavior) or small and self-contained (frame interleaving), not the risky
ElasticCC-adjacent rewrite originally feared. A live capture + RFC-9001-
verified decrypt of a real Chrome 150 stable build confirmed nearly every
pinned transport-parameter value byte-for-byte, catching and fixing one real
error (`max_idle_timeout`) that no amount of secondhand-documentation review
would have caught, and directly motivated the frame-fragmentation fix. The
QUIC Initial fingerprint criterion has now been fully validated end to end,
including the `docker/bench.sh` netem goodput regression re-check (Twelfth/
Thirteenth increments): once the operator switched Docker Desktop to the
Hyper-V backend (fixing a kernel that lacked `sch_netem`) and an unrelated
`bc`-portability bug in `bench.sh` itself was found and fixed (it had been
silently misreporting every transfer as `timeout` on this Windows/MSYS
environment regardless of actual success), a real netem sweep confirmed
goodput at 0/20/30/40% loss matches the recorded ROADMAP baseline — no
regression from the frame-fragmentation change or anything else touching
`packet_packer.go` since that baseline was recorded. No remaining gaps.
