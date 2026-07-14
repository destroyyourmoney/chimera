# Design Spec — Reality ServerHello/Cert Takeover Engine

> Status: **Phases 1–4 implemented and validated against real Chrome**
> (architecture A: terminate-with-own-keys + mimicked ServerHello). Closes
> ROADMAP Этап 1b acceptance item:
> «ретранслировать подлинный ServerHello/Cert самого steal-host с key-takeover
> (полный VLESS-Reality)» and the `[~]` criterion «байт-парность — только после
> ретрансляции ServerHello самого steal-host» — for the fields covered below.
>
> **What's implemented:**
> - `internal/reality/probe.go` — `ProbeServerHello`/`ParseServerHello`/
>   `ServerHelloTemplateFor`: opens a real TLS 1.3 handshake to the steal-host
>   with the same impersonated ClientHello CHIMERA's client sends, captures the
>   genuine ServerHello off the record layer, parses cipher suite, negotiated
>   group, and extension type/order into a `ServerHelloTemplate`, and caches it
>   per-SNI with TTL + cached-failure fallback.
> - `third_party/utls` (vendored fork, `replace` in `go.mod`, mirrors the
>   quic-go/ElasticCC workflow) — new `Config.ServerHelloShape` /
>   `ServerHelloShape{ForceCipherSuite, ForceGroup, ExtensionOrder}`. Patches
>   `handshake_server_tls13.go` (cipher/group negotiation only overridden when
>   the client actually offered the forced value — never triggers a
>   HelloRetryRequest) and `handshake_messages.go`
>   (`serverHelloMsg.extensionOrder` controls supported_versions/key_share
>   emission order; any other value falls back to the original hardcoded
>   order).
> - `internal/reality/reality.go` `ServerWrap` — now calls `utls.Server`
>   (patched fork) instead of stock `crypto/tls.Server`, and builds a
>   `ServerHelloShape` from the cached template for the session's steal-host.
>   Probe failure (steal-host briefly unreachable) yields a `nil` shape, which
>   is the pre-existing stock-ordering behavior — never fails the session.
> - Tests: `internal/reality/probe_test.go` (parser + live-loopback probe +
>   cache-hit), `internal/reality/shape_test.go`
>   (`TestServerWrap_AppliesServerHelloShape` proves forced cipher/group/order
>   land on the actual wire bytes of an authorized session by recording and
>   re-parsing them; `TestServerWrap_NoTemplateFallsBackToDefault` proves the
>   fail-open path).
>
> **Resolved gap — hybrid PQ group forcing:** `ServerWrap`'s `CurvePreferences`
> now allows both `X25519` and `X25519MLKEM768` (previously X25519-only), so
> `ForceGroup` can steer live negotiation to whichever one a real steal-host's
> template calls for. This is safe for the `ss`-based auth: `ss` is derived by
> the auth gate (`clienthello.Parse`/`auth.Open`, *before* `ServerWrap` ever
> runs) from the ClientHello's plain X25519 `key_share` entry specifically.
> uTLS's `KeySharePrivateKeys` keeps a *separate* ECDH key (`MlkemEcdhe`) for
> the X25519MLKEM768 entry's classical component, so whichever group the live
> TLS handshake negotiates never touches `ss`. Verified end-to-end by
> `TestServerWrap_ForcesHybridGroup` (forces `ForceGroup=X25519MLKEM768`,
> confirms the negotiated group lands in the wire ServerHello *and* the
> PSK confirm still succeeds).
>
> **Resolved — Phase 4 drift:** `reality.SetFingerprint` (the existing Этап 5
> fingerprint-pipeline hook, wired to `config.Watch`'s hot-reloadable `fp:`
> field) now calls `InvalidateServerHelloTemplates()`, dropping every cached
> `ServerHelloTemplate`. A template captured against the *previous*
> impersonated ClientHello could reflect a negotiation a real steal-host
> would no longer make against the new one (e.g. different cipher order or PQ
> support across Chrome builds). Verified by
> `TestSetFingerprint_InvalidatesTemplateCache`.
>
> **Resolved — real-Chrome vantage validation:** `internal/reality/chrome_vantage_test.go`
> (`TestChromeVantageServerHelloParity`, skipped unless `CHIMERA_CHROME_PATH`
> points at a real Chrome/Chromium binary) closes the "same-process
> round-trip only" gap. No OS-level packet-capture tool was available on this
> dev box (no tshark/npcap; same constraint as `docs/uquic-initial-fingerprint.md`'s
> QUIC work), so ground truth instead comes from wrapping a local TLS 1.3
> vantage server's accepted `net.Conn` to record exactly what it wrote, for
> both a genuine headless Chrome (BoringSSL) connection and CHIMERA's own —
> an application-level capture of a real, independent, external TLS
> implementation's output, not a comparison of this codebase against itself.
> Run against Chrome for Testing 150.0.7871.115
> (`npx @puppeteer/browsers install chrome@stable`): real Chrome negotiated
> `cipher=0x1301` (TLS_AES_128_GCM_SHA256), `group=0x11ec` (X25519MLKEM768),
> extension order `[supported_versions, key_share]` against the vantage
> server; CHIMERA's own probe against the *same* server produced an
> identical result; and CHIMERA's authorized-session served ServerHello
> (via the normal `ServerWrap` production path, probing that same server
> internally) matched all three fields exactly too. This is the first
> end-to-end confirmation, against a real independent implementation, that
> probe → template → served-ServerHello reproduces what an actual Chrome
> visitor to the steal-host would see.
>
> **Resolved — real external CDN validation:** `internal/reality/external_cdn_test.go`
> (`TestExternalCDNServerHelloParity`, skipped unless `CHIMERA_EXTERNAL_STEALHOST=host[:port]`
> is set) closes the "local stand-in only" gap noted below. Unlike
> `chrome_vantage_test.go`'s local, single-cert Go `crypto/tls` vantage
> server, this test targets a real production CDN over the public Internet
> and never terminates or MITMs its TLS: the (optional, `CHIMERA_CHROME_PATH`-gated)
> real-Chrome leg connects through a transparent byte-relay proxy — Chrome's
> `--host-resolver-rules` points the target hostname at the local relay,
> which does nothing but pipe bytes to and from the real host on 443
> unmodified, so Chrome's own certificate validation and the CDN's handshake
> are completely undisturbed; the test only observes wire bytes that already
> crossed the network, then feeds them through this package's own
> `ParseServerHello` (same parser as the probe/serve legs). Two comparisons
> run: (A) CHIMERA's probe vs. its own served ServerHello (always), and (B),
> when `CHIMERA_CHROME_PATH` is also set, both of those against a real
> headless Chrome's ServerHello via the relay — a genuine three-way,
> independent-implementation check. This test is a **canary, not a hard CI
> gate**: real CDN configuration changes over time.
>
> Run against `www.microsoft.com:443` (chosen because it was already used as
> the example steal-host elsewhere in this codebase's tests, introducing no
> new external dependency), with Chrome for Testing 150.0.7871.115: all three
> legs agreed exactly — `cipher=0x1302` (TLS_AES_256_GCM_SHA384),
> `group=0x001d` (plain X25519 — this real CDN did **not** negotiate the
> hybrid PQ group the local stand-in and Chrome-vs-local-stand-in test did),
> extension order `[supported_versions(0x2b), key_share(0x33)]`. Stable
> across repeated runs (3x back-to-back, no HelloRetryRequest observed). This
> is the first end-to-end confirmation against a real, independent,
> production TLS stack over the public Internet that probe → template →
> served-ServerHello reproduces what an actual visitor to a real steal-host
> would see — including a cipher/group choice that genuinely differs from
> every other test in this package, so this wasn't a coincidence of the
> local stand-in happening to match.
>
> **Resolved along the way — HelloRetryRequest detection:** while designing
> the external-CDN test it became clear a real CDN can answer our probe's
> ClientHello with a HelloRetryRequest (RFC 8446 §4.1.4) if it doesn't like
> any offered key_share group — wire-identical to a ServerHello
> (`handshake_type=2`) except for a magic `Random` value, with a bare
> 2-byte-group `key_share` (no public key). The local `crypto/tls` stand-in
> used elsewhere in this package's tests never produces this (its group
> always matches ours), so the gap was invisible until real-CDN diversity was
> in scope. `ParseServerHello` (`internal/reality/probe.go`) now detects the
> magic Random and returns `errHelloRetryRequest` instead of silently
> emitting a template whose `KeyShareGroup` looks valid but was never paired
> with a real key exchange. `ServerWrap`'s existing fail-open behavior on any
> probe error already covers this — it is simply one more path to the same
> safe nil-shape fallback. Covered by
> `TestParseServerHello_HelloRetryRequest` (crafted HRR message).
>
> **Resolved — OS-level pcap validation with an independent tool.** Revisits
> the earlier "no tshark/npcap/pktmon-for-loopback available" constraint
> noted above and in `docs/uquic-initial-fingerprint.md`: that constraint was
> specifically about *loopback* traffic. Once the external-CDN work above
> produced real non-loopback egress, both tools were re-tried against it:
>
> - **`pktmon`** (built into Windows, no install) *does* capture real
>   non-loopback traffic on this box when run elevated (`pktmon start -c
>   --comp nics --pkt-size 0 -f capture.etl`, `pktmon stop`, `pktmon
>   etl2pcap`) — confirmed by capturing full bidirectional TLS 1.3 sessions
>   to several real hosts. One environment-specific wrinkle: `pktmon
>   etl2pcap` tags the whole output file's link-layer type as Ethernet even
>   though this box's VPN tunnel adapter ("Mullvad Tunnel") emits raw IP
>   frames with no L2 header, which makes generic Ethernet-assuming
>   dissectors (including `tshark`'s default) misparse those frames as
>   garbage. Fix: split out the misparsed frames (`frame.protocols ==
>   "eth:ethertype:data"`) and re-tag them with `editcap -T rawip4`, after
>   which they dissect correctly. A second, destination-specific wrinkle: for
>   this box's route to Microsoft's Akamai edge specifically (and only that
>   destination — Cloudflare, Wikipedia, and example.com all captured
>   cleanly bidirectionally), only the outbound leg was ever captured,
>   reproducibly, for both CHIMERA's own client and plain `curl` — almost
>   certainly a VPN split-tunnel/exclusion rule for Microsoft traffic on this
>   particular host, unrelated to this codebase. Worked around by pointing
>   the pcap-comparison run at `www.cloudflare.com:443` instead (Part 1's
>   canary result above stands independently for `www.microsoft.com`; this
>   Part 2 validation is about proving the *capture/parse methodology* is
>   sound, not re-litigating which steal-host to use).
> - **`tshark`** installed cleanly via
>   `winget install --id WiresharkFoundation.Wireshark --source winget
>   --accept-package-agreements --accept-source-agreements --silent`
>   — no interactive npcap-driver prompt blocked it (the feared blocker in
>   the original plan did not materialize here; live capture would still
>   need npcap, but reading a `pktmon`-produced `.pcapng` file needs no
>   capture driver at all).
>
> **Result:** ran `TestExternalCDNServerHelloParity` against
> `www.cloudflare.com:443` under an active `pktmon` capture (`pktmon start
> -c --comp nics --pkt-size 0`), converted to pcapng (`pktmon etl2pcap`),
> located CHIMERA's own probe connection by TCP port + TLS SNI
> (`tls.handshake.extensions_server_name=="www.cloudflare.com"`), and
> dissected the real captured ServerHello frame with `tshark` (after the
> `rawip4` re-tag above) — a tool that shares **no code** with this
> package's `ParseServerHello`. `tshark` reported `tls.handshake.type=2`,
> `tls.handshake.ciphersuite=0x1301`, `tls.handshake.extensions_key_share_group=4588`
> (`0x11ec`), extension order `[51, 43]` (key_share then supported_versions)
> — an **exact match**, field for field, with what
> `TestExternalCDNServerHelloParity`'s own log line reported for the same
> run (`cipher=0x1301 group=0x11ec extensions=[51 43]`). This is the
> defense-in-depth check `chrome_vantage_test.go` and
> `external_cdn_test.go` couldn't provide on their own (both legs there
> still share this package's own `ParseServerHello`): independent
> confirmation, via a completely separate parser reading the same captured
> wire bytes at the OS level, that `ParseServerHello` has no interpretation
> bug of its own. Not wired into any automated test (`pktmon`/`tshark`
> aren't dependencies of this repo and the capture requires elevation) —
> this was a one-time manual spike; the result and reproduction steps are
> recorded here for the next person who wants to re-verify or extend it.

## 1. Context & problem

For an authorized client, CHIMERA today (`chimera_utls` build) upgrades the
session to a **real** TLS 1.3 handshake:

- Client: `reality.ClientWrap` — live uTLS Chrome ClientHello; the uTLS X25519
  ephemeral is reused as the CHIMERA auth key; auth tag rides in `SessionId`.
  (`internal/reality/reality.go:100`)
- Server: `reality.ServerWrap` — terminates with **stock `crypto/tls`**,
  presenting a **self-signed** cert for the steal-host name.
  (`internal/reality/reality.go:144`, wired at `internal/server/transport_reality.go:25`)

The auth gate that selects this path (vs. transparent splice for everyone else)
lives at `internal/server/server.go:159` (`handle`) → `authenticate` →
`authedTransport`. Probers without a valid tag are spliced to the real steal-host
(`spliceConn`, `server.go:248`), wire-identical to a normal visitor.

**The residual leak.** TLS 1.3 encrypts everything after ServerHello, so the
self-signed Certificate is invisible to passive DPI — and an active prober never
sees it (it gets spliced). The **only** passive-observable artifact of an
authorized session is the **cleartext ServerHello**, whose JA3S (TLS version +
cipher suite + extension list/order) is produced by Go's `crypto/tls`, not by the
CDN/nginx that actually fronts the steal-host. A passive observer that fingerprints
ServerHellos can therefore tell a CHIMERA authorized session apart from a genuine
visit to the steal-host. This violates the project invariant (no new fingerprint).

**Why stock `crypto/tls` cannot fix it.** Go exposes no hook to (a) emit a
ServerHello with a chosen extension ordering/layout, (b) inject a foreign
ServerHello, or (c) substitute the negotiated key_share while keeping the key
schedule/transcript consistent. JA3S parity therefore requires a **server-side
TLS 1.3 engine we control** — exactly what XTLS-Reality ships as a patched stack.

**What is NOT worth doing.** Serving the steal-host's *real fetched certificate*
chain is near-zero value: it is encrypted (passive DPI can't see it) and the
prober path already shows the genuine handshake via splice. Cert relay is cosmetic
and is explicitly de-scoped from the valuable core.

## 2. Threat model & exact goal

| Adversary | Capability | Current status | Goal |
|---|---|---|---|
| Passive DPI (TSPU) | Reads cleartext ClientHello + ServerHello, timing, sizes | ClientHello ✓ (uTLS); **ServerHello ✗ (Go JA3S)** | ServerHello JA3S == steal-host |
| Active prober | Opens its own TLS to the IP | ✓ genuine via splice | unchanged |
| MITM on path | Tampers handshake | ✓ PSK proof rejects (`confirm`) | unchanged |

**Goal (precise):** for an authorized session, the **cleartext ServerHello bytes**
emitted by the CHIMERA server are byte-shaped identically to what the real
steal-host returns for the *same* ClientHello — same `legacy_version`,
`cipher_suite`, `legacy_compression`, and the same **extension set and ordering**
(`supported_versions`, `key_share`, and any others the steal-host emits) — while
the CHIMERA server still **controls the session keys** (can read/write the inner
tunnel). The session must remain a cryptographically valid TLS 1.3 handshake to
the CHIMERA client.

## 3. Candidate architectures

### (A) Terminate-with-own-keys + mimicked ServerHello  ⭐ recommended

The CHIMERA server terminates TLS itself (its own ephemeral key_share → it holds
the keys → reads the tunnel), but its custom TLS-1.3 server emits a ServerHello
whose **observable layout is copied from a template learned by probing the real
steal-host**.

- **Probe (offline/cached):** open a real TLS 1.3 handshake to `dest:443` with a
  ClientHello matching our client's (uTLS Chrome). Capture the genuine ServerHello
  and record: negotiated cipher suite, selected group, supported_versions value,
  and the exact extension order/contents. Cache per `dest` (refresh periodically;
  reuse the existing `preconnect.Pool` warm-dial machinery, `server.go:248`).
- **Serve:** for an authorized client, run our TLS-1.3 server engine seeded with
  the template. We substitute **our** key_share public key into the `key_share`
  extension (we own the private half) but keep every other field byte-aligned with
  the template. Compression=0, cipher matches template, extension order matches.
- **Certificate:** encrypted ⇒ irrelevant to JA3S. Keep self-signed (current
  `certFor`) or, optionally, the fetched real chain — cosmetic, de-scoped.
- **Client side:** unchanged conceptually (uTLS already drives the handshake);
  must accept our ServerHello (it will — it's a valid TLS 1.3 SH) and continues to
  authenticate via the PSK `confirm` proof, not PKI.

**Pros:** server reads the tunnel (no double-relay); achievable with a controlled
stack; matches XTLS-Reality's actual posture (own keys, mimicked SH). **Cons:**
needs a controllable TLS-1.3 server stack (see §5); template must track steal-host
changes.

### (B) Live relay + key-substitution (maximal fidelity)

Proxy the authorized client's handshake to the real `dest` and relay `dest`'s
genuine ServerHello byte-for-byte, then substitute key material so the CHIMERA
server (not `dest`) ends up holding the session keys.

**Pros:** ServerHello is literally `dest`'s bytes (perfect JA3S, auto-tracks
changes). **Cons:** the key-substitution step is the subtle, security-critical
heart of XTLS-Reality; getting the transcript hash / key schedule wrong silently
breaks either secrecy or the handshake. Requires deep, correct surgery into the
TLS-1.3 key schedule on both ends and careful transcript bookkeeping. Highest risk;
easiest to get subtly wrong (there is published history of Reality handshake bugs).

**Recommendation:** **(A)**. It reaches the stated goal (cleartext SH parity) with
far less cryptographic risk, and is the design XTLS-Reality effectively runs.
Treat (B) as a future maximal-fidelity option only if a probe-template proves
insufficient against a specific real-world classifier.

## 4. On-the-wire: today vs. target

```
Today (authorized):
  C → S : ClientHello            [uTLS Chrome — genuine JA3]
  S → C : ServerHello            [Go crypto/tls — JA3S ≠ steal-host]  ← LEAK
  S → C : {EncryptedExtensions, Certificate(self-signed), CertVerify, Finished}  [encrypted]
  C → S : {Finished}             [encrypted]
  C↔S   : CHIMERA confirm (PSK proof) then inner tunnel  [encrypted]

Target (A):
  C → S : ClientHello            [unchanged]
  S → C : ServerHello            [mimicked: cipher+ext layout == steal-host; our key_share]
  S → C : {EE, Certificate, CertVerify, Finished}  [encrypted — unchanged posture]
  C↔S   : confirm + tunnel       [unchanged]
```

## 5. Go feasibility — the stack question

**Important asymmetry.** uTLS is already a dependency, but only client-side:
`ClientWrap` uses `utls.UClient` to mimic the Chrome **ClientHello** (JA3/JA4 =
*client* fingerprint). The server path (`ServerWrap`, `reality.go:156`) uses the
**stock** `tls.Server`. JA3S is the **ServerHello** fingerprint, emitted by the
server. Verified against utls v1.8.2: `utls.Server()` exists but is the
**unmodified crypto/tls server** — uTLS provides **no** server-side fingerprint
API (no `ServerHelloID`/`UServer`/extension-order hook); `handshake_server_tls13.go`
builds the ServerHello the same fixed way Go does. So "we already use uTLS" does
**not** solve JA3S — uTLS is a client-impersonation library.

uTLS is itself a fork of crypto/tls (`Copyright … The Go Authors`). That makes it
the natural place to add the missing server-side capability, rather than
introducing a *second*, separate crypto/tls fork. Options, increasing effort:

1. **Patch uTLS's server side** ⭐ — add a server-side "ServerHello template" hook
   to the already-present dependency: order/emit extensions per a supplied spec,
   force cipher/compression, inject our key_share. Keeps a **single** TLS fork
   (uTLS already drives the client), and the auth/`ss` key-reuse logic already
   lives in uTLS-land on the client side. Vendor uTLS (or a `replace` directive)
   mirroring the existing quic-go/ElasticCC vendor-fork workflow.
2. **Fork & patch stock `crypto/tls`** — same mechanism, but creates a second TLS
   fork to maintain alongside uTLS. Rejected for redundancy now that we know uTLS
   is the existing fork.
3. **Hand-rolled minimal TLS-1.3 server** (only the messages we emit + key
   schedule). Maximal control, maximal audit burden. Last resort.

**Recommendation:** Option **1** — patch the uTLS server (already vendored as a
dependency and already a crypto/tls fork). One TLS fork, change confined to
ServerHello construction; record layer and key schedule stay battle-tested.

## 6. Integration points (concrete)

- `internal/reality/reality.go`
  - `ServerWrap` (`:156`): replace the stock `tls.Server(pc, cfg)` with the
    patched-uTLS server seeded by a `ServerHelloTemplate` (cipher, group, ordered
    extension specs) sourced from the probe cache. (Note: client `ClientWrap`
    already lives in uTLS, so both ends share one TLS fork.)
  - `certFor`/`selfSigned` (`:252`): unchanged (cert stays encrypted/cosmetic).
  - `confirm` PSK proof (`:171`): unchanged — still the authentication root.
- New `internal/reality/probe.go` (proposed): probe `dest`, parse its genuine
  ServerHello into a `ServerHelloTemplate`, cache per host with TTL refresh; reuse
  `preconnect.Pool` warm dials for timing hygiene.
- `internal/server/transport_reality.go:25`: pass the template (or a provider)
  into `ServerWrap`; thread the steal-host address through for probing.
- Client (`internal/reality/ClientWrap`, `internal/carrier/transport_reality.go`):
  no protocol change; verify uTLS accepts the mimicked ServerHello unchanged.
- Vendored **uTLS** patch (server-side ServerHello templating) under `vendor/`,
  mirroring the quic-go/ElasticCC fork layout; add a `replace` directive / vendor
  entry. One TLS fork total — no separate crypto/tls fork.

## 7. Correctness notes (must-get-right)

- **Key schedule:** since we keep our own key_share private, the TLS-1.3 key
  schedule (Early/Handshake/Master secrets via the chosen group ECDH +
  transcript) stays internally consistent — the engine derives keys exactly as
  stock crypto/tls would; only ServerHello *serialization* is templated.
- **Transcript hash:** the templated ServerHello bytes are what gets fed to the
  transcript hash on both ends. The client computes the same transcript from the
  bytes it receives, so Finished/CertVerify verification stays valid **as long as
  the emitted bytes are exactly what the client hashes** — no hidden re-encoding.
- **session_id_echo:** must echo the client's 32-byte `SessionId` (which carries
  our auth tag). The template's other extensions must not assume a particular
  client key_share group beyond what the ClientHello actually offered.
- **Downgrade/version:** pin TLS 1.3 only (matches current `MinVersion`/
  `MaxVersion`), supported_versions extension value `0x0304`.

## 8. Validation plan

1. **JA3S diff harness:** capture the genuine steal-host ServerHello (probe) and
   the CHIMERA authorized-session ServerHello; assert byte-equality of
   {version, cipher, compression, extension-type sequence} and equal JA3S hash.
   Add as a Go test under `chimera_utls` driving a loopback server with a recorded
   template.
2. **Handshake validity:** existing `reality` e2e (uTLS client ↔ engine) must still
   reach `confirm` + HTTPS=200 inside the tunnel, under `-race`.
3. **No-oracle parity:** prober path (`spliceConn`) unchanged; re-run the auth-reject
   and fuzz tests.
4. **Drift check:** template refresh picks up steal-host cipher/extension changes
   without rebuild (ties into Этап 5 fingerprint pipeline).

## 9. Effort & risk

| Item | Effort | Risk |
|---|---|---|
| Vendor + patch uTLS server-side ServerHello templating | High | Med (confined to SH serialization) |
| Probe → ServerHelloTemplate parser + cache | Med | Low |
| ServerWrap rewire + template threading | Low–Med | Low |
| JA3S diff test harness | Med | Low |
| Maintenance: template drift vs steal-host | ongoing | Low (covered by Этап 5 pipeline) |

**Top risks:** (1) crypto/tls fork maintenance across Go versions; (2) a real
classifier keying on a ServerHello field the template doesn't reproduce (mitigate:
diff harness in §8.1); (3) probe timing/availability of `dest` (mitigate: cache +
warm pool + fall back to current self-signed SH if no template, which is no worse
than today).

## 10. Open questions (for next decision point)

1. Pin to a single uTLS version for the vendored fork, or track upstream uTLS?
2. Probe cadence & cache TTL — and behavior when `dest` is briefly unreachable
   (fall back to today's stock SH, accepting the temporary JA3S leak?).
3. Do we ever need architecture (B)'s literal byte-relay, or is the (A) template
   provably sufficient against the classifiers we care about? (Decide from §8.1
   diff data before investing in (B).)

---

### Recommended phased execution (when approved)

1. **Phase 1 — Probe & template:** `internal/reality/probe.go` + `ServerHelloTemplate`
   type + parser + cache; unit tests on parsing real captured ServerHellos.
2. **Phase 2 — Engine:** vendor uTLS fork with a server-side ServerHello templating
   hook; `ServerWrap` uses it; loopback handshake green under `-race`.
3. **Phase 3 — Validation:** JA3S diff harness (§8.1); wire probe→template→engine
   end-to-end; fall-back-to-stock-SH safety net.
4. **Phase 4 — Drift:** hook template refresh into the Этап 5 fingerprint pipeline.
