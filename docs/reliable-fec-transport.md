# Design Spec — Reliable-FEC Datagram Transport (`internal/rudp`)

> Status: **PLAN**. The one large remaining subsystem that is fully buildable AND
> testable in this environment (loopback property tests + Docker/netem), with no
> mobile/desktop SDK, no root, no in-RU vantage. It is the measurement-backed fix
> for the headline criterion «netem 20/30/40 % loss → goodput ≥ 70 % baseline».

## 1. Why this, and why now

We proved by measurement (see ROADMAP Этап 3, netem table) that **congestion control
cannot reach ≥70 % goodput at 30–40 % loss**: BW=200 and BW=400 Mbps Brutal both
gave ~2 MB/s at 40 % loss → the ceiling is **reliable-stream ARQ** (every lost
packet costs a retransmission RTT, and lost ACKs compound it), not pacing.

The fix is to stop relying on retransmission for the common case: carry bulk data
over **unreliable QUIC datagrams** with an application-level layer that
(a) **reconstructs most loss locally via FEC** (no RTT penalty), and
(b) falls back to **ARQ only for the rare loss a group's parity can't cover**.
This is the KCP+FEC / kcptun model. At 40 % loss with enough parity, the large
majority of drops are repaired without a round trip, so goodput tracks the link
instead of collapsing.

We already have the pieces: the FEC codec (`internal/fec`), the QUIC DATAGRAM
send/receive path (`internal/quic/datagram.go`, `udpclient.go`), the carrier, and a
netem harness (`docker/bench.sh`). `rudp` is the reliability+ordering layer between
them.

## 2. What it is

`internal/rudp`: a reliable, ordered, FEC-protected bytestream (`net.Conn`) over an
unreliable datagram interface. It plugs:

```
 bulk relay (io.Copy, vision.Splice)         ← unchanged consumers
        │  net.Conn
        ▼
 rudp.Conn  ── segmentation · FEC · reorder · ARQ · window/pacing ──┐
        │  Send([]byte) / Recv() []byte (PacketConn-like)           │
        ▼                                                            │
 QUIC DATAGRAM channel (internal/quic) — or any datagram transport ─┘
```

Decoupling via a tiny `Datagram` interface (`Send([]byte) error`,
`Recv(ctx) ([]byte, error)`) lets us unit-test `rudp` over an in-memory lossy pipe
with **zero** network or QUIC dependency, then wire the same code over real QUIC
datagrams for e2e/netem.

## 3. Wire format (one type byte; rudp has its own datagram stream)

```
DATA   : [0x10 | seq:4 | len:2 | payload(len) ]
PARITY : [0x11 | group:4 | k:1 | idx:1 | blockLen:2 | parityBlock ]   (FEC repair)
ACK    : [0x12 | cumAck:4 | nSack:1 | (sackStart:4,sackEnd:4)*nSack | lossPermille:2 ]
FIN    : [0x13 | finalSeq:4 ]
```

- `seq` numbers DATA segments (monotonic). `cumAck` = highest in-order seq the
  receiver has delivered; SACK ranges report received-but-not-contiguous spans so
  the sender retransmits only true gaps.
- PARITY reuses the length-prefixed-XOR-block scheme already in `internal/fec`
  (exact variable-length recovery); `k` = parity count per group (1 for XOR v1).
- `lossPermille` rides ACKs to drive FEC redundancy + sender pacing (we already do
  this for the datagram FEC loop — reuse `fec.MakeFeedback`/`ParseFeedback` ideas).

## 4. Components

1. **Segmenter (send):** chop the bytestream into ≤MSS payloads (MSS ≈ path MTU −
   QUIC/datagram/rudp headers, ~1100 B), assign `seq`, keep in a **retransmit
   buffer** until ACKed.
2. **FEC encoder (send):** group N DATA segments, emit K PARITY (reuse
   `internal/fec`; adaptive N/K from observed loss via `SetLoss`). v1: XOR K=1 with
   small adaptive N; v2: Reed–Solomon GF(256) for efficient K>1 at high loss.
3. **Reorder buffer (recv):** index incoming DATA by `seq`; deliver contiguously to
   the reader; hold out-of-order until the gap fills (by arrival, FEC recovery, or
   retransmit).
4. **FEC decoder (recv):** reconstruct missing seqs in a group from PARITY +
   survivors **before** asking for retransmission.
5. **ARQ (recv→send):** ACK with cumAck+SACK; sender retransmits only gaps SACK
   shows missing AND FEC couldn't recover, on a **capped** RTO (lesson from the PTO
   bug — never exponential-backoff into seconds).
6. **Window + pacing (send):** bounded in-flight (BDP-sized, like ElasticCC's
   `openWindowToBDP`); pace at loss-compensated rate (reuse the Brutal/ElasticCC
   formula `rate/(1-loss)`).
7. **Flow control (recv→send):** advertise receive-buffer space in ACK to bound
   memory.

## 5. Phasing — each phase independently buildable + testable here

| Phase | Deliverable | Test (all local, `-race`) |
|---|---|---|
| 0 ✅ | `Datagram` iface + in-memory **lossy pipe** (drop %, reorder, dup) + wire codec | codec round-trip; pipe drops/reorders as configured |
| 1 ✅ | Segmentation + reorder + cumAck/SACK + capped-RTO ARQ (no FEC) | byte-exact transfer over pipe at 0/20/40 % loss; ordered; no dup delivery |
| 2 ✅ | FEC encode/decode wired in (reuse `internal/fec`, adaptive N) | at p loss, **fraction recovered without retransmit** is high; still byte-exact |
| 3 ✅ | Window + loss-compensated pacing + flow control | throughput scales; memory bounded; no deadlock under loss |
| 4 ✅ | Wire `rudp` over the real QUIC datagram path as a bulk sub-mode | e2e loopback: SOCKS CONNECT → rudp-over-QUIC → echo, byte-exact (mirrors `TestQUICUDPAssocEcho`) |
| 5 ✅ | netem benchmark mode + tuning | `docker/bench.sh MODE=quic-rudp`: goodput vs current stream mode at 20/30/40 % — **verdict below** |

Property test (phases 1–2): randomized loss+reorder+dup seeds, assert the received
bytes equal the sent bytes exactly — the core correctness guarantee.

## 6. Integration points

- **New** `internal/rudp/` (transport-agnostic; depends only on `internal/fec`).
- **New** `internal/rudp/pipe_test.go` lossy in-memory `Datagram` for tests.
- `internal/quic`: a `Datagram` adapter over the QUIC datagram channel (the
  send/recv loops already exist in `datagram.go`/`udpclient.go` — factor a small
  adapter). A bulk sub-mode where CONNECT relay rides `rudp` instead of a QUIC
  stream — selected by a carrier flag (e.g. `carrier.Config.Reliable` or
  `-transport quic-rudp`).
- `docker/bench.sh`: add `MODE=quic-rudp` so the netem sweep compares stream vs
  rudp goodput under loss.
- Consumers (`vision.Splice`, SOCKS relay) are unchanged — `rudp.Conn` is a `net.Conn`.

## 7. FEC sizing for high loss (the crux)

XOR with one parity per group recovers ≤1 erasure/group, so surviving 40 % loss
needs tiny groups (N=1 → 100 % overhead, ~16 % residual handled by ARQ) — correct
but bandwidth-heavy. **Reed–Solomon (N data + K parity, recovers any K of N+K)** is
the efficient answer: pick K so `P(>K losses in N+K) ` is small at the measured `p`.
Plan: v1 ships XOR + adaptive small N (proves the path, netem-measurable); v2 adds
RS over GF(256) (≈200 LOC, zero-dependency, or a vetted lib) for efficient high-loss
operation. RS upgrade is isolated to the FEC encoder/decoder — no `rudp` API change.

**Implementation note (phase 2).** FEC rides *under* rudp's DATA framing: each
rudp DATA frame (which carries its `seq`) is fed to `fec.Encoder` as the opaque
payload, so a FEC-recovered packet reveals its own `seq` for free and drops
straight into the reorder buffer. FEC frame bytes (`0x00`/`0x01`) and rudp frame
bytes (`0x10+`) are a disjoint namespace, so both coexist on one datagram stream.
Retransmissions bypass FEC (raw `0x10` DATA) — they are the ARQ fallback and
re-protecting them would muddle group/seq contiguity. Crucially, the FEC group
size is driven by the **sender's own** measured first-transmission loss (fraction
of acked segments that needed a retransmit), *not* the `fec.Decoder`'s loss
estimate: the decoder only counts groups it can finalize, so groups with ≥2
losses (the common case at high loss) are never counted, biasing its estimate
toward zero and starving the group size — a vicious cycle that left FEC recovering
nothing in the first cut. The sender-side estimate is unbiased.

## 8. Risks

- **Reinventing TCP badly:** mitigate by keeping it minimal (cumAck+SACK+capped-RTO,
  not full TCP), and by the property tests that assert byte-exactness under
  adversarial loss/reorder before any tuning.
- **FEC overhead vs goodput tradeoff:** adaptive N/K from measured loss; netem
  sweep tunes it. Over a loss-≠-congestion carrier, spending bandwidth on parity is
  the right trade.
- **Two reliability layers if run over a QUIC *stream*:** run `rudp` over QUIC
  **datagrams** (unreliable) only — never over a reliable stream (would double-ARQ).
- **Memory:** bounded reorder + retransmit buffers via advertised flow-control window.

## 8a. Phase 5 verdict — measured, and it disproves the hypothesis

`docker/bench.sh` netem sweep, 10 MB object, 15 ms/NIC delay, both modes on the
same harness (goodput, MB/s):

| loss % | `quic` (stream, ElasticCC) | `quic-rudp` (this transport) |
|---|---|---|
| 0  | **14.23** | 4.99 |
| 20 | **4.94**  | 2.64 |
| 30 | **2.70**  | 1.36 |
| 40 | 1.11      | 1.07 (≈ tied) |

(For reference the TCP-Reality baseline collapses to ~0 at 20–40 % loss.)

**`quic-rudp` does not beat the QUIC stream — the acceptance target is not met,**
and the measurement settles the design question:

1. **ElasticCC already solves loss≠congestion on the stream.** The motivating
   earlier number (stream ~2 MB/s at 40 %) does not reproduce here; adaptive
   ElasticCC-over-stream holds 1.11 MB/s at 40 % and 2.70 at 30 %, *above*
   `quic-rudp`. The carrier's existing transport already captures the
   loss-resilience goodput this subsystem was built to add.
2. **The QUIC datagram path is architecturally capped below the stream.** At 0 %
   loss `quic-rudp` tops out ~5 MB/s vs the stream's 14 — quic-go's DATAGRAM
   channel (32-frame send queue, best-effort, no native loss recovery) plus the
   app-level reliability layer (double congestion control + FEC parity overhead)
   cannot match the optimized reliable stream. Tuning lifted `quic-rudp` ~10–20×
   from the first cut (0.46→4.99 at 0 %; 0.05→1.07 at 40 %) but cannot clear that
   ceiling.

This is the "reinventing TCP badly" risk from §8, now confirmed with data: over a
carrier whose stream transport already runs a loss-tolerant CC, re-implementing
reliability above unreliable datagrams adds overhead without benefit. **Recommendation:**
do not promote `quic-rudp` to the default bulk path; keep investing in ElasticCC
on the stream. The subsystem is retained because it is correct, fully tested, and
the experiment that produced this verdict — and because the work surfaced and
fixed a real silent-corruption bug in the shared `internal/fec` codec (mid-group
`SetLoss` mis-sized parity; see §7) that also affected the production QUIC
UDP-proxy datagram path.

## 9. Acceptance criteria

- Byte-exact transfer under 0/20/40 % loss + reorder + dup in the loopback property
  test (`-race`), with FEC recovering the majority of loss without retransmission.
- e2e loopback over real QUIC datagrams: byte-exact bulk transfer.
- `docker/bench.sh MODE=quic-rudp`: goodput at 20/30/40 % loss **materially above**
  the QUIC-stream numbers (target: approach ≥70 % of baseline at 20–30 %; honest
  measurement of the 40 % case). This is the first design that can actually hit the
  Этап 3 goodput criterion — and it's measurable right here.

## 10. Effort

Medium-large, but bounded and incremental: ~Phase 1–2 are the bulk (~600–900 LOC +
tests); Phases 3–5 are smaller. Every phase lands with passing local tests; Phase 5
gives the netem verdict without any external infrastructure.
