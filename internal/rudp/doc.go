// Package rudp implements a reliable, ordered, FEC-protected bytestream
// (a net.Conn) layered over an unreliable datagram transport.
//
// # Why this exists
//
// CHIMERA proved by measurement (ROADMAP Этап 3, netem sweep) that congestion
// control alone cannot reach ≥70 % goodput at 30–40 % loss: a reliable-stream
// ARQ pays a retransmission RTT for every lost packet, and lost ACKs compound
// it, so goodput collapses regardless of the configured rate. The fix is to
// stop relying on retransmission for the common case — carry bulk data over
// unreliable QUIC datagrams with an application layer that
//
//	(a) reconstructs the majority of loss locally via FEC (no RTT penalty), and
//	(b) falls back to ARQ only for the rare loss a group's parity can't cover.
//
// This is the KCP+FEC / kcptun model.
//
// # Layering
//
//	bulk relay (io.Copy / vision.Splice)        ← unchanged consumers
//	       │  net.Conn
//	       ▼
//	rudp.Conn  ── segmentation · FEC · reorder · ARQ · window/pacing
//	       │  Datagram.Send / Datagram.Recv (PacketConn-like)
//	       ▼
//	QUIC DATAGRAM channel (internal/quic) — or any datagram transport
//
// Decoupling through the tiny [Datagram] interface lets rudp be unit-tested
// over an in-memory lossy pipe (drop %, reorder, dup) with zero network or QUIC
// dependency, then wired over real QUIC datagrams for e2e/netem.
//
// # Phasing
//
// This package lands incrementally; each phase is independently buildable and
// testable with -race:
//
//	Phase 0  Datagram iface + lossy pipe + wire codec
//	Phase 1  segmentation + reorder + cumAck/SACK + capped-RTO ARQ (no FEC)
//	Phase 2  FEC encode/decode (reuse internal/fec)
//	Phase 3  window + loss-compensated pacing + flow control
//	Phase 4  rudp over the real QUIC datagram path as a bulk sub-mode
//	Phase 5  netem benchmark mode + tuning
//
// See docs/reliable-fec-transport.md for the full design spec.
package rudp
