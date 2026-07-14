//go:build chimera_quic

package quic

// datagramMux manages the mapping from assocID → *net.UDPConn for one QUIC
// connection. It runs a background goroutine that reads QUIC datagrams and
// dispatches them to the appropriate UDP socket.
//
// QUIC DATAGRAM (RFC 9221) flow:
//  1. Client sends CmdUDPAssoc on a control stream → server calls Register.
//  2. Server dials the target UDP address, registers the UDP socket under the
//     assigned assocID, and starts forwarding.
//  3. Client sends QUIC datagrams: [assocID(2) | udpPayload].
//  4. Server reads datagrams, demux by assocID, writes udpPayload to UDP socket.
//  5. Server reads UDP responses, wraps with assocID prefix, sends via QUIC datagram.

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"

	"chimera/internal/fec"
	"chimera/internal/tunnel"
)

// maxUDPRead is the maximum UDP read buffer. UDP datagrams are at most 65507
// bytes (IPv4) but QUIC datagrams are limited by path MTU (~1200 bytes overhead
// removed). Oversized datagrams are silently dropped (UDP semantics: no fragmentation).
const maxUDPRead = 65507

// nextAssocID is a connection-scoped counter for assigning unique assocIDs.
// Using atomic so Register does not need to hold the mux lock. The counter is
// masked to 15 bits at use sites (see Register) so the high byte of a wrapped
// datagram never collides with FEC frame markers.
var nextAssocID atomic.Uint32

// defaultFECLoss seeds the adaptive FEC group size before any measured loss
// feedback is available. 0.1 → N=10 → ~10 % redundancy, protecting against a
// single erasure per 10 datagrams. Closed-loop adaptation (feeding the
// receiver's observed loss back into Encoder.SetLoss) is the remaining step.
const defaultFECLoss = 0.1

// datagramMux multiplexes UDP associations over one QUIC connection. Every
// datagram it sends is FEC-framed via enc so the peer can recover a single
// erasure per group from the parity frames.
type datagramMux struct {
	ctx      context.Context
	conn     *quic.Conn
	enc      *fec.Encoder
	mu       sync.RWMutex
	socs     map[uint16]*net.UDPConn
	dispatch sync.Once
}

func newDatagramMux(ctx context.Context, conn *quic.Conn) *datagramMux {
	return &datagramMux{
		ctx:  ctx,
		conn: conn,
		enc:  fec.NewEncoder(defaultFECLoss),
		socs: make(map[uint16]*net.UDPConn),
	}
}

// ensureDispatch starts the UDP-association datagram dispatch loop exactly once,
// on demand. It is started lazily (on the first CmdUDPAssoc) rather than eagerly
// per connection, so a connection dedicated to the rudp bulk sub-mode leaves the
// QUIC datagram channel free for rudp to own — there can be only one
// ReceiveDatagram consumer per connection.
func (m *datagramMux) ensureDispatch() {
	m.dispatch.Do(func() {
		go runDatagramDispatch(m.ctx, m.conn, m)
	})
}

// Register dials targetAddr via UDP, assigns the next assocID, and starts
// forwarding datagrams in both directions. Returns the assocID on success.
func (m *datagramMux) Register(ctx context.Context, targetAddr string) (uint16, error) {
	raddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		return 0, err
	}
	uc, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return 0, err
	}
	// Mask to 15 bits: keeps the high byte of WrapDatagram's output ≤ 0x7F so a
	// data datagram is never mistaken for a FEC frame after wrapping.
	id := uint16(nextAssocID.Add(1) & 0x7FFF)

	m.mu.Lock()
	m.socs[id] = uc
	m.mu.Unlock()

	// Forward UDP responses → QUIC datagrams.
	go m.udpToQuic(ctx, id, uc)
	return id, nil
}

// Dispatch sends payload to the UDP socket associated with assocID.
func (m *datagramMux) Dispatch(assocID uint16, payload []byte) {
	m.mu.RLock()
	uc := m.socs[assocID]
	m.mu.RUnlock()
	if uc == nil {
		return
	}
	_, _ = uc.Write(payload)
}

// Close closes all UDP sockets.
func (m *datagramMux) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, uc := range m.socs {
		uc.Close()
	}
	m.socs = make(map[uint16]*net.UDPConn)
}

// udpToQuic reads UDP datagrams from uc and sends them as QUIC datagrams with
// the given assocID prefix. Datagrams that exceed the QUIC path MTU are silently
// dropped (UDP does not support fragmentation; the sender should respect PMTUD).
// Runs until uc is closed or ctx is cancelled.
func (m *datagramMux) udpToQuic(ctx context.Context, assocID uint16, uc *net.UDPConn) {
	buf := make([]byte, maxUDPRead)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, err := uc.Read(buf)
		if err != nil {
			return
		}
		// FEC-frame the wrapped datagram. AddData returns the data frame plus,
		// once per group, a parity frame the peer uses to recover an erasure.
		dgram := tunnel.WrapDatagram(assocID, buf[:n])
		dataFrame, parityFrame := m.enc.AddData(dgram)
		if err := m.conn.SendDatagram(dataFrame); err != nil {
			var mtuErr *quic.DatagramTooLargeError
			if errors.As(err, &mtuErr) {
				// Drop oversized datagram; log once per call to avoid spam.
				slog.Debug("quic datagram exceeds path MTU, dropped",
					"assoc", assocID,
					"payload_bytes", n,
					"max_bytes", mtuErr.MaxDatagramPayloadSize,
				)
				continue
			}
			slog.Debug("quic datagram send failed", "assoc", assocID, "err", err)
			return
		}
		if parityFrame != nil {
			// Parity is best-effort: an oversized or failed parity send just
			// means this group is unprotected, never a data loss.
			if err := m.conn.SendDatagram(parityFrame); err != nil {
				slog.Debug("quic fec parity send failed", "assoc", assocID, "err", err)
			}
		}
	}
}

// lossReportInterval is how many received data/parity frames elapse between
// loss-feedback frames sent back to the peer. Frequent enough to track netem
// loss steps, sparse enough to stay negligible overhead.
const lossReportInterval = 64

// runDatagramDispatch reads QUIC datagrams from conn, FEC-decodes them, and
// dispatches both the directly-received and any FEC-recovered payloads to the
// appropriate UDP socket via mux. It also closes the adaptive-FEC loop: incoming
// feedback frames drive the local Encoder's group size, and the locally observed
// loss is reported back to the peer every lossReportInterval frames.
// Returns when ctx is done or conn is closed.
func runDatagramDispatch(ctx context.Context, conn *quic.Conn, mux *datagramMux) {
	dec := fec.NewDecoder(0)
	seen := 0
	for {
		raw, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		// Feedback frames adapt our own Encoder; they are not FEC-protected data.
		if fec.IsFeedback(raw) {
			if loss, ok := fec.ParseFeedback(raw); ok {
				mux.enc.SetLoss(loss)
			}
			continue
		}
		// A data frame carries a payload to dispatch now; any frame (data or
		// parity) may complete a group and yield a recovered payload.
		payload, isData, recovered := dec.Add(raw)
		if isData {
			dispatchWrapped(mux, payload)
		}
		if recovered != nil {
			dispatchWrapped(mux, recovered)
		}
		// Periodically report our observed inbound loss so the peer's Encoder can
		// raise FEC redundancy. Best-effort: a lost report just delays adaptation.
		if seen++; seen%lossReportInterval == 0 {
			if err := conn.SendDatagram(fec.MakeFeedback(dec.LossEstimate())); err != nil {
				slog.Debug("quic fec feedback send failed", "err", err)
			}
		}
	}
}

// dispatchWrapped unwraps an assocID-prefixed datagram and forwards it.
func dispatchWrapped(mux *datagramMux, wrapped []byte) {
	assocID, payload, ok := tunnel.UnwrapDatagram(wrapped)
	if !ok {
		return
	}
	mux.Dispatch(assocID, payload)
}
