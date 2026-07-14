//go:build chimera_quic

package quic

// Client-side UDP-association datagram driver. This is the peer of the server's
// datagramMux (datagram.go): it multiplexes many UDP associations over one QUIC
// carrier connection, FEC-frames outbound datagrams, FEC-decodes inbound ones,
// and closes the adaptive-FEC loss-feedback loop symmetrically with the server.
//
// Flow for one association:
//  1. OpenAssoc opens an authenticated stream, sends CmdUDPAssoc | host | port,
//     reads back the server-assigned assocID, then closes the control stream
//     (the association persists at the connection/datagram level).
//  2. Send wraps payload as [assocID(2) | payload], FEC-frames it, and emits the
//     data frame (plus a parity frame once per group) on the QUIC DATAGRAM channel.
//  3. A background loop reads inbound datagrams: feedback frames adapt our
//     Encoder; data/parity frames are FEC-decoded and routed (by assocID) to
//     Receive callers. Observed loss is reported back every lossReportInterval.

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"chimera/internal/carrier"
	"chimera/internal/fec"
	"chimera/internal/tunnel"
)

// udpAssocReplyTimeout bounds the wait for the server's CmdUDPAssoc reply.
const udpAssocReplyTimeout = 10 * time.Second

// inboundQueue bounds buffered inbound datagrams; overflow drops oldest-style
// (UDP semantics: loss is acceptable, back-pressure is not).
const inboundQueue = 256

var errAssocRefused = errors.New("quic udp: server refused association")

// udpCarrier is the client-side UDP multiplexer over one QUIC connection.
type udpCarrier struct {
	conn *quic.Conn
	cfg  carrier.Config
	enc  *fec.Encoder
	dec  *fec.Decoder

	inbound   chan inboundDatagram
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
}

type inboundDatagram struct {
	assoc   uint16
	payload []byte
}

// DialUDP opens a QUIC carrier connection ready to host UDP associations.
// Registered as carrier.QUICDialUDP.
func DialUDP(cfg carrier.Config) (carrier.UDPCarrier, error) {
	conn, err := dial(cfg)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	u := &udpCarrier{
		conn:    conn,
		cfg:     cfg,
		enc:     fec.NewEncoder(defaultFECLoss),
		dec:     fec.NewDecoder(0),
		inbound: make(chan inboundDatagram, inboundQueue),
		ctx:     ctx,
		cancel:  cancel,
	}
	go u.receiveLoop()
	return u, nil
}

// OpenAssoc binds host:port on the server and returns the datagram assocID.
func (u *udpCarrier) OpenAssoc(host string, port uint16) (uint16, error) {
	sc, sess, err := authStream(u.conn, u.cfg)
	if err != nil {
		return 0, err
	}
	// The association lives at the connection/datagram level; the control stream
	// is only needed for the request/reply, so close just the stream (NOT the
	// whole connection, which streamConn.Close would do).
	defer sc.Stream.Close()

	if err := sess.WriteUDPAssoc(sc, host, port); err != nil {
		return 0, err
	}
	_ = sc.SetReadDeadline(time.Now().Add(udpAssocReplyTimeout))
	ok, assocID, err := sess.ReadUDPAssocReply(sc)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, errAssocRefused
	}
	return assocID, nil
}

// Send forwards payload to the target bound to assocID. Best-effort: an oversized
// datagram (exceeds path MTU) is dropped, matching UDP's no-fragmentation model.
func (u *udpCarrier) Send(assocID uint16, payload []byte) error {
	dgram := tunnel.WrapDatagram(assocID, payload)
	data, parity := u.enc.AddData(dgram)
	if err := u.conn.SendDatagram(data); err != nil {
		var mtuErr *quic.DatagramTooLargeError
		if errors.As(err, &mtuErr) {
			slog.Debug("quic udp send: datagram exceeds path MTU, dropped",
				"assoc", assocID, "payload_bytes", len(payload))
			return nil
		}
		return err
	}
	if parity != nil {
		// Parity is best-effort: failure just leaves this group unprotected.
		if err := u.conn.SendDatagram(parity); err != nil {
			slog.Debug("quic udp send: parity failed", "assoc", assocID, "err", err)
		}
	}
	return nil
}

// Receive blocks for the next inbound datagram from any association.
func (u *udpCarrier) Receive(ctx context.Context) (uint16, []byte, error) {
	select {
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	case <-u.ctx.Done():
		return 0, nil, net.ErrClosed
	case d := <-u.inbound:
		return d.assoc, d.payload, nil
	}
}

// Close tears down the carrier connection and stops the receive loop.
func (u *udpCarrier) Close() error {
	u.closeOnce.Do(func() {
		u.cancel()
		_ = u.conn.CloseWithError(0, "")
	})
	return nil
}

// receiveLoop reads inbound QUIC datagrams, decodes FEC, routes payloads by
// assocID, and closes the loss-feedback loop (mirrors runDatagramDispatch).
func (u *udpCarrier) receiveLoop() {
	seen := 0
	for {
		raw, err := u.conn.ReceiveDatagram(u.ctx)
		if err != nil {
			return
		}
		if fec.IsFeedback(raw) {
			if loss, ok := fec.ParseFeedback(raw); ok {
				u.enc.SetLoss(loss)
			}
			continue
		}
		payload, isData, recovered := u.dec.Add(raw)
		if isData {
			u.route(payload)
		}
		if recovered != nil {
			u.route(recovered)
		}
		if seen++; seen%lossReportInterval == 0 {
			if err := u.conn.SendDatagram(fec.MakeFeedback(u.dec.LossEstimate())); err != nil {
				slog.Debug("quic udp feedback send failed", "err", err)
			}
		}
	}
}

// route unwraps an assocID-prefixed datagram and queues it for Receive. Drops on
// a full queue (UDP semantics) rather than blocking the receive loop.
func (u *udpCarrier) route(wrapped []byte) {
	assoc, payload, ok := tunnel.UnwrapDatagram(wrapped)
	if !ok {
		return
	}
	cp := append([]byte(nil), payload...)
	select {
	case u.inbound <- inboundDatagram{assoc: assoc, payload: cp}:
	default:
		slog.Debug("quic udp inbound queue full, dropped", "assoc", assoc)
	}
}
