//go:build chimera_quic

package quic

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"

	"github.com/quic-go/quic-go"

	"chimera/internal/carrier"
	"chimera/internal/rudp"
	"chimera/internal/tunnel"
	"chimera/internal/vision"
)

// quicSendQueue is the depth of the adapter's outbound datagram buffer. It
// absorbs short bursts from rudp's transmit loop; when full, frames are dropped
// (see Send) rather than blocking.
const quicSendQueue = 256

// quicDatagram adapts a QUIC connection's RFC 9221 datagram channel to
// rudp.Datagram, letting a reliable, FEC-protected bytestream (internal/rudp)
// ride unreliable QUIC datagrams as a bulk sub-mode. This is the transport that
// can actually hold goodput under 30–40 % loss, where a reliable QUIC *stream*
// collapses: rudp repairs most loss with FEC (no RTT) and ARQ only mops up the
// rest. rudp must never run over a reliable stream — that would double the ARQ.
//
// Critically, Send must be non-blocking. quic-go's SendDatagram blocks once its
// 32-frame send queue fills; if rudp called it inline, a receiver's read loop
// would block sending an ACK, stop draining inbound datagrams, and deadlock both
// peers. Instead Send hands frames to a dedicated goroutine through a buffered
// channel and drops on overflow — the correct unreliable-datagram behavior,
// which rudp's FEC + ARQ recover from and whose drops feed its loss-based
// congestion control as natural back-pressure.
//
// The QUIC connection is owned by the caller (one connection may carry other
// associations), so Close only stops the send goroutine; it does not close the
// connection.
type quicDatagram struct {
	conn   *quic.Conn
	sendCh chan []byte
	ctx    context.Context
	cancel context.CancelFunc
}

// newQUICDatagram wraps conn as an rudp.Datagram and starts its send pump.
func newQUICDatagram(conn *quic.Conn) rudp.Datagram {
	ctx, cancel := context.WithCancel(context.Background())
	q := &quicDatagram{
		conn:   conn,
		sendCh: make(chan []byte, quicSendQueue),
		ctx:    ctx,
		cancel: cancel,
	}
	go q.sendLoop()
	return q
}

// sendLoop drains queued frames onto the QUIC datagram channel. SendDatagram may
// block here (that is fine — this goroutine does nothing else); an oversized
// frame is dropped, and a real connection error ends the pump (rudp surfaces the
// failure via Recv).
func (q *quicDatagram) sendLoop() {
	for {
		select {
		case <-q.ctx.Done():
			return
		case frame := <-q.sendCh:
			if err := q.conn.SendDatagram(frame); err != nil {
				var tooLarge *quic.DatagramTooLargeError
				if errors.As(err, &tooLarge) {
					continue // drop; ARQ recovers
				}
				return // connection error: stop pumping
			}
		}
	}
}

// Send enqueues a frame for transmission without blocking, dropping it if the
// queue is full. The frame is copied because the caller owns it only for the
// duration of the call but transmission is deferred to sendLoop.
func (q *quicDatagram) Send(frame []byte) error {
	cp := append([]byte(nil), frame...)
	select {
	case q.sendCh <- cp:
	default: // queue full → drop; rudp FEC/ARQ + congestion control handle it
	}
	return nil
}

// Recv blocks for the next QUIC datagram.
func (q *quicDatagram) Recv(ctx context.Context) ([]byte, error) {
	return q.conn.ReceiveDatagram(ctx)
}

// Close stops the send pump. The QUIC connection outlives any single rudp stream.
func (q *quicDatagram) Close() error {
	q.cancel()
	return nil
}

// rudpRelayCfg is the rudp configuration for the carrier bulk sub-mode. MSS is
// conservative so a frame plus rudp+FEC headers stays under the QUIC datagram
// path MTU on a real 1500-byte network; FEC is on for loss resilience.
func rudpRelayCfg() rudp.Config {
	return rudp.Config{MSS: 1000, FEC: true}
}

// rudpCarrierConn is the client-side relay net.Conn: an rudp bytestream over the
// QUIC datagram channel, bundled with the authenticated control stream and the
// owning QUIC connection so closing it tears everything down in order.
type rudpCarrierConn struct {
	*rudp.Conn
	ctrl  *streamConn
	qconn *quic.Conn
}

// Close flushes the rudp stream (delivering buffered data + FIN), then closes the
// control stream and the QUIC connection.
func (r *rudpCarrierConn) Close() error {
	err := r.Conn.Close()
	_ = r.ctrl.Close() // streamConn.Close also closes the QUIC connection
	return err
}

// DialConnectRUDP opens a QUIC carrier, authenticates a control stream, requests
// a CmdConnectRUDP tunnel to host:port, and on success returns a relay net.Conn
// whose bulk bytes ride the reliable-FEC datagram transport over QUIC datagrams.
// Registered as carrier.QUICDialConnectRUDP (Transport "quic-rudp").
//
// Benchmarks in docs/reliable-fec-transport.md showed that this experiment is
// correct but not faster than the normal QUIC stream with ElasticCC, so it is
// intentionally not the default bulk path.
//
// The connection is dedicated to this one rudp stream: the datagram channel is
// owned exclusively by rudp, so this dialer must not be connection-pooled with
// UDP associations.
func DialConnectRUDP(cfg carrier.Config, host string, port uint16) (net.Conn, error) {
	conn, err := dial(cfg)
	if err != nil {
		return nil, err
	}
	sc, sess, err := authStream(conn, cfg)
	if err != nil {
		_ = conn.CloseWithError(0, "")
		return nil, err
	}
	if err := sess.WriteConnectRUDP(sc, host, port); err != nil {
		_ = conn.CloseWithError(0, "")
		return nil, err
	}
	ok, err := sess.ReadStatus(sc)
	if err != nil {
		_ = conn.CloseWithError(0, "")
		return nil, err
	}
	if !ok {
		_ = conn.CloseWithError(0, "")
		return nil, errors.New("quic carrier: server refused CONNECT (rudp; upstream dial failed)")
	}
	rc := rudp.NewConn(newQUICDatagram(conn), rudpRelayCfg())
	return &rudpCarrierConn{Conn: rc, ctrl: sc, qconn: conn}, nil
}

// serveRUDPConnect is the server side of CmdConnectRUDP: dial the target, ack the
// client on the control stream, then relay between the target and an rudp stream
// carried over this connection's QUIC datagram channel. The connection must not
// be running the UDP datagram-dispatch loop (it is started lazily only for
// CmdUDPAssoc), so rudp owns the datagram channel.
func serveRUDPConnect(conn *quic.Conn, sess *tunnel.Session, rw io.ReadWriteCloser, host string, port uint16) {
	target, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		_ = sess.WriteStatus(rw, false)
		return
	}
	defer target.Close()
	if err := sess.WriteStatus(rw, true); err != nil {
		return
	}
	rc := rudp.NewConn(newQUICDatagram(conn), rudpRelayCfg())
	defer rc.Close()
	vision.Splice(rc, target)
}
