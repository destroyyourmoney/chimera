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

const quicSendQueue = 256

type quicDatagram struct {
	conn   *quic.Conn
	sendCh chan []byte
	ctx    context.Context
	cancel context.CancelFunc
}

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

func (q *quicDatagram) sendLoop() {
	for {
		select {
		case <-q.ctx.Done():
			return
		case frame := <-q.sendCh:
			if err := q.conn.SendDatagram(frame); err != nil {
				var tooLarge *quic.DatagramTooLargeError
				if errors.As(err, &tooLarge) {
					continue
				}
				return
			}
		}
	}
}

func (q *quicDatagram) Send(frame []byte) error {
	cp := append([]byte(nil), frame...)
	select {
	case q.sendCh <- cp:
	default:
	}
	return nil
}

func (q *quicDatagram) Recv(ctx context.Context) ([]byte, error) {
	return q.conn.ReceiveDatagram(ctx)
}

func (q *quicDatagram) Close() error {
	q.cancel()
	return nil
}

func rudpRelayCfg() rudp.Config {
	return rudp.Config{MSS: 1000, FEC: true}
}

type rudpCarrierConn struct {
	*rudp.Conn
	ctrl  *streamConn
	qconn *quic.Conn
}

func (r *rudpCarrierConn) Close() error {
	err := r.Conn.Close()
	_ = r.ctrl.Close()
	return err
}

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
