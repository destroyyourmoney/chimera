//go:build chimera_quic

package quic

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

const udpAssocReplyTimeout = 10 * time.Second

const inboundQueue = 256

var errAssocRefused = errors.New("quic udp: server refused association")

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

func (u *udpCarrier) OpenAssoc(host string, port uint16) (uint16, error) {
	sc, sess, err := authStream(u.conn, u.cfg)
	if err != nil {
		return 0, err
	}

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

		if err := u.conn.SendDatagram(parity); err != nil {
			slog.Debug("quic udp send: parity failed", "assoc", assocID, "err", err)
		}
	}
	return nil
}

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

func (u *udpCarrier) Close() error {
	u.closeOnce.Do(func() {
		u.cancel()
		_ = u.conn.CloseWithError(0, "")
	})
	return nil
}

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
