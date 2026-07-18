//go:build chimera_quic

package quic

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

const maxUDPRead = 65507

var nextAssocID atomic.Uint32

const defaultFECLoss = 0.1

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

func (m *datagramMux) ensureDispatch() {
	m.dispatch.Do(func() {
		go runDatagramDispatch(m.ctx, m.conn, m)
	})
}

func (m *datagramMux) Register(ctx context.Context, targetAddr string) (uint16, error) {
	raddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		return 0, err
	}
	uc, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return 0, err
	}

	id := uint16(nextAssocID.Add(1) & 0x7FFF)

	m.mu.Lock()
	m.socs[id] = uc
	m.mu.Unlock()

	go m.udpToQuic(ctx, id, uc)
	return id, nil
}

func (m *datagramMux) Dispatch(assocID uint16, payload []byte) {
	m.mu.RLock()
	uc := m.socs[assocID]
	m.mu.RUnlock()
	if uc == nil {
		return
	}
	_, _ = uc.Write(payload)
}

func (m *datagramMux) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, uc := range m.socs {
		uc.Close()
	}
	m.socs = make(map[uint16]*net.UDPConn)
}

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

		dgram := tunnel.WrapDatagram(assocID, buf[:n])
		dataFrame, parityFrame := m.enc.AddData(dgram)
		if err := m.conn.SendDatagram(dataFrame); err != nil {
			var mtuErr *quic.DatagramTooLargeError
			if errors.As(err, &mtuErr) {

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

			if err := m.conn.SendDatagram(parityFrame); err != nil {
				slog.Debug("quic fec parity send failed", "assoc", assocID, "err", err)
			}
		}
	}
}

const lossReportInterval = 64

func runDatagramDispatch(ctx context.Context, conn *quic.Conn, mux *datagramMux) {
	dec := fec.NewDecoder(0)
	seen := 0
	for {
		raw, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}

		if fec.IsFeedback(raw) {
			if loss, ok := fec.ParseFeedback(raw); ok {
				mux.enc.SetLoss(loss)
			}
			continue
		}

		payload, isData, recovered := dec.Add(raw)
		if isData {
			dispatchWrapped(mux, payload)
		}
		if recovered != nil {
			dispatchWrapped(mux, recovered)
		}

		if seen++; seen%lossReportInterval == 0 {
			if err := conn.SendDatagram(fec.MakeFeedback(dec.LossEstimate())); err != nil {
				slog.Debug("quic fec feedback send failed", "err", err)
			}
		}
	}
}

func dispatchWrapped(mux *datagramMux, wrapped []byte) {
	assocID, payload, ok := tunnel.UnwrapDatagram(wrapped)
	if !ok {
		return
	}
	mux.Dispatch(assocID, payload)
}
