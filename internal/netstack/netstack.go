//go:build chimera_netstack

package netstack

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"chimera/internal/carrier"
)

const (
	nicID          = tcpip.NICID(1)
	defaultMTU     = 1400
	channelQueue   = 512
	tcpMaxInFlight = 1024
	udpReadBuf     = 64 * 1024
	udpFlowQueue   = 64

	dnsPort           = 53
	dnsOverTCPTimeout = 5 * time.Second

	udpCarrierDialTimeout = 1500 * time.Millisecond

	udpCarrierRetryBackoff = 30 * time.Second
)

var errUDPCarrierSlow = errors.New("netstack: udp carrier dial exceeded fast-fail timeout")

type TCPDialer interface {
	DialConnect(host string, port uint16) (net.Conn, error)
}

type UDPDialer interface {
	DialUDPCarrier() (carrier.UDPCarrier, error)
}

type Stack struct {
	stack *stack.Stack
	ep    *channel.Endpoint
	tcp   TCPDialer
	udp   UDPDialer

	udpCtx    context.Context
	udpCancel context.CancelFunc

	udpMu      sync.Mutex
	udpCarrier carrier.UDPCarrier

	udpDialErr   error
	udpDialErrAt time.Time

	udpFlows sync.Map
}

func New(tcpDialer TCPDialer, udpDialer UDPDialer) (*Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(channelQueue, defaultMTU, "")
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, errFrom("create nic", err)
	}

	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	udpCtx, udpCancel := context.WithCancel(context.Background())
	ns := &Stack{stack: s, ep: ep, tcp: tcpDialer, udp: udpDialer, udpCtx: udpCtx, udpCancel: udpCancel}

	tcpFwd := tcp.NewForwarder(s, 0, tcpMaxInFlight, ns.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(s, ns.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
	return ns, nil
}

func (s *Stack) InjectInbound(ipPacket []byte) {
	if len(ipPacket) == 0 {
		return
	}
	proto := tcpip.NetworkProtocolNumber(header.IPv4ProtocolNumber)
	if ipPacket[0]>>4 == 6 {
		proto = header.IPv6ProtocolNumber
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(ipPacket),
	})
	s.ep.InjectInbound(proto, pkt)
	pkt.DecRef()
}

func (s *Stack) ReadOutbound(ctx context.Context) []byte {
	pkt := s.ep.ReadContext(ctx)
	if pkt == nil {
		return nil
	}
	defer pkt.DecRef()
	buf := pkt.ToBuffer()
	return buf.Flatten()
}

func (s *Stack) Close() {
	s.ep.Close()
	s.stack.Close()
	s.udpCancel()
	s.udpMu.Lock()
	if s.udpCarrier != nil {
		_ = s.udpCarrier.Close()
	}
	s.udpMu.Unlock()
}

func (s *Stack) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	host := addrToHost(id.LocalAddress)
	port := id.LocalPort

	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)
	local := gonet.NewTCPConn(&wq, ep)

	go func() {
		defer local.Close()
		up, err := s.tcp.DialConnect(host, port)
		if err != nil {
			slog.Debug("netstack tcp: carrier dial failed", "target", host, "port", port, "err", err)
			return
		}
		defer up.Close()
		relay(local, up)
	}()
}

func (s *Stack) handleUDP(r *udp.ForwarderRequest) bool {
	id := r.ID()
	host := addrToHost(id.LocalAddress)
	port := id.LocalPort

	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		return true
	}
	local := gonet.NewUDPConn(&wq, ep)

	if s.udp == nil {
		_ = local.Close()
		return true
	}
	go s.relayUDP(local, host, port)
	return true
}

func (s *Stack) ensureUDPCarrier() (carrier.UDPCarrier, error) {
	s.udpMu.Lock()
	if s.udpCarrier != nil {
		uc := s.udpCarrier
		s.udpMu.Unlock()
		return uc, nil
	}
	if s.udpDialErr != nil && time.Since(s.udpDialErrAt) < udpCarrierRetryBackoff {
		err := s.udpDialErr
		s.udpMu.Unlock()
		return nil, err
	}
	s.udpMu.Unlock()

	type dialResult struct {
		uc  carrier.UDPCarrier
		err error
	}
	done := make(chan dialResult, 1)
	go func() {
		uc, err := s.udp.DialUDPCarrier()
		done <- dialResult{uc, err}
	}()

	select {
	case r := <-done:
		s.udpMu.Lock()
		defer s.udpMu.Unlock()
		if r.err != nil {
			s.udpDialErr, s.udpDialErrAt = r.err, time.Now()
			return nil, r.err
		}
		if s.udpCarrier != nil {

			go r.uc.Close()
			return s.udpCarrier, nil
		}
		s.udpCarrier = r.uc
		s.udpDialErr = nil
		go s.udpDispatchLoop(r.uc)
		return r.uc, nil

	case <-time.After(udpCarrierDialTimeout):
		err := errUDPCarrierSlow
		s.udpMu.Lock()
		s.udpDialErr, s.udpDialErrAt = err, time.Now()
		s.udpMu.Unlock()

		go func() {
			r := <-done
			s.udpMu.Lock()
			defer s.udpMu.Unlock()
			select {
			case <-s.udpCtx.Done():
				if r.uc != nil {
					r.uc.Close()
				}
				return
			default:
			}
			if r.err != nil {
				s.udpDialErr, s.udpDialErrAt = r.err, time.Now()
				return
			}
			if s.udpCarrier != nil {
				r.uc.Close()
				return
			}
			s.udpCarrier = r.uc
			s.udpDialErr = nil
			go s.udpDispatchLoop(r.uc)
		}()
		return nil, err
	}
}

func (s *Stack) udpDispatchLoop(uc carrier.UDPCarrier) {
	for {
		assoc, payload, err := uc.Receive(s.udpCtx)
		if err != nil {
			s.udpMu.Lock()
			if s.udpCarrier == uc {
				s.udpCarrier = nil
			}
			s.udpMu.Unlock()
			s.udpFlows.Range(func(key, value any) bool {
				close(value.(chan []byte))
				s.udpFlows.Delete(key)
				return true
			})
			return
		}
		if ch, ok := s.udpFlows.Load(assoc); ok {
			select {
			case ch.(chan []byte) <- payload:
			default:

			}
		}
	}
}

func (s *Stack) relayUDP(local *gonet.UDPConn, host string, port uint16) {
	defer local.Close()

	uc, err := s.ensureUDPCarrier()
	if err != nil {

		if port == dnsPort {
			s.relayDNSOverTCP(local, host)
			return
		}
		slog.Debug("netstack udp: carrier dial failed", "err", err)
		return
	}
	assoc, err := uc.OpenAssoc(host, port)
	if err != nil {
		slog.Debug("netstack udp: open assoc failed", "target", host, "port", port, "err", err)
		return
	}

	inbound := make(chan []byte, udpFlowQueue)
	s.udpFlows.Store(assoc, inbound)
	defer s.udpFlows.Delete(assoc)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		buf := make([]byte, udpReadBuf)
		for {
			n, err := local.Read(buf)
			if err != nil {
				cancel()
				return
			}
			if err := uc.Send(assoc, buf[:n]); err != nil {
				cancel()
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case payload, ok := <-inbound:
			if !ok {
				return
			}
			if _, err := local.Write(payload); err != nil {
				return
			}
		}
	}
}

func (s *Stack) relayDNSOverTCP(local *gonet.UDPConn, host string) {
	buf := make([]byte, udpReadBuf)
	for {
		n, err := local.Read(buf)
		if err != nil {
			return
		}
		query := append([]byte(nil), buf[:n]...)
		resp, err := s.dnsQueryOverTCP(host, query)
		if err != nil {
			slog.Debug("netstack udp: dns-over-tcp fallback failed", "target", host, "err", err)
			continue
		}
		if _, err := local.Write(resp); err != nil {
			return
		}
	}
}

func (s *Stack) dnsQueryOverTCP(host string, query []byte) ([]byte, error) {
	conn, err := s.tcp.DialConnect(host, dnsPort)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(dnsOverTCPTimeout))

	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(query)))
	if _, err := conn.Write(prefix[:]); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(prefix[:]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		_ = dst.Close()
		_ = src.Close()
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

func addrToHost(a tcpip.Address) string {
	return net.IP(a.AsSlice()).String()
}

func errFrom(what string, e tcpip.Error) error {
	return &tcpipError{what: what, e: e}
}

type tcpipError struct {
	what string
	e    tcpip.Error
}

func (e *tcpipError) Error() string { return "netstack: " + e.what + ": " + e.e.String() }
