//go:build chimera_netstack

// Package netstack turns raw IP packets into TCP/UDP flows and bridges each flow
// to a CHIMERA carrier — the userspace network stack behind a TUN device (or a
// TUN-less packet source). It is compiled in only under the `chimera_netstack`
// build tag so the default binary never imports gVisor.
//
// Architecture (see docs/gvisor-netstack-datapath.md):
//
//	IP packets ─► InjectInbound ─► gVisor netstack ─► tcp/udp.Forwarder
//	                                                       │
//	         TCP flow → TCPDialer.DialConnect(host,port) ──┤ relay
//	         UDP flow → UDPDialer.DialUDPCarrier()/OpenAssoc ┘
//	outbound IP packets ◄─ ReadOutbound (to TUN device / packet sink)
//
// The forwarders reuse the carrier APIs already built: DialConnect (TCP) and
// carrier.UDPCarrier (UDP DATAGRAM, FEC-protected). A real TUN device feeds
// InjectInbound and drains ReadOutbound; tests drive them directly via a software
// loopback, so the whole stack is exercised without privileges.
package netstack

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"

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
	nicID         = tcpip.NICID(1)
	defaultMTU    = 1400 // ≤ carrier path MTU minus QUIC/datagram overhead
	channelQueue  = 512
	tcpMaxInFlight = 1024
	udpReadBuf    = 64 * 1024
	udpFlowQueue  = 64 // per-flow inbound buffer once demuxed off the shared carrier
)

// TCPDialer bridges a TCP flow's original destination to a carrier stream.
// Satisfied by *endpoint.Pool / *endpoint.AutoPool.
type TCPDialer interface {
	DialConnect(host string, port uint16) (net.Conn, error)
}

// UDPDialer bridges a UDP flow to a carrier datagram association. Optional;
// when nil, UDP flows are dropped. Satisfied by *endpoint.Pool / *endpoint.AutoPool.
type UDPDialer interface {
	DialUDPCarrier() (carrier.UDPCarrier, error)
}

// Stack is the userspace network stack. Feed it IP packets with InjectInbound and
// drain its replies with ReadOutbound.
type Stack struct {
	stack *stack.Stack
	ep    *channel.Endpoint
	tcp   TCPDialer
	udp   UDPDialer

	udpCtx    context.Context
	udpCancel context.CancelFunc

	// udpMu guards udpCarrier: the shared, lazily-dialed UDP carrier every
	// flow's association is opened on (see ensureUDPCarrier's doc comment for
	// why a fresh carrier per flow was the bug this replaced).
	udpMu      sync.Mutex
	udpCarrier carrier.UDPCarrier
	// udpFlows demuxes the one shared carrier's Receive loop back to each
	// flow's own inbound channel by assocID.
	udpFlows sync.Map // assocID uint16 -> chan []byte
}

// New builds the stack and installs the TCP/UDP forwarders. tcp is required; udp
// may be nil to disable UDP forwarding.
func New(tcpDialer TCPDialer, udpDialer UDPDialer) (*Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(channelQueue, defaultMTU, "")
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, errFrom("create nic", err)
	}
	// Accept any destination as local (we terminate everything) and any source.
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

// InjectInbound feeds one raw IP packet (from the TUN device / packet source) into
// the stack. The network protocol is inferred from the IP version nibble.
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

// ReadOutbound returns the next IP packet the stack wants to send (to be written to
// the TUN device). Blocks until a packet is available or ctx is done (nil then).
func (s *Stack) ReadOutbound(ctx context.Context) []byte {
	pkt := s.ep.ReadContext(ctx)
	if pkt == nil {
		return nil
	}
	defer pkt.DecRef()
	buf := pkt.ToBuffer()
	return buf.Flatten()
}

// Close tears down the stack, its endpoint, and the shared UDP carrier (if
// one was ever dialed).
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

// handleTCP relays one inbound TCP flow to its original destination via the carrier.
func (s *Stack) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	host := addrToHost(id.LocalAddress)
	port := id.LocalPort

	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		r.Complete(true) // send RST
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

// handleUDP relays one inbound UDP flow to its destination via a carrier
// association. Returns true (request consumed) in all cases.
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

// ensureUDPCarrier returns the shared UDP carrier, dialing it on the first
// call and reusing it for every later flow.
//
// The original version dialed a fresh carrier per flow, i.e. a brand-new
// QUIC connection (full handshake + Reality auth) for every single UDP flow
// netstack sees -- in practice one per DNS query, since a typical resolver
// opens a new ephemeral UDP socket per lookup. That serialized a full
// connection setup in front of every DNS response, comfortably blowing past
// a resolver's few-second timeout, and made every lookup depend on QUIC/UDP
// actually reaching the server even when TCP transport was selected
// (defaultUDPDial forces QUIC because datagrams require it) -- exactly what
// showed up as "connected, but no site loads" / ERR_NAME_NOT_RESOLVED.
//
// carrier.UDPCarrier was already designed to multiplex many associations
// over one connection (OpenAssoc returns a per-flow assocID; the server's
// datagramMux, see internal/quic/datagram.go, already dials/dispatches per
// assocID on a single connection) -- this just makes the client actually use
// that instead of paying a fresh connection per flow.
func (s *Stack) ensureUDPCarrier() (carrier.UDPCarrier, error) {
	s.udpMu.Lock()
	defer s.udpMu.Unlock()
	if s.udpCarrier != nil {
		return s.udpCarrier, nil
	}
	uc, err := s.udp.DialUDPCarrier()
	if err != nil {
		return nil, err
	}
	s.udpCarrier = uc
	go s.udpDispatchLoop(uc)
	return uc, nil
}

// udpDispatchLoop is the single reader of the shared carrier's Receive
// stream: it demuxes inbound datagrams by assocID out to each flow's own
// channel (registered in udpFlows by relayUDP). Runs until the carrier
// errors/closes, at which point every still-registered flow is woken (its
// channel closed) so relayUDP's loop returns instead of blocking forever,
// and the carrier is dropped so the next flow dials a fresh one.
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
				// Flow's inbound buffer is full; drop (UDP semantics -- the
				// alternative is blocking the one shared dispatch loop and
				// stalling every other flow behind a slow reader).
			}
		}
	}
}

// relayUDP bridges one UDP flow to an association on the shared carrier (see
// ensureUDPCarrier).
func (s *Stack) relayUDP(local *gonet.UDPConn, host string, port uint16) {
	defer local.Close()

	uc, err := s.ensureUDPCarrier()
	if err != nil {
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

	// local → carrier
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

	// carrier → local, demuxed by udpDispatchLoop into our own inbound channel.
	for {
		select {
		case <-ctx.Done():
			return
		case payload, ok := <-inbound:
			if !ok {
				return // udpDispatchLoop closed us: the shared carrier died
			}
			if _, err := local.Write(payload); err != nil {
				return
			}
		}
	}
}

// relay copies bidirectionally between a and b, closing both when either side ends.
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

// addrToHost renders a tcpip address as a host string for the carrier dialer.
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
