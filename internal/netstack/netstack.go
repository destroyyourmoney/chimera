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
	nicID         = tcpip.NICID(1)
	defaultMTU    = 1400 // ≤ carrier path MTU minus QUIC/datagram overhead
	channelQueue  = 512
	tcpMaxInFlight = 1024
	udpReadBuf    = 64 * 1024
	udpFlowQueue  = 64 // per-flow inbound buffer once demuxed off the shared carrier

	dnsPort           = 53
	dnsOverTCPTimeout = 5 * time.Second

	// udpCarrierDialTimeout bounds how long a flow waits on a UDP/QUIC
	// carrier dial before treating it as unavailable. A real QUIC dial
	// failure (handshake/idle timeout) can take 10s of seconds -- far past
	// what any DNS resolver waits (nslookup: 2s, most browsers: a few
	// seconds), so waiting for the real failure before falling back to
	// DNS-over-TCP (relayDNSOverTCP) means the fallback always loses the
	// race against the resolver giving up first. See ensureUDPCarrier.
	udpCarrierDialTimeout = 1500 * time.Millisecond
	// udpCarrierRetryBackoff: once a dial has been given up on as slow/failed,
	// don't retry it for every subsequent flow (each DNS query is its own UDP
	// flow) -- that would just serialize every query behind another doomed
	// multi-second dial. Recheck after this backoff in case the network
	// recovered.
	udpCarrierRetryBackoff = 30 * time.Second
)

// errUDPCarrierSlow is returned by ensureUDPCarrier when the dial hasn't
// finished within udpCarrierDialTimeout; the real dial keeps running in the
// background (see ensureUDPCarrier's doc comment).
var errUDPCarrierSlow = errors.New("netstack: udp carrier dial exceeded fast-fail timeout")

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
	// udpDialErr/udpDialErrAt cache the outcome of the last dial attempt that
	// was given up on as slow (see udpCarrierDialTimeout) so flows arriving
	// within udpCarrierRetryBackoff fail fast instead of piling up behind
	// another doomed dial.
	udpDialErr   error
	udpDialErrAt time.Time
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
//
// The dial itself is bounded by udpCarrierDialTimeout and run in the
// background rather than held under udpMu: a real QUIC dial failure
// (handshake/idle timeout deep in quic-go) can take far longer than any DNS
// resolver waits, so a flow gives up and reports "unavailable" quickly
// (falling through to relayDNSOverTCP for DNS) while the slow dial keeps
// running -- if it eventually succeeds, a later flow picks up the now-ready
// shared carrier. A short failure cache (udpDialErr/At) keeps the next
// flows -- e.g. every retry a stub resolver sends -- from each queuing up
// behind their own doomed dial attempt.
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
			// Another flow's dial (or a previous slow one finishing late,
			// see below) already won; don't leak this one.
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
		// Let the real dial keep running; if it eventually succeeds, make it
		// available to later flows instead of throwing the connection away.
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
		// No UDP/QUIC carrier available (e.g. transport is "tcp", or the
		// server is unreachable over QUIC). Datagrams in general have no
		// TCP equivalent, but DNS -- overwhelmingly the dominant UDP flow a
		// resolver opens -- has a standard TCP framing (RFC 1035 §4.2.2), so
		// answer just that case over the carrier's already-working TCP
		// CONNECT path instead of silently dropping every lookup.
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

// relayDNSOverTCP answers DNS queries on one UDP flow by round-tripping each
// query over the carrier's TCP CONNECT path (see relayUDP's fallback comment).
// Every datagram the resolver sends is one complete DNS message, so each is
// answered independently over its own short-lived carrier stream.
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

// dnsQueryOverTCP sends one DNS message to host:53 through the carrier's TCP
// CONNECT path and returns the answer, using the RFC 1035 §4.2.2 TCP framing
// (a 2-byte big-endian length prefix before the message on both directions).
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
