//go:build chimera_netstack

package netstack

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"chimera/internal/carrier"
)

// loopback pumps the stack's outbound packets back in as inbound, so a gonet
// client on the same stack reaches the forwarders — a privilege-free stand-in for
// a TUN device.
func (s *Stack) loopback(ctx context.Context) {
	for {
		b := s.ReadOutbound(ctx)
		if b == nil {
			return
		}
		s.InjectInbound(b)
	}
}

// addClientAddr assigns a source address so the test's gonet client has one; the
// forwarders accept any destination via promiscuous mode regardless.
func (s *Stack) addClientAddr(t *testing.T, ip [4]byte) {
	t.Helper()
	err := s.stack.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4(ip), PrefixLen: 24},
	}, stack.AddressProperties{})
	if err != nil {
		t.Fatalf("add client addr: %v", err)
	}
}

// --- fakes ---

type fakeTCPDialer struct {
	target string // real loopback echo to relay to
	mu     sync.Mutex
	host   string
	port   uint16
}

func (f *fakeTCPDialer) DialConnect(host string, port uint16) (net.Conn, error) {
	f.mu.Lock()
	f.host, f.port = host, port
	f.mu.Unlock()
	return net.Dial("tcp", f.target)
}

func (f *fakeTCPDialer) seen() (string, uint16) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.host, f.port
}

// fakeUDPCarrier echoes every Send back through Receive.
type fakeUDPCarrier struct {
	in   chan []byte
	once sync.Once
	done chan struct{}
}

func newFakeUDPCarrier() *fakeUDPCarrier {
	return &fakeUDPCarrier{in: make(chan []byte, 16), done: make(chan struct{})}
}
func (f *fakeUDPCarrier) OpenAssoc(string, uint16) (uint16, error) { return 1, nil }
func (f *fakeUDPCarrier) Send(_ uint16, payload []byte) error {
	select {
	case f.in <- append([]byte(nil), payload...):
	case <-f.done:
	}
	return nil
}
func (f *fakeUDPCarrier) Receive(ctx context.Context) (uint16, []byte, error) {
	select {
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	case <-f.done:
		return 0, nil, io.EOF
	case p := <-f.in:
		return 1, p, nil
	}
}
func (f *fakeUDPCarrier) Close() error { f.once.Do(func() { close(f.done) }); return nil }

type fakeUDPDialer struct{ c *fakeUDPCarrier }

func (d fakeUDPDialer) DialUDPCarrier() (carrier.UDPCarrier, error) { return d.c, nil }

// --- helpers ---

func startTCPEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	return ln.Addr().String()
}

// --- tests ---

func TestNetstackTCPForward(t *testing.T) {
	fd := &fakeTCPDialer{target: startTCPEcho(t)}
	ns, err := New(fd, nil)
	if err != nil {
		t.Fatalf("new stack: %v", err)
	}
	defer ns.Close()
	ns.addClientAddr(t, [4]byte{10, 0, 0, 1})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go ns.loopback(ctx)

	dst := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4([4]byte{10, 0, 0, 99}), Port: 8080}
	conn, err := gonet.DialContextTCP(ctx, ns.stack, dst, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("dial through netstack: %v", err)
	}
	defer conn.Close()

	msg := []byte("netstack-tcp-roundtrip")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo = %q, want %q", got, msg)
	}

	// The forwarder must have handed the ORIGINAL destination to the carrier dialer.
	if host, port := fd.seen(); host != "10.0.0.99" || port != 8080 {
		t.Fatalf("carrier dialed %s:%d, want 10.0.0.99:8080", host, port)
	}
}

func TestNetstackUDPForward(t *testing.T) {
	fc := newFakeUDPCarrier()
	ns, err := New(&fakeTCPDialer{}, fakeUDPDialer{c: fc})
	if err != nil {
		t.Fatalf("new stack: %v", err)
	}
	defer ns.Close()
	ns.addClientAddr(t, [4]byte{10, 0, 0, 1})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go ns.loopback(ctx)

	laddr := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4([4]byte{10, 0, 0, 1})}
	raddr := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4([4]byte{10, 0, 0, 53}), Port: 53}
	conn, err := gonet.DialUDP(ns.stack, &laddr, &raddr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("dial udp through netstack: %v", err)
	}
	defer conn.Close()

	msg := []byte("netstack-udp-roundtrip")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, 1500)
	n, err := conn.Read(got)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got[:n], msg) {
		t.Fatalf("udp echo = %q, want %q", got[:n], msg)
	}
}
