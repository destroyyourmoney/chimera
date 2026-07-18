//go:build chimera_netstack

package netstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
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

func (s *Stack) loopback(ctx context.Context) {
	for {
		b := s.ReadOutbound(ctx)
		if b == nil {
			return
		}
		s.InjectInbound(b)
	}
}

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

type fakeTCPDialer struct {
	target string
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

type failingUDPDialer struct{}

func (failingUDPDialer) DialUDPCarrier() (carrier.UDPCarrier, error) {
	return nil, errors.New("no udp carrier")
}

type slowUDPDialer struct{ release chan struct{} }

func (d *slowUDPDialer) DialUDPCarrier() (carrier.UDPCarrier, error) {
	<-d.release
	return nil, errors.New("slow udp dial: network never answered")
}

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

func startDNSOverTCPEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("dns-over-tcp listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				for {
					var prefix [2]byte
					if _, err := io.ReadFull(c, prefix[:]); err != nil {
						return
					}
					msg := make([]byte, binary.BigEndian.Uint16(prefix[:]))
					if _, err := io.ReadFull(c, msg); err != nil {
						return
					}
					if _, err := c.Write(prefix[:]); err != nil {
						return
					}
					if _, err := c.Write(msg); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

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

type fakeUDPCarrierMulti struct {
	mu        sync.Mutex
	nextID    uint16
	in        chan multiDatagram
	done      chan struct{}
	closeOnce sync.Once
}

type multiDatagram struct {
	assoc   uint16
	payload []byte
}

func newFakeUDPCarrierMulti() *fakeUDPCarrierMulti {
	return &fakeUDPCarrierMulti{in: make(chan multiDatagram, 32), done: make(chan struct{})}
}

func (f *fakeUDPCarrierMulti) OpenAssoc(string, uint16) (uint16, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	return f.nextID, nil
}

func (f *fakeUDPCarrierMulti) Send(assoc uint16, payload []byte) error {
	select {
	case f.in <- multiDatagram{assoc: assoc, payload: append([]byte(nil), payload...)}:
	case <-f.done:
	}
	return nil
}

func (f *fakeUDPCarrierMulti) Receive(ctx context.Context) (uint16, []byte, error) {
	select {
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	case <-f.done:
		return 0, nil, io.EOF
	case d := <-f.in:
		return d.assoc, d.payload, nil
	}
}

func (f *fakeUDPCarrierMulti) Close() error {
	f.closeOnce.Do(func() { close(f.done) })
	return nil
}

type countingUDPDialer struct {
	mu    sync.Mutex
	count int
	c     *fakeUDPCarrierMulti
}

func (d *countingUDPDialer) DialUDPCarrier() (carrier.UDPCarrier, error) {
	d.mu.Lock()
	d.count++
	d.mu.Unlock()
	return d.c, nil
}

func TestNetstackUDPForward_SharesOneCarrierAcrossFlows(t *testing.T) {
	fc := newFakeUDPCarrierMulti()
	dialer := &countingUDPDialer{c: fc}
	ns, err := New(&fakeTCPDialer{}, dialer)
	if err != nil {
		t.Fatalf("new stack: %v", err)
	}
	defer ns.Close()
	ns.addClientAddr(t, [4]byte{10, 0, 0, 1})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go ns.loopback(ctx)

	laddr := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4([4]byte{10, 0, 0, 1})}
	dial := func(port uint16) *gonet.UDPConn {
		t.Helper()
		raddr := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4([4]byte{10, 0, 0, 53}), Port: port}
		conn, err := gonet.DialUDP(ns.stack, &laddr, &raddr, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatalf("dial udp through netstack: %v", err)
		}
		return conn
	}
	roundtrip := func(conn *gonet.UDPConn, msg string) {
		t.Helper()
		if _, err := conn.Write([]byte(msg)); err != nil {
			t.Fatalf("write: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		got := make([]byte, 1500)
		n, err := conn.Read(got)
		if err != nil {
			t.Fatalf("read echo: %v", err)
		}
		if string(got[:n]) != msg {
			t.Fatalf("udp echo = %q, want %q", got[:n], msg)
		}
	}

	conn1 := dial(53)
	defer conn1.Close()
	conn2 := dial(5353)
	defer conn2.Close()

	roundtrip(conn1, "query-a")
	roundtrip(conn2, "query-b")

	dialer.mu.Lock()
	got := dialer.count
	dialer.mu.Unlock()
	if got != 1 {
		t.Fatalf("DialUDPCarrier called %d times across 2 flows, want exactly 1 (flows must share one carrier)", got)
	}
}

func TestNetstackDNSFallsBackToTCPWhenUDPCarrierUnavailable(t *testing.T) {
	fd := &fakeTCPDialer{target: startDNSOverTCPEcho(t)}
	ns, err := New(fd, failingUDPDialer{})
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

	query := []byte("fake-dns-query")
	if _, err := conn.Write(query); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, 1500)
	n, err := conn.Read(got)
	if err != nil {
		t.Fatalf("read dns-over-tcp answer: %v", err)
	}
	if !bytes.Equal(got[:n], query) {
		t.Fatalf("answer = %q, want %q (echoed query)", got[:n], query)
	}

	if host, port := fd.seen(); host != "10.0.0.53" || port != 53 {
		t.Fatalf("tcp fallback dialed %s:%d, want 10.0.0.53:53", host, port)
	}
}

func TestNetstackDNSFallsBackFastWhenUDPCarrierDialIsSlow(t *testing.T) {
	dialer := &slowUDPDialer{release: make(chan struct{})}
	defer close(dialer.release)

	fd := &fakeTCPDialer{target: startDNSOverTCPEcho(t)}
	ns, err := New(fd, dialer)
	if err != nil {
		t.Fatalf("new stack: %v", err)
	}
	defer ns.Close()
	ns.addClientAddr(t, [4]byte{10, 0, 0, 1})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go ns.loopback(ctx)

	laddr := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4([4]byte{10, 0, 0, 1})}
	dial := func() *gonet.UDPConn {
		t.Helper()
		raddr := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4([4]byte{10, 0, 0, 53}), Port: 53}
		conn, err := gonet.DialUDP(ns.stack, &laddr, &raddr, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatalf("dial udp through netstack: %v", err)
		}
		return conn
	}
	query := func(conn *gonet.UDPConn, msg string, budget time.Duration) {
		t.Helper()
		start := time.Now()
		if _, err := conn.Write([]byte(msg)); err != nil {
			t.Fatalf("write: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(budget))
		got := make([]byte, 1500)
		n, err := conn.Read(got)
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("read dns-over-tcp answer within %v budget: %v (elapsed %v)", budget, err, elapsed)
		}
		if string(got[:n]) != msg {
			t.Fatalf("answer = %q, want %q", got[:n], msg)
		}
		if elapsed > budget {
			t.Fatalf("answer took %v, want under %v (a real resolver would have given up)", elapsed, budget)
		}
	}

	conn1 := dial()
	defer conn1.Close()
	query(conn1, "first-query", 2*time.Second)

	conn2 := dial()
	defer conn2.Close()
	query(conn2, "second-query", 500*time.Millisecond)
}
