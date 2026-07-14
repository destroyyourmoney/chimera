//go:build chimera_quic

package quic

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"chimera/internal/carrier"
	"chimera/internal/endpoint"
	"chimera/internal/socks"
)

// TestSOCKSUDPAssocEndToEnd drives the whole UDP path from a real SOCKS5 client:
// SOCKS UDP ASSOCIATE → local relay → endpoint.Pool → QUIC carrier (FEC) → server
// → real UDP echo target → back. It proves the SOCKS5 UDP ASSOCIATE inbound works
// over the loss-resilient datagram carrier.
func TestSOCKSUDPAssocEndToEnd(t *testing.T) {
	serverAddr, pub := startServer(t)
	echoHost, echoPort := startUDPEcho(t)

	cfg := carrier.Config{Server: serverAddr, PubB64: pub, SNI: "example.com", Transport: "quic"}
	pool := endpoint.NewPool([]carrier.Config{cfg}) // *Pool implements endpoint.UDPDialer

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("socks listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = socks.ServeListener(ctx, ln, pool) }()

	// --- act as a SOCKS5 client ---
	ctrl, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial socks: %v", err)
	}
	defer ctrl.Close()

	// greeting: VER=5, 1 method, no-auth
	if _, err := ctrl.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := readFull(t, ctrl, resp); err != nil {
		t.Fatalf("greeting reply: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("greeting reply = %v", resp)
	}

	// UDP ASSOCIATE request with DST 0.0.0.0:0 (client doesn't pre-declare source)
	if _, err := ctrl.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("associate req: %v", err)
	}
	// reply: VER REP RSV ATYP(=1 IPv4) ADDR(4) PORT(2)
	rep := make([]byte, 10)
	if _, err := readFull(t, ctrl, rep); err != nil {
		t.Fatalf("associate reply: %v", err)
	}
	if rep[0] != 0x05 || rep[1] != 0x00 {
		t.Fatalf("associate reply status = %v", rep[:2])
	}
	relayIP := net.IPv4(rep[4], rep[5], rep[6], rep[7])
	relayPort := int(rep[8])<<8 | int(rep[9])
	relayAddr := &net.UDPAddr{IP: relayIP, Port: relayPort}

	// Send a UDP datagram via the relay, addressed to the echo server.
	uc, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer uc.Close()

	payload := []byte("socks-udp-roundtrip")
	dgram := buildSOCKSUDP(echoHost, echoPort, payload)
	if _, err := uc.Write(dgram); err != nil {
		t.Fatalf("write relay: %v", err)
	}

	_ = uc.SetReadDeadline(time.Now().Add(5 * time.Second))
	in := make([]byte, 65535)
	n, err := uc.Read(in)
	if err != nil {
		t.Fatalf("read relay: %v", err)
	}
	gotHost, gotPort, gotData, ok := parseSOCKSUDP(in[:n])
	if !ok {
		t.Fatalf("malformed relay reply: %x", in[:n])
	}
	if gotHost != echoHost || gotPort != echoPort {
		t.Fatalf("reply target = %s:%d, want %s:%d", gotHost, gotPort, echoHost, echoPort)
	}
	if !bytes.Equal(gotData, payload) {
		t.Fatalf("echo = %q, want %q", gotData, payload)
	}
}

// buildSOCKSUDP wraps data in a SOCKS5 UDP datagram targeting host:port (IPv4).
func buildSOCKSUDP(host string, port uint16, data []byte) []byte {
	ip := net.ParseIP(host).To4()
	out := []byte{0x00, 0x00, 0x00, 0x01}
	out = append(out, ip...)
	out = append(out, byte(port>>8), byte(port))
	return append(out, data...)
}

// parseSOCKSUDP extracts host/port/data from a SOCKS5 UDP datagram (IPv4 only).
func parseSOCKSUDP(b []byte) (host string, port uint16, data []byte, ok bool) {
	if len(b) < 10 || b[3] != 0x01 {
		return "", 0, nil, false
	}
	host = net.IP(b[4:8]).String()
	port = uint16(b[8])<<8 | uint16(b[9])
	return host, port, b[10:], true
}

func readFull(t *testing.T, c net.Conn, b []byte) (int, error) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := 0
	for got < len(b) {
		n, err := c.Read(b[got:])
		if err != nil {
			return got, err
		}
		got += n
	}
	return got, nil
}
