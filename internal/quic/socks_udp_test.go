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

func TestSOCKSUDPAssocEndToEnd(t *testing.T) {
	serverAddr, pub := startServer(t)
	echoHost, echoPort := startUDPEcho(t)

	cfg := carrier.Config{Server: serverAddr, PubB64: pub, SNI: "example.com", Transport: "quic"}
	pool := endpoint.NewPool([]carrier.Config{cfg})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("socks listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = socks.ServeListener(ctx, ln, pool) }()

	ctrl, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial socks: %v", err)
	}
	defer ctrl.Close()

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

	if _, err := ctrl.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("associate req: %v", err)
	}

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

func buildSOCKSUDP(host string, port uint16, data []byte) []byte {
	ip := net.ParseIP(host).To4()
	out := []byte{0x00, 0x00, 0x00, 0x01}
	out = append(out, ip...)
	out = append(out, byte(port>>8), byte(port))
	return append(out, data...)
}

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
