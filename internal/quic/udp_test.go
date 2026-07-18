//go:build chimera_quic

package quic

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"chimera/internal/carrier"
)

func startUDPEcho(t *testing.T) (host string, port uint16) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("udp echo listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 65507)
		for {
			n, addr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteToUDP(append([]byte(nil), buf[:n]...), addr)
		}
	}()
	h, p, _ := net.SplitHostPort(pc.LocalAddr().String())
	pn, _ := strconv.Atoi(p)
	return h, uint16(pn)
}

func TestQUICUDPAssocEcho(t *testing.T) {
	addr, pub := startServer(t)
	echoHost, echoPort := startUDPEcho(t)
	cfg := carrier.Config{Server: addr, PubB64: pub, SNI: "example.com", Transport: "quic"}

	uc, err := DialUDP(cfg)
	if err != nil {
		t.Fatalf("dial udp carrier: %v", err)
	}
	defer uc.Close()

	assocID, err := uc.OpenAssoc(echoHost, echoPort)
	if err != nil {
		t.Fatalf("open assoc: %v", err)
	}

	payload := []byte("chimera-udp-roundtrip")
	if err := uc.Send(assocID, payload); err != nil {
		t.Fatalf("send: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	gotAssoc, gotPayload, err := uc.Receive(ctx)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if gotAssoc != assocID {
		t.Fatalf("assoc mismatch: got %d want %d", gotAssoc, assocID)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("echo mismatch: got %q want %q", gotPayload, payload)
	}
}

func TestQUICUDPAssocManyDatagrams(t *testing.T) {
	addr, pub := startServer(t)
	echoHost, echoPort := startUDPEcho(t)
	cfg := carrier.Config{Server: addr, PubB64: pub, SNI: "example.com", Transport: "quic"}

	uc, err := DialUDP(cfg)
	if err != nil {
		t.Fatalf("dial udp carrier: %v", err)
	}
	defer uc.Close()

	assocID, err := uc.OpenAssoc(echoHost, echoPort)
	if err != nil {
		t.Fatalf("open assoc: %v", err)
	}

	const count = 200
	for i := 0; i < count; i++ {
		msg := []byte(fmt.Sprintf("datagram-%d", i))
		if err := uc.Send(assocID, msg); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	seen := map[string]bool{}
	for len(seen) < count {
		_, payload, err := uc.Receive(ctx)
		if err != nil {
			t.Fatalf("received %d/%d before error: %v", len(seen), count, err)
		}
		seen[string(payload)] = true
	}
	if len(seen) != count {
		t.Fatalf("expected %d distinct echoes, got %d", count, len(seen))
	}
}
