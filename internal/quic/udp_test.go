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

// startUDPEcho starts a UDP echo server and returns its host and port. Each
// received datagram is echoed back to its sender verbatim.
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

// TestQUICUDPAssocEcho proves the full client↔server UDP datagram path end to end
// over the QUIC carrier: OpenAssoc → Send → (server forwards to a real UDP echo
// server) → server relays the echo back as a QUIC datagram → Receive. This
// exercises the FEC framing in BOTH directions on a live connection.
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

// TestQUICUDPAssocManyDatagrams drives enough datagrams through the association to
// trigger FEC group/parity emission and the periodic loss-feedback frames in both
// directions, confirming the steady-state datagram path stays correct under volume.
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

	// Enough to cross lossReportInterval (64) so feedback frames flow both ways.
	const count = 200
	for i := 0; i < count; i++ {
		msg := []byte(fmt.Sprintf("datagram-%d", i))
		if err := uc.Send(assocID, msg); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}

	// Collect echoes. On a loopback link there is no real loss, so every datagram
	// should come back; allow a short drain window and a small tolerance for any
	// reordering/scheduling slack.
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
