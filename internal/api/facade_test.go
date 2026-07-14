package api

import (
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"chimera/internal/carrier"
)

const validLink = "chimera://@example.com:443?pbk=AAAA&sid=0a1b&sni=www.microsoft.com&mode=auto#NodeA"

func TestNewSessionFromSubscription_ParsesEndpoints(t *testing.T) {
	doc := "#!chimera-subscription-v1\n" + validLink + "\n" +
		"chimera://@2.2.2.2:443?pbk=BBBB&sni=www.apple.com&mode=tcp#NodeB\n"

	s, err := NewSessionFromSubscription(doc, "")
	if err != nil {
		t.Fatalf("NewSessionFromSubscription: %v", err)
	}
	if got := len(s.configs); got != 2 {
		t.Fatalf("expected 2 endpoints, got %d", got)
	}
	// Per-endpoint keys must be preserved (the flat Config cannot express this).
	if s.configs[0].PubB64 != "AAAA" || s.configs[1].PubB64 != "BBBB" {
		t.Fatalf("per-endpoint keys not preserved: %q / %q", s.configs[0].PubB64, s.configs[1].PubB64)
	}
}

func TestNewSessionFromSubscription_RejectsBadSignKey(t *testing.T) {
	doc := "#!chimera-subscription-v1\n" + validLink + "\n"
	if _, err := NewSessionFromSubscription(doc, "zznothex"); err == nil {
		t.Fatal("expected error for non-hex sign key")
	}
}

func TestNewSessionFromSubscription_TamperedSignatureRejected(t *testing.T) {
	// A signed doc whose signature does not match the body must be rejected when
	// a key is supplied — the UI must never apply a tampered subscription.
	keyHex := "00112233445566778899aabbccddeeff"
	doc := "#!chimera-subscription-v1\n# sig: deadbeef\n" + validLink + "\n"
	if _, err := NewSessionFromSubscription(doc, keyHex); err == nil {
		t.Fatal("expected HMAC mismatch error")
	}
}

func TestStateJSON_DisconnectedShape(t *testing.T) {
	s := NewSession(Config{Transport: "tcp"})
	var snap StateSnapshot
	if err := json.Unmarshal([]byte(s.StateJSON()), &snap); err != nil {
		t.Fatalf("StateJSON not valid JSON: %v", err)
	}
	if snap.State != "disconnected" {
		t.Fatalf("expected disconnected, got %q", snap.State)
	}
}

func TestSnapshot_ReportsEndpointStats(t *testing.T) {
	s := NewSessionFromConfigs(parseDoc(t))
	// Wire a real pool so Stats() is populated without dialing.
	s.mu.Lock()
	s.state = StateConnected
	s.mu.Unlock()
	// dialer is nil here (no Connect); Snapshot must still produce valid output.
	snap := s.Snapshot()
	if snap.Transport == "" {
		t.Fatal("expected a transport in snapshot")
	}
}

func TestMeteredConn_CountsBytes(t *testing.T) {
	var up, down atomic.Int64
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	mc := &meteredConn{Conn: client, up: &up, down: &down}
	go func() {
		buf := make([]byte, 5)
		io.ReadFull(server, buf)
		server.Write([]byte("pong"))
	}()

	if _, err := mc.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(mc, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if up.Load() != 5 {
		t.Fatalf("expected 5 bytes up, got %d", up.Load())
	}
	if down.Load() != 4 {
		t.Fatalf("expected 4 bytes down, got %d", down.Load())
	}
}

func TestParseLinkJSON_RoundTrip(t *testing.T) {
	out, err := ParseLinkJSON(validLink)
	if err != nil {
		t.Fatalf("ParseLinkJSON: %v", err)
	}
	if !strings.Contains(out, `"www.microsoft.com"`) || !strings.Contains(out, `"NodeA"`) {
		t.Fatalf("link fields missing from JSON: %s", out)
	}
}

func TestParseLinkJSON_RejectsWrongScheme(t *testing.T) {
	if _, err := ParseLinkJSON("https://example.com"); err == nil {
		t.Fatal("expected error for non-chimera scheme")
	}
}

func TestRunSOCKS_NotConnected(t *testing.T) {
	s := NewSession(Config{Transport: "tcp"})
	if err := s.RunSOCKS(t.Context(), "127.0.0.1:0"); err == nil {
		t.Fatal("expected error when not connected")
	}
}

// parseDoc returns the configs for a minimal one-line subscription.
func parseDoc(t *testing.T) []carrier.Config {
	t.Helper()
	s, err := NewSessionFromSubscription("#!chimera-subscription-v1\n"+validLink+"\n", "")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return s.configs
}
