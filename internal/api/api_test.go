package api

import (
	"context"
	"errors"
	"net"
	"testing"

	"chimera/internal/carrier"
	"chimera/internal/endpoint"
)

// mockDialer always returns the provided conn/err.
type mockDialer struct {
	conn net.Conn
	err  error
}

func (m *mockDialer) DialConnect(_ string, _ uint16) (net.Conn, error) {
	return m.conn, m.err
}

// fakeConn is a minimal net.Conn for tests.
type fakeConn struct{ net.Conn }

func (fakeConn) Close() error { return nil }

func TestSession_StateTransitions(t *testing.T) {
	s := NewSession(Config{Transport: "tcp"})
	if s.State() != StateDisconnected {
		t.Fatal("expected Disconnected initially")
	}

	s.mu.Lock()
	s.dialer = &mockDialer{conn: fakeConn{}}
	s.state = StateConnected
	if cancel := s.cancel; cancel == nil {
		ctx, cancel := context.WithCancel(context.Background())
		_ = ctx
		s.cancel = cancel
	}
	s.mu.Unlock()

	if s.State() != StateConnected {
		t.Fatal("expected Connected after manual wire")
	}

	s.Disconnect()
	if s.State() != StateDisconnected {
		t.Fatal("expected Disconnected after Disconnect")
	}
}

func TestSession_DialFailsWhenNotConnected(t *testing.T) {
	s := NewSession(Config{Transport: "tcp"})
	_, err := s.Dial("tcp", "example.com:443")
	if err == nil {
		t.Fatal("expected error when not connected")
	}
}

func TestSession_DialForwardsToDialer(t *testing.T) {
	s := NewSession(Config{Transport: "tcp"})
	expected := fakeConn{}
	s.mu.Lock()
	s.dialer = &mockDialer{conn: expected}
	s.metered = &meteredDialer{inner: s.dialer, up: &s.up, down: &s.down}
	s.state = StateConnected
	ctx, cancel := context.WithCancel(context.Background())
	_ = ctx
	s.cancel = cancel
	s.mu.Unlock()

	conn, err := s.Dial("tcp", "example.com:443")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close()
}

func TestSession_DisconnectIdempotent(t *testing.T) {
	s := NewSession(Config{Transport: "tcp"})
	s.Disconnect() // already disconnected — should not panic
	s.Disconnect()
}

func TestSession_ConnectNoServers(t *testing.T) {
	s := NewSession(Config{Transport: "tcp"}) // no Servers set
	err := s.Connect(context.Background())
	if err == nil {
		t.Fatal("expected error with no servers configured")
	}
	if s.State() != StateDisconnected {
		t.Fatal("expected Disconnected after failed Connect")
	}
}

func TestSession_ConnectSucceedsWhenLaterEndpointPings(t *testing.T) {
	oldPing := pingCarrier
	defer func() { pingCarrier = oldPing }()

	var seen []string
	pingCarrier = func(cfg carrier.Config) error {
		seen = append(seen, cfg.Server)
		if cfg.Server == "bad.example:443" {
			return errors.New("down")
		}
		return nil
	}

	s := NewSession(Config{
		Servers:   []string{"bad.example:443", "good.example:443"},
		PubB64:    "AAAA",
		SNI:       "www.microsoft.com",
		Transport: "tcp",
	})
	if err := s.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer s.Disconnect()
	if s.State() != StateConnected {
		t.Fatalf("expected connected, got %s", s.State())
	}
	if len(seen) != 2 {
		t.Fatalf("expected both endpoints to be pinged, got %v", seen)
	}
}

func TestSession_ConnectFailsWhenAllEndpointsFail(t *testing.T) {
	oldPing := pingCarrier
	defer func() { pingCarrier = oldPing }()

	pingCarrier = func(cfg carrier.Config) error {
		return errors.New("down: " + cfg.Server)
	}

	s := NewSession(Config{
		Servers:   []string{"a.example:443", "b.example:443"},
		PubB64:    "AAAA",
		SNI:       "www.microsoft.com",
		Transport: "tcp",
	})
	if err := s.Connect(context.Background()); err == nil {
		t.Fatal("expected Connect to fail when every endpoint is down")
	}
	if s.State() != StateDisconnected {
		t.Fatalf("expected disconnected after failed Connect, got %s", s.State())
	}
}

func TestNewSession_DefaultsTransportToAuto(t *testing.T) {
	s := NewSession(Config{}) // Transport not set
	if s.cfg.Transport != "auto" {
		t.Fatalf("expected Transport=auto, got %q", s.cfg.Transport)
	}
}

func TestSession_StateString(t *testing.T) {
	if StateDisconnected.String() != "disconnected" {
		t.Fatal("wrong string for Disconnected")
	}
	if StateConnecting.String() != "connecting" {
		t.Fatal("wrong string for Connecting")
	}
	if StateConnected.String() != "connected" {
		t.Fatal("wrong string for Connected")
	}
}

// Compile-time check: Session.Dial signature matches gomobile's net.Conn return.
var _ func(string, string) (net.Conn, error) = NewSession(Config{}).Dial

// Compile-time check: endpoint.Dialer interface is satisfied by both pool types.
var _ endpoint.Dialer = endpoint.NewPool([]carrier.Config{})
var _ endpoint.Dialer = endpoint.NewAutoPool([]carrier.Config{})
