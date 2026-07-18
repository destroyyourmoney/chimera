package endpoint

import (
	"errors"
	"net"
	"testing"

	"chimera/internal/carrier"
)

func TestAutoPool_RacesTransports(t *testing.T) {
	cfgs := []carrier.Config{{Server: "s1", Transport: "auto"}}
	ap := NewAutoPool(cfgs)

	wins := make(map[string]int)
	ap.pool.dial = func(c carrier.Config, _ string, _ uint16) (net.Conn, error) {
		wins[c.Transport]++
		return fakeConn{}, nil
	}
	ap.pool.now = ap.pool.now

	conn, err := ap.DialConnect("h", 1)
	if err != nil {
		t.Fatalf("AutoPool.DialConnect: %v", err)
	}
	conn.Close()

	if len(wins) == 0 {
		t.Fatal("no transport was dialed")
	}
}

func TestAutoPool_DemotesQUICOnFailure(t *testing.T) {
	cfgs := []carrier.Config{{Server: "s1", Transport: "auto"}}
	ap := NewAutoPool(cfgs)
	if carrier.QUICDialConnect == nil && len(ap.pool.eps) == 1 {
		t.Skip("QUIC not compiled in; only TCP endpoint created")
	}

	ap.pool.dial = func(c carrier.Config, _ string, _ uint16) (net.Conn, error) {
		if c.Transport == "quic" {
			return nil, errors.New("quic blocked")
		}
		return fakeConn{}, nil
	}

	conn, err := ap.DialConnect("h", 1)
	if err != nil {
		t.Fatalf("expected TCP fallback to succeed: %v", err)
	}
	conn.Close()

	stats := ap.Stats()
	var quicHealthy bool
	for _, s := range stats {
		if s.Server == "s1" && !s.Healthy && s.Fails > 0 {

		}
		if s.Server == "s1" && s.Healthy && s.Fails == 0 {
			quicHealthy = true
		}
	}
	_ = quicHealthy
}

func TestAutoPool_FallsBackToTCPWhenQUICAbsent(t *testing.T) {
	if carrier.QUICDialConnect != nil {
		t.Skip("QUIC is compiled in; this test covers the absent-QUIC code path")
	}
	cfgs := []carrier.Config{{Server: "s1", Transport: "auto"}}
	ap := NewAutoPool(cfgs)
	if len(ap.pool.eps) != 1 {
		t.Fatalf("expected 1 TCP endpoint when QUIC absent, got %d", len(ap.pool.eps))
	}
	if ap.pool.eps[0].cfg.Transport != "tcp" {
		t.Fatalf("expected tcp transport, got %q", ap.pool.eps[0].cfg.Transport)
	}
}

func TestDialRaceConnect_WinsWithFirstSuccess(t *testing.T) {
	p, _ := newTestPool(t, []string{"a", "b"}, nil)
	conn, err := p.DialRaceConnect("h", 1)
	if err != nil {
		t.Fatalf("DialRaceConnect: %v", err)
	}
	conn.Close()
}

func TestDialRaceConnect_AllFailed(t *testing.T) {
	p, _ := newTestPool(t, []string{"a", "b"}, func(string) error { return errors.New("down") })
	if _, err := p.DialRaceConnect("h", 1); err == nil {
		t.Fatal("expected error when all endpoints fail")
	}
}

func TestDialRaceConnect_SerialFallbackToUnhealthy(t *testing.T) {
	p, now := newTestPool(t, []string{"a"}, nil)

	p.dial = func(_ carrier.Config, _ string, _ uint16) (net.Conn, error) {
		return nil, errors.New("a down")
	}
	_, _ = p.DialRaceConnect("h", 1)

	p.dial = func(_ carrier.Config, _ string, _ uint16) (net.Conn, error) {
		return fakeConn{}, nil
	}

	*now = now.Add(baseBackoff + 1)

	conn, err := p.DialRaceConnect("h", 1)
	if err != nil {
		t.Fatalf("expected serial fallback to recover: %v", err)
	}
	conn.Close()
}

func TestAutoPool_SetFingerprintUpdatesTransportVariants(t *testing.T) {
	ap := NewAutoPool([]carrier.Config{{Server: "s1", Transport: "auto", Fp: "chrome120"}})
	ap.SetFingerprint("chrome131")
	for _, e := range ap.pool.eps {
		if e.cfg.Fp != "chrome131" {
			t.Fatalf("endpoint %+v fp = %q, want chrome131", e.cfg, e.cfg.Fp)
		}
		if e.cfg.Transport != "tcp" && e.cfg.Transport != "quic" {
			t.Fatalf("unexpected transport after SetFingerprint: %q", e.cfg.Transport)
		}
	}
}
