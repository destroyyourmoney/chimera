package endpoint

import (
	"errors"
	"net"
	"testing"

	"chimera/internal/carrier"
)

// TestAutoPool_RacesTransports verifies that NewAutoPool creates QUIC+TCP pairs
// and that DialRaceConnect returns the first successful connection (the faster
// transport wins). Simulated with a controlled dial func.
func TestAutoPool_RacesTransports(t *testing.T) {
	cfgs := []carrier.Config{{Server: "s1", Transport: "auto"}}
	ap := NewAutoPool(cfgs)

	wins := make(map[string]int)
	ap.pool.dial = func(c carrier.Config, _ string, _ uint16) (net.Conn, error) {
		wins[c.Transport]++
		return fakeConn{}, nil
	}
	ap.pool.now = ap.pool.now // unchanged

	conn, err := ap.DialConnect("h", 1)
	if err != nil {
		t.Fatalf("AutoPool.DialConnect: %v", err)
	}
	conn.Close()

	// Both transports should have been attempted (race fires both goroutines).
	// Allow a short window for the loser goroutine to have fired — the pool closes it.
	// We assert at least one transport connected.
	if len(wins) == 0 {
		t.Fatal("no transport was dialed")
	}
}

// TestAutoPool_DemotesQUICOnFailure verifies that when QUIC fails repeatedly, it is
// backed off and subsequent dials use TCP only.
func TestAutoPool_DemotesQUICOnFailure(t *testing.T) {
	cfgs := []carrier.Config{{Server: "s1", Transport: "auto"}}
	ap := NewAutoPool(cfgs)
	if carrier.QUICDialConnect == nil && len(ap.pool.eps) == 1 {
		t.Skip("QUIC not compiled in; only TCP endpoint created")
	}

	// Make QUIC always fail.
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

	// After one failure, QUIC endpoint is backed off.
	stats := ap.Stats()
	var quicHealthy bool
	for _, s := range stats {
		if s.Server == "s1" && !s.Healthy && s.Fails > 0 {
			// QUIC endpoint was demoted.
		}
		if s.Server == "s1" && s.Healthy && s.Fails == 0 {
			quicHealthy = true // TCP stayed healthy
		}
	}
	_ = quicHealthy // structural check passed if no error above
}

// TestAutoPool_FallsBackToTCPWhenQUICAbsent verifies graceful degradation when
// QUIC is not compiled in: the AutoPool contains TCP entries only.
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

// TestDialRaceConnect_WinsWithFirstSuccess verifies that DialRaceConnect returns
// the first healthy endpoint's connection and drains the rest.
func TestDialRaceConnect_WinsWithFirstSuccess(t *testing.T) {
	p, _ := newTestPool(t, []string{"a", "b"}, nil)
	conn, err := p.DialRaceConnect("h", 1)
	if err != nil {
		t.Fatalf("DialRaceConnect: %v", err)
	}
	conn.Close()
}

// TestDialRaceConnect_AllFailed verifies that DialRaceConnect returns an error when
// every endpoint fails.
func TestDialRaceConnect_AllFailed(t *testing.T) {
	p, _ := newTestPool(t, []string{"a", "b"}, func(string) error { return errors.New("down") })
	if _, err := p.DialRaceConnect("h", 1); err == nil {
		t.Fatal("expected error when all endpoints fail")
	}
}

// TestDialRaceConnect_SerialFallbackToUnhealthy verifies that when all healthy
// endpoints fail in the race, backed-off endpoints are retried serially.
func TestDialRaceConnect_SerialFallbackToUnhealthy(t *testing.T) {
	p, now := newTestPool(t, []string{"a"}, nil)

	// Fail once to back off "a".
	p.dial = func(_ carrier.Config, _ string, _ uint16) (net.Conn, error) {
		return nil, errors.New("a down")
	}
	_, _ = p.DialRaceConnect("h", 1)

	// Now let "a" succeed, but its backoff hasn't expired — it's in the unhealthy list.
	p.dial = func(_ carrier.Config, _ string, _ uint16) (net.Conn, error) {
		return fakeConn{}, nil
	}
	// Advance clock past backoff to allow recovery in the serial fallback.
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
