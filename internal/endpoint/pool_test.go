package endpoint

import (
	"errors"
	"net"
	"testing"
	"time"

	"chimera/internal/carrier"
)

type fakeConn struct{ net.Conn }

func (fakeConn) Close() error { return nil }

func newTestPool(t *testing.T, servers []string, behave func(server string) error) (*Pool, *time.Time) {
	t.Helper()
	cfgs := make([]carrier.Config, len(servers))
	for i, s := range servers {
		cfgs[i] = carrier.Config{Server: s}
	}
	if behave == nil {
		behave = func(string) error { return nil }
	}
	p := NewPool(cfgs)
	now := time.Unix(1_000_000, 0)
	p.now = func() time.Time { return now }
	p.dial = func(c carrier.Config, _ string, _ uint16) (net.Conn, error) {
		if err := behave(c.Server); err != nil {
			return nil, err
		}
		return fakeConn{}, nil
	}
	return p, &now
}

func TestFailoverToHealthyEndpoint(t *testing.T) {
	p, _ := newTestPool(t, []string{"a", "b"}, func(s string) error {
		if s == "a" {
			return errors.New("a is down")
		}
		return nil
	})
	conn, err := p.DialConnect("example.com", 443)
	if err != nil {
		t.Fatalf("expected failover success, got %v", err)
	}
	conn.Close()

	stats := statByServer(p)
	if stats["a"].Healthy {
		t.Error("endpoint a should be marked unhealthy after failure")
	}
	if !stats["b"].Healthy {
		t.Error("endpoint b should be healthy after success")
	}
}

func TestAllEndpointsDownReturnsError(t *testing.T) {
	p, _ := newTestPool(t, []string{"a", "b"}, func(string) error {
		return errors.New("down")
	})
	if _, err := p.DialConnect("h", 1); err == nil {
		t.Fatal("expected error when all endpoints fail")
	}
}

func TestBackoffAndAutoRecovery(t *testing.T) {
	down := map[string]bool{"a": true}
	p, now := newTestPool(t, []string{"a"}, func(s string) error {
		if down[s] {
			return errors.New("a down")
		}
		return nil
	})

	if _, err := p.DialConnect("h", 1); err == nil {
		t.Fatal("expected failure while a is down")
	}
	if statByServer(p)["a"].Healthy {
		t.Fatal("a should be backed off")
	}

	down["a"] = false
	*now = now.Add(baseBackoff + time.Second)
	conn, err := p.DialConnect("h", 1)
	if err != nil {
		t.Fatalf("a should be retried and promoted after backoff: %v", err)
	}
	conn.Close()
	if !statByServer(p)["a"].Healthy {
		t.Error("a should be healthy again after a successful dial")
	}
}

func TestExponentialBackoffGrows(t *testing.T) {
	p, now := newTestPool(t, []string{"a"}, func(string) error { return errors.New("down") })

	prev := time.Duration(0)
	for i := 0; i < 4; i++ {
		_, _ = p.DialConnect("h", 1)
		e := p.eps[0]
		window := e.downUntil.Sub(*now)
		if window <= prev {
			t.Fatalf("backoff did not grow: attempt %d window %v <= prev %v", i, window, prev)
		}
		prev = window

		*now = now.Add(window + time.Second)
	}
}

func TestPrefersLowerLatency(t *testing.T) {

	p, now := newTestPool(t, []string{"slow", "fast"}, nil)
	p.dial = func(c carrier.Config, _ string, _ uint16) (net.Conn, error) {
		if c.Server == "slow" {
			*now = now.Add(100 * time.Millisecond)
		} else {
			*now = now.Add(5 * time.Millisecond)
		}
		return fakeConn{}, nil
	}

	for _, e := range p.eps {
		start := *now
		_, _ = p.dial(e.cfg, "h", 1)
		p.markOK(e, now.Sub(start))
	}

	if got := p.candidates()[0].cfg.Server; got != "fast" {
		t.Fatalf("expected 'fast' preferred by latency, got %q", got)
	}
}

func TestSingleEndpointPassthrough(t *testing.T) {
	p, _ := newTestPool(t, []string{"only"}, nil)
	conn, err := p.DialConnect("h", 1)
	if err != nil {
		t.Fatalf("single endpoint should work: %v", err)
	}
	conn.Close()
}

func statByServer(p *Pool) map[string]Stat {
	m := map[string]Stat{}
	for _, s := range p.Stats() {
		m[s.Server] = s
	}
	return m
}
