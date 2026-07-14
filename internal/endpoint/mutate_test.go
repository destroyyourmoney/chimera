package endpoint

import (
	"testing"

	"chimera/internal/carrier"
)

func TestPool_AddEndpointsDedups(t *testing.T) {
	p := NewPool([]carrier.Config{{Server: "a:443"}})
	added := p.AddEndpoints([]carrier.Config{{Server: "a:443"}, {Server: "b:443"}})
	if added != 1 {
		t.Fatalf("added %d, want 1 (a is a duplicate)", added)
	}
	if got := len(p.Stats()); got != 2 {
		t.Fatalf("pool has %d endpoints, want 2", got)
	}
}

func TestPool_RemoveEndpoints(t *testing.T) {
	p := NewPool([]carrier.Config{{Server: "a:443"}, {Server: "b:443"}})
	removed := p.RemoveEndpoints([]string{"a:443"})
	if removed != 1 {
		t.Fatalf("removed %d, want 1", removed)
	}
	stats := p.Stats()
	if len(stats) != 1 || stats[0].Server != "b:443" {
		t.Fatalf("pool = %+v, want only b:443", stats)
	}
}

func TestPool_RemoveNeverEmpties(t *testing.T) {
	p := NewPool([]carrier.Config{{Server: "a:443"}})
	if removed := p.RemoveEndpoints([]string{"a:443"}); removed != 0 {
		t.Fatalf("removed %d, want 0 (refuse to empty pool)", removed)
	}
	if len(p.Stats()) != 1 {
		t.Fatal("pool must retain its last endpoint")
	}
}

func TestPool_SetFingerprintUpdatesEndpoints(t *testing.T) {
	p := NewPool([]carrier.Config{
		{Server: "a:443", Transport: "tcp", Fp: "chrome120"},
		{Server: "b:443", Transport: "quic", Fp: "chrome120"},
	})
	p.SetFingerprint("chrome131")
	for _, e := range p.eps {
		if e.cfg.Fp != "chrome131" {
			t.Fatalf("endpoint %s fp = %q, want chrome131", e.cfg.Server, e.cfg.Fp)
		}
	}
	if p.eps[0].cfg.Transport != "tcp" || p.eps[1].cfg.Transport != "quic" {
		t.Fatalf("SetFingerprint changed transports: %+v / %+v", p.eps[0].cfg, p.eps[1].cfg)
	}
}
