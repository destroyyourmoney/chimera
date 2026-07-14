package telemetry

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"chimera/internal/endpoint"
)

// fakePool implements poolStats with controllable health.
type fakePool struct {
	stats []endpoint.Stat
}

func (f *fakePool) Stats() []endpoint.Stat { return f.stats }

func allDown(n int) []endpoint.Stat {
	out := make([]endpoint.Stat, n)
	for i := range out {
		out[i] = endpoint.Stat{Server: "s", Healthy: false, Fails: 5}
	}
	return out
}

func allUp(n int) []endpoint.Stat {
	out := make([]endpoint.Stat, n)
	for i := range out {
		out[i] = endpoint.Stat{Server: "s", Healthy: true}
	}
	return out
}

func TestMonitor_FiresHookWhenBurnedThresholdMet(t *testing.T) {
	pool := &fakePool{stats: allDown(3)}
	cfg := Config{
		CheckInterval:     10 * time.Millisecond,
		BurnedThreshold:   0.5,
		ConsecutiveBurned: 2,
	}
	mon := NewMonitor(pool, cfg)

	var fired atomic.Int32
	mon.OnRotationNeeded(func(_ []BurnedEndpoint) {
		fired.Add(1)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	go mon.Run(ctx)

	<-ctx.Done()
	if fired.Load() == 0 {
		t.Fatal("rotation hook was not fired despite all endpoints being down")
	}
}

func TestMonitor_NoHookWhenHealthy(t *testing.T) {
	pool := &fakePool{stats: allUp(3)}
	cfg := Config{
		CheckInterval:     10 * time.Millisecond,
		BurnedThreshold:   0.5,
		ConsecutiveBurned: 1,
	}
	mon := NewMonitor(pool, cfg)

	var fired atomic.Int32
	mon.OnRotationNeeded(func(_ []BurnedEndpoint) {
		fired.Add(1)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	go mon.Run(ctx)

	<-ctx.Done()
	if fired.Load() != 0 {
		t.Fatal("rotation hook fired spuriously when all endpoints are healthy")
	}
}

func TestMonitor_ConsecutiveResetOnRecovery(t *testing.T) {
	pool := &fakePool{stats: allDown(3)}
	cfg := Config{
		CheckInterval:     10 * time.Millisecond,
		BurnedThreshold:   0.5,
		ConsecutiveBurned: 3, // requires 3 consecutive bad checks
	}
	mon := NewMonitor(pool, cfg)

	var fired atomic.Int32
	mon.OnRotationNeeded(func(_ []BurnedEndpoint) {
		fired.Add(1)
		// After first hook fire, mark all endpoints healthy to reset consecutive.
		pool.stats = allUp(3)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	go mon.Run(ctx)
	<-ctx.Done()

	// Should fire at most once since recovery resets the counter.
	if fired.Load() > 1 {
		t.Fatalf("rotation hook fired %d times (expected ≤ 1 after recovery reset)", fired.Load())
	}
}

func TestDefaultConfig(t *testing.T) {
	c := DefaultConfig()
	if c.CheckInterval <= 0 {
		t.Fatal("CheckInterval must be positive")
	}
	if c.BurnedThreshold <= 0 || c.BurnedThreshold > 1 {
		t.Fatal("BurnedThreshold must be in (0, 1]")
	}
	if c.ConsecutiveBurned <= 0 {
		t.Fatal("ConsecutiveBurned must be positive")
	}
}
