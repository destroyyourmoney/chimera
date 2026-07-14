// Package telemetry collects endpoint health events and provides a rotation
// signal when all endpoints in a pool are burned (consistently unhealthy).
//
// The Monitor runs in the background and periodically snapshots endpoint stats.
// When the burned fraction exceeds a threshold, it calls the optional RotationHook
// so the operator (or auto-provisioning pipeline) can swap in fresh endpoints.
//
// Usage:
//
//	mon := telemetry.NewMonitor(pool, telemetry.DefaultConfig())
//	mon.OnRotationNeeded(func(burned []telemetry.BurnedEndpoint) {
//	    // swap endpoints, alert ops, etc.
//	})
//	ctx, cancel := context.WithCancel(context.Background())
//	go mon.Run(ctx)
package telemetry

import (
	"context"
	"log/slog"
	"time"

	"chimera/internal/endpoint"
)

const (
	defaultCheckInterval     = 30 * time.Second
	defaultBurnedThreshold   = 0.6  // fraction of unhealthy endpoints that triggers rotation
	defaultConsecutiveBurned = 3    // checks in a row above threshold before firing hook
)

// Config holds Monitor tuning parameters.
type Config struct {
	CheckInterval     time.Duration
	BurnedThreshold   float64 // 0–1: fraction of unhealthy endpoints to trigger rotation
	ConsecutiveBurned int     // consecutive check cycles above threshold before rotating
}

// DefaultConfig returns sensible production defaults.
func DefaultConfig() Config {
	return Config{
		CheckInterval:     defaultCheckInterval,
		BurnedThreshold:   defaultBurnedThreshold,
		ConsecutiveBurned: defaultConsecutiveBurned,
	}
}

// BurnedEndpoint is a snapshot of an unhealthy endpoint reported to the hook.
type BurnedEndpoint struct {
	Server string
	Fails  int
	RTT    time.Duration
}

// RotationHook is called when the monitor decides endpoint rotation is needed.
type RotationHook func(burned []BurnedEndpoint)

// Monitor watches an endpoint pool and fires a rotation hook when too many
// endpoints are consistently unhealthy.
type Monitor struct {
	pool cfg
	c    Config
	hook RotationHook
}

// poolStats is the interface we need from the endpoint.Pool (and AutoPool).
type poolStats interface {
	Stats() []endpoint.Stat
}

// cfg wraps the pool stat interface so Monitor does not import *endpoint.Pool directly.
type cfg struct {
	p poolStats
}

// NewMonitor creates a Monitor over the given pool (must satisfy poolStats).
func NewMonitor(p poolStats, c Config) *Monitor {
	return &Monitor{pool: cfg{p}, c: c}
}

// OnRotationNeeded registers the hook called when rotation is warranted.
// Only one hook is supported; calling this again replaces the previous hook.
func (m *Monitor) OnRotationNeeded(fn RotationHook) {
	m.hook = fn
}

// Run starts the periodic health check loop. It blocks until ctx is cancelled.
func (m *Monitor) Run(ctx context.Context) {
	ticker := time.NewTicker(m.c.CheckInterval)
	defer ticker.Stop()
	consecutive := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			burned := m.check()
			stats := m.pool.p.Stats()
			total := len(stats)
			if total == 0 {
				continue
			}
			burnedFrac := float64(len(burned)) / float64(total)
			slog.Info("endpoint health",
				"total", total,
				"unhealthy", len(burned),
				"burned_frac", burnedFrac,
			)
			if burnedFrac >= m.c.BurnedThreshold {
				consecutive++
			} else {
				consecutive = 0
			}
			if consecutive >= m.c.ConsecutiveBurned && m.hook != nil {
				slog.Warn("endpoint rotation needed",
					"burned", len(burned), "total", total,
					"consecutive_cycles", consecutive,
				)
				m.hook(burned)
				consecutive = 0
			}
		}
	}
}

func (m *Monitor) check() []BurnedEndpoint {
	stats := m.pool.p.Stats()
	var burned []BurnedEndpoint
	for _, s := range stats {
		if !s.Healthy {
			burned = append(burned, BurnedEndpoint{
				Server: s.Server,
				Fails:  s.Fails,
				RTT:    s.RTT,
			})
		}
	}
	return burned
}
