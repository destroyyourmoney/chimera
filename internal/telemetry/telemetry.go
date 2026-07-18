package telemetry

import (
	"context"
	"log/slog"
	"time"

	"chimera/internal/endpoint"
)

const (
	defaultCheckInterval     = 30 * time.Second
	defaultBurnedThreshold   = 0.6
	defaultConsecutiveBurned = 3
)

type Config struct {
	CheckInterval     time.Duration
	BurnedThreshold   float64
	ConsecutiveBurned int
}

func DefaultConfig() Config {
	return Config{
		CheckInterval:     defaultCheckInterval,
		BurnedThreshold:   defaultBurnedThreshold,
		ConsecutiveBurned: defaultConsecutiveBurned,
	}
}

type BurnedEndpoint struct {
	Server string
	Fails  int
	RTT    time.Duration
}

type RotationHook func(burned []BurnedEndpoint)

type Monitor struct {
	pool cfg
	c    Config
	hook RotationHook
}

type poolStats interface {
	Stats() []endpoint.Stat
}

type cfg struct {
	p poolStats
}

func NewMonitor(p poolStats, c Config) *Monitor {
	return &Monitor{pool: cfg{p}, c: c}
}

func (m *Monitor) OnRotationNeeded(fn RotationHook) {
	m.hook = fn
}

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
