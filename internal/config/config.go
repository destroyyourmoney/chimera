package config

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

const WatchInterval = 30 * time.Second

type RateLimitConfig struct {
	Rate  float64 `yaml:"rate"`
	Burst float64 `yaml:"burst"`
}

type ServerConfig struct {
	Listen    string   `yaml:"listen"`
	StealHost string   `yaml:"steal_host"`
	PrivB64   string   `yaml:"priv"`
	ShortIDs  []string `yaml:"short_ids"`
	Transport string   `yaml:"transport"`
	Verbose   bool     `yaml:"verbose"`

	Fp string `yaml:"fp"`

	RateLimit RateLimitConfig `yaml:"rate_limit"`
}

func Watch(ctx context.Context, path string, onChange func(*ServerConfig)) {
	load := func() *ServerConfig {
		c, err := LoadServer(path)
		if err != nil {
			slog.Warn("config watch: reload failed", "path", path, "err", err)
			return nil
		}
		return c
	}
	last := load()
	if last != nil {
		onChange(last)
	}
	t := time.NewTicker(WatchInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c := load()
			if c == nil {
				continue
			}
			if configChanged(last, c) {
				slog.Info("config hot-reload: fingerprint updated", "fp", c.Fp)
				last = c
				onChange(c)
			}
		}
	}
}

func configChanged(a, b *ServerConfig) bool {
	if a == nil {
		return true
	}
	return a.Fp != b.Fp
}

func LoadServer(path string) (*ServerConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config: open %q: %w", path, err)
	}
	defer f.Close()
	var c ServerConfig
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: parse %q: %w", path, err)
	}
	return &c, nil
}
