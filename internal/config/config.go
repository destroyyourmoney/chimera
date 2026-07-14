// Package config loads the server YAML configuration file and exposes it as
// typed Go structs. CLI flags always take precedence over config-file values.
//
// Minimal example (chimera-server.yaml):
//
//	listen: ":443"
//	steal_host: "www.microsoft.com:443"
//	priv: "base64url-encoded-private-key"
//	short_ids:
//	  - "0a1b2c3d"
//	transport: "tcp"
//	verbose: false
//	rate_limit:
//	  rate: 5
//	  burst: 10
package config

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// WatchInterval is how often Watch polls the config file for changes.
const WatchInterval = 30 * time.Second

// RateLimitConfig controls per-IP abuse limits on the auth path.
type RateLimitConfig struct {
	Rate  float64 `yaml:"rate"`
	Burst float64 `yaml:"burst"`
}

// ServerConfig is the YAML schema for `chimera server -config <file>`.
// All fields are optional; zero values use the same defaults as CLI flags.
type ServerConfig struct {
	Listen    string   `yaml:"listen"`
	StealHost string   `yaml:"steal_host"`
	PrivB64   string   `yaml:"priv"`
	ShortIDs  []string `yaml:"short_ids"`
	Transport string   `yaml:"transport"`
	Verbose   bool     `yaml:"verbose"`
	// Fp selects the TLS ClientHello fingerprint for the utls build.
	// Valid values: "chrome" (default), "chrome131", "chrome120", "firefox",
	// "safari", "ios", "edge". Can be changed and hot-reloaded without restart.
	Fp string `yaml:"fp"`

	RateLimit RateLimitConfig `yaml:"rate_limit"`
}

// Watch polls path every WatchInterval and calls onChange whenever the parsed
// ServerConfig changes. Runs until ctx is cancelled. The first load is synchronous
// and calls onChange immediately if successful; subsequent calls happen on change.
// This is the fingerprint-update pipeline hook: the operator edits `fp:` in the
// YAML config and the running server picks up the new fingerprint within WatchInterval
// without a restart.
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

// configChanged reports whether any hot-reloadable field differs between a and b.
// Currently only Fp (fingerprint) is hot-reloadable; other fields require a restart.
func configChanged(a, b *ServerConfig) bool {
	if a == nil {
		return true
	}
	return a.Fp != b.Fp
}

// LoadServer parses path as a YAML ServerConfig.
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
