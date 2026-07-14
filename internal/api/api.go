// Package api exposes the CHIMERA tunnel as an embeddable Go API.
//
// This is the integration surface for mobile bindings (gomobile), desktop tray
// apps, and headless embedding. Callers create a Session, call Connect once, then
// dial arbitrary host:port through the tunnel. Disconnect stops all active relay
// goroutines and closes the underlying carrier.
//
//	s := api.NewSession(cfg)
//	if err := s.Connect(ctx); err != nil { … }
//	conn, err := s.Dial("tcp", "example.com:443")
//	…
//	s.Disconnect()
//
// Thread safety: all public methods are safe for concurrent use.
package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"chimera/internal/carrier"
	"chimera/internal/endpoint"
)

var pingCarrier = carrier.Ping

// Config is the API-level session configuration. It mirrors carrier.Config but
// is decoupled from it so the API surface can evolve independently.
type Config struct {
	// Servers is a list of CHIMERA server addresses ("host:port"). Multiple
	// addresses are balanced with automatic health-aware failover.
	Servers []string
	// PubB64 is the server's X25519 public key encoded as base64url.
	PubB64 string
	// SNI is the TLS ServerName to present (steal-host domain).
	SNI string
	// ShortIDHex is the optional short ID (hex string) for the auth tag.
	ShortIDHex string
	// Transport selects the carrier: "tcp", "quic", or "auto" (race QUIC+TCP).
	// Defaults to "auto".
	Transport string
	// Shaping enables H3-video traffic shaping on the write path (QUIC only).
	Shaping bool
}

// State is the observable tunnel state.
type State int

const (
	StateDisconnected State = iota
	StateConnecting
	StateConnected
)

func (s State) String() string {
	switch s {
	case StateConnecting:
		return "connecting"
	case StateConnected:
		return "connected"
	default:
		return "disconnected"
	}
}

// Session manages the lifecycle of one CHIMERA tunnel session.
type Session struct {
	cfg     Config
	mu      sync.RWMutex
	state   State
	dialer  endpoint.Dialer // raw pool/auto-pool (used by netstack/TUN)
	metered endpoint.Dialer // byte-counting wrapper (used by Dial/SOCKS)
	cancel  context.CancelFunc

	// configs, when non-empty, are per-endpoint carrier configs (e.g. parsed
	// from a subscription with per-endpoint keys) and take precedence over the
	// flat cfg.Servers/PubB64 view.
	configs []carrier.Config

	up   atomic.Int64 // bytes written to tunnel (egress, via Dial/SOCKS)
	down atomic.Int64 // bytes read from tunnel (ingress, via Dial/SOCKS)
}

// NewSession creates a Session with the given config. Connect must be called
// before Dial.
func NewSession(cfg Config) *Session {
	if cfg.Transport == "" {
		cfg.Transport = "auto"
	}
	return &Session{cfg: cfg}
}

// NewSessionFromConfigs creates a Session from explicit per-endpoint carrier
// configs (as produced by a subscription). This is the path that preserves
// per-endpoint keys, SNIs and transports — the flat Config cannot express them.
func NewSessionFromConfigs(configs []carrier.Config) *Session {
	transport := "auto"
	if len(configs) > 0 && configs[0].Transport != "" {
		transport = configs[0].Transport
	}
	return &Session{cfg: Config{Transport: transport}, configs: configs}
}

// Connect initialises the endpoint pool and verifies at least one endpoint
// reachable by issuing a Ping. Returns an error if all endpoints fail.
// Connect is idempotent: calling it on an already-connected Session is a no-op.
func (s *Session) Connect(ctx context.Context) error {
	s.mu.Lock()
	if s.state == StateConnected {
		s.mu.Unlock()
		return nil
	}
	s.state = StateConnecting
	s.mu.Unlock()

	cfgs := s.carrierConfigs()
	if len(cfgs) == 0 {
		s.setState(StateDisconnected)
		return errors.New("api: no servers configured")
	}

	var dialer endpoint.Dialer
	if s.cfg.Transport == "auto" {
		dialer = endpoint.NewAutoPool(cfgs)
	} else {
		dialer = endpoint.NewPool(cfgs)
	}

	// Verify at least one endpoint is reachable.
	if err := pingAny(ctx, cfgs); err != nil {
		s.setState(StateDisconnected)
		return err
	}

	_, cancel := context.WithCancel(context.Background())

	s.mu.Lock()
	s.dialer = dialer
	s.metered = &meteredDialer{inner: dialer, up: &s.up, down: &s.down}
	s.cancel = cancel
	s.state = StateConnected
	s.mu.Unlock()

	return nil
}

// Disconnect tears down the session. All subsequent Dial calls will fail.
// Calling Disconnect on a non-connected Session is a no-op.
func (s *Session) Disconnect() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == StateDisconnected {
		return
	}
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	s.dialer = nil
	s.metered = nil
	s.state = StateDisconnected
}

// Dial opens a tunnel to the given network address through the CHIMERA server.
// Only "tcp" network is supported. The returned net.Conn is ready for
// bidirectional I/O.
func (s *Session) Dial(_ string, addr string) (net.Conn, error) {
	s.mu.RLock()
	dialer := s.metered
	state := s.state
	s.mu.RUnlock()

	if state != StateConnected || dialer == nil {
		return nil, errors.New("api: not connected; call Connect first")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	portN, err := net.LookupPort("tcp", port)
	if err != nil {
		return nil, err
	}
	return dialer.DialConnect(host, uint16(portN))
}

// State returns the current connection state.
func (s *Session) State() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

func (s *Session) setState(st State) {
	s.mu.Lock()
	s.state = st
	s.mu.Unlock()
}

// carrierConfigs returns the per-endpoint configs to dial. Explicit per-endpoint
// configs (from a subscription) win; otherwise the flat cfg.Servers view is
// expanded with the shared PubB64/SNI/ShortID.
func (s *Session) carrierConfigs() []carrier.Config {
	if len(s.configs) > 0 {
		return s.configs
	}
	cfgs := make([]carrier.Config, 0, len(s.cfg.Servers))
	for _, srv := range s.cfg.Servers {
		cfgs = append(cfgs, carrier.Config{
			Server:     srv,
			PubB64:     s.cfg.PubB64,
			SNI:        s.cfg.SNI,
			ShortIDHex: s.cfg.ShortIDHex,
			Transport:  s.cfg.Transport,
			Shaping:    s.cfg.Shaping,
		})
	}
	return cfgs
}

func pingAny(ctx context.Context, cfgs []carrier.Config) error {
	var lastErr error
	for _, cfg := range cfgs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := pingCarrier(cfg); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		return errors.New("api: no endpoints to ping")
	}
	return fmt.Errorf("api: all endpoints failed reachability check: %w", lastErr)
}
