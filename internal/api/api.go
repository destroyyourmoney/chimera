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

type Config struct {
	Servers []string

	PubB64 string

	SNI string

	ShortIDHex string

	Transport string

	Shaping bool
}

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

type Session struct {
	cfg     Config
	mu      sync.RWMutex
	state   State
	dialer  endpoint.Dialer
	metered endpoint.Dialer
	cancel  context.CancelFunc

	configs []carrier.Config

	up   atomic.Int64
	down atomic.Int64
}

func NewSession(cfg Config) *Session {
	if cfg.Transport == "" {
		cfg.Transport = "auto"
	}
	return &Session{cfg: cfg}
}

func NewSessionFromConfigs(configs []carrier.Config) *Session {
	transport := "auto"
	if len(configs) > 0 && configs[0].Transport != "" {
		transport = configs[0].Transport
	}
	return &Session{cfg: Config{Transport: transport}, configs: configs}
}

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
