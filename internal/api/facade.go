// facade.go is the UI-facing surface of the api package: subscription loading,
// a JSON state snapshot, a blocking SOCKS runner, and link parsing. It is kept
// separate from the core Session lifecycle (api.go) so the embedding surface
// (mobile bindings, desktop FFI, tray apps) can evolve without touching the
// tunnel internals.
package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"

	"chimera/internal/endpoint"
	"chimera/internal/link"
	"chimera/internal/socks"
	"chimera/internal/subscription"
)

// NewSessionFromSubscription builds a Session from a subscription document
// (the "#!chimera-subscription-v1" format). When signKeyHex is non-empty and the
// document carries a "# sig:" line, the HMAC-SHA256 signature is verified before
// any endpoint is accepted; a mismatch returns an error and no Session.
func NewSessionFromSubscription(subscriptionText, signKeyHex string) (*Session, error) {
	var key []byte
	if signKeyHex != "" {
		k, err := hex.DecodeString(strings.TrimSpace(signKeyHex))
		if err != nil {
			return nil, fmt.Errorf("api: invalid sign key hex: %w", err)
		}
		key = k
	}
	cfgs, err := subscription.Parse(strings.NewReader(subscriptionText), key)
	if err != nil {
		return nil, fmt.Errorf("api: load subscription: %w", err)
	}
	return NewSessionFromConfigs(cfgs), nil
}

// RunSOCKS runs a local SOCKS5 inbound on listen (e.g. "127.0.0.1:1080"),
// relaying through the connected tunnel. It blocks until ctx is cancelled or the
// listener errors. The Session must already be Connected. This is the desktop
// fallback path and the TUN-less proxy mode.
func (s *Session) RunSOCKS(ctx context.Context, listen string) error {
	s.mu.RLock()
	dialer := s.metered
	state := s.state
	s.mu.RUnlock()
	if state != StateConnected || dialer == nil {
		return errors.New("api: not connected; call Connect first")
	}
	return socks.Serve(ctx, listen, dialer)
}

// StateSnapshot is a flat, serialisable view of the session for the UI. All
// fields are primitives so it round-trips cleanly through JSON and gomobile.
type StateSnapshot struct {
	State     string         `json:"state"`
	Transport string         `json:"transport"`
	BytesUp   int64          `json:"bytesUp"`
	BytesDown int64          `json:"bytesDown"`
	Endpoints []EndpointStat `json:"endpoints"`
}

// EndpointStat is one endpoint's health in the snapshot.
type EndpointStat struct {
	Server  string `json:"server"`
	Healthy bool   `json:"healthy"`
	Fails   int    `json:"fails"`
	RTTms   int64  `json:"rttMs"`
}

// statser is implemented by *endpoint.Pool and *endpoint.AutoPool.
type statser interface{ Stats() []endpoint.Stat }

// Snapshot returns the current observable state. Safe for concurrent use.
func (s *Session) Snapshot() StateSnapshot {
	s.mu.RLock()
	dialer := s.dialer
	snap := StateSnapshot{
		State:     s.state.String(),
		Transport: s.cfg.Transport,
		BytesUp:   s.up.Load(),
		BytesDown: s.down.Load(),
	}
	s.mu.RUnlock()

	if st, ok := dialer.(statser); ok {
		for _, e := range st.Stats() {
			snap.Endpoints = append(snap.Endpoints, EndpointStat{
				Server:  e.Server,
				Healthy: e.Healthy,
				Fails:   e.Fails,
				RTTms:   e.RTT.Milliseconds(),
			})
		}
	}
	return snap
}

// StateJSON returns Snapshot() encoded as JSON — the poll-friendly surface for
// UI clients that cannot consume Go structs (gomobile, FFI). Never returns an
// error string; on the (impossible) marshal failure it returns a minimal object.
func (s *Session) StateJSON() string {
	b, err := json.Marshal(s.Snapshot())
	if err != nil {
		return `{"state":"disconnected","endpoints":[]}`
	}
	return string(b)
}

// ParseLinkJSON parses a chimera:// URI and returns its fields as JSON, for the
// "add server" UI flow. Returns an error for a malformed or wrong-scheme link.
func ParseLinkJSON(uri string) (string, error) {
	p, err := link.Parse(uri)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(struct {
		Host, Port, Pbk, Sid, Sni, Fp, Mode, Tag string
	}{p.Host, p.Port, p.Pbk, p.Sid, p.Sni, p.Fp, p.Mode, p.Tag})
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// meteredDialer wraps an endpoint.Dialer, counting bytes through every conn it
// hands out so the UI can show live throughput. It only implements DialConnect
// (endpoint.Dialer); the raw dialer is used for the netstack/TUN path so UDP
// carrier semantics are preserved untouched.
type meteredDialer struct {
	inner    endpoint.Dialer
	up, down *atomic.Int64
}

func (m *meteredDialer) DialConnect(host string, port uint16) (net.Conn, error) {
	c, err := m.inner.DialConnect(host, port)
	if err != nil {
		return nil, err
	}
	return &meteredConn{Conn: c, up: m.up, down: m.down}, nil
}

type meteredConn struct {
	net.Conn
	up, down *atomic.Int64
}

func (c *meteredConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.down.Add(int64(n))
	return n, err
}

func (c *meteredConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.up.Add(int64(n))
	return n, err
}
