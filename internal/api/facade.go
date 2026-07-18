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

type StateSnapshot struct {
	State     string         `json:"state"`
	Transport string         `json:"transport"`
	BytesUp   int64          `json:"bytesUp"`
	BytesDown int64          `json:"bytesDown"`
	Endpoints []EndpointStat `json:"endpoints"`
}

type EndpointStat struct {
	Server  string `json:"server"`
	Healthy bool   `json:"healthy"`
	Fails   int    `json:"fails"`
	RTTms   int64  `json:"rttMs"`
}

type statser interface{ Stats() []endpoint.Stat }

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

func (s *Session) StateJSON() string {
	b, err := json.Marshal(s.Snapshot())
	if err != nil {
		return `{"state":"disconnected","endpoints":[]}`
	}
	return string(b)
}

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
