// Package server implements the CHIMERA TCP carrier.
//
// For each connection it peeks the ClientHello and checks the embedded auth tag
// (and shortID). Authorized peers enter tunnel mode (the server performs egress
// to the requested target). Everyone else — including active probers — is
// transparently spliced to a real steal-host and receives that host's genuine
// TLS session, so an unauthenticated peer cannot distinguish a CHIMERA server
// from a plain reverse proxy.
//
// PoC caveat: in tunnel mode the inner protocol currently runs over the
// post-handshake TCP stream in the clear. Phase 1b wraps it in a Reality-hijacked
// TLS session so authorized sessions are byte-indistinguishable from the
// steal-host on the wire too.
package server

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"io"
	"log/slog"
	"net"
	"strconv"
	"time"

	"chimera/internal/auth"
	"chimera/internal/carrier"
	"chimera/internal/clienthello"
	"chimera/internal/keys"
	"chimera/internal/preconnect"
	"chimera/internal/ratelimit"
	"chimera/internal/serve"
	"chimera/internal/tunnel"
	"chimera/internal/vision"
)

// Default abuse limits for the per-IP auth-path token bucket. Generous enough
// for a browser opening many parallel carriers, tight enough to bound a flood.
const (
	DefaultAuthRate  = 50.0 // auth attempts/sec per source IP
	DefaultAuthBurst = 100.0
	cleanupInterval  = 2 * time.Minute
	cleanupIdle      = 5 * time.Minute
)

// Config holds the operator-side server configuration.
type Config struct {
	Listen    string   // e.g. ":443" or "127.0.0.1:8443"
	StealHost string   // real TLS host to impersonate, host:port
	PrivB64   string   // base64url X25519 static private key
	ShortIDs  []string // allowed short IDs as hex; empty = accept any (PoC)
	AuthRate  float64  // per-IP auth attempts/sec; <=0 uses default, set via flag
	AuthBurst float64  // per-IP auth burst; <=0 uses default
	// Allowlist, if set, overrides ShortIDs with a dynamic allow-list (e.g.
	// internal/useracl.Store) so users can be added/revoked without a restart.
	Allowlist carrier.Allowlist
}

// server is the per-process carrier state shared across connections.
type server struct {
	priv      *ecdh.PrivateKey
	serverPub []byte
	stealHost string
	allowed   carrier.Allowlist
	limiter   *ratelimit.Limiter
	preconn   *preconnect.Pool // pre-warmed connections to steal-host
}

// Run starts the listener and serves connections until ctx is cancelled, then
// drains in-flight connections and returns cleanly.
func Run(ctx context.Context, cfg Config) error {
	priv, err := keys.DecodePrivate(cfg.PrivB64)
	if err != nil {
		return err
	}
	allowed := resolveAllowlist(cfg)

	rate, burst := cfg.AuthRate, cfg.AuthBurst
	if rate <= 0 {
		rate, burst = DefaultAuthRate, DefaultAuthBurst
	}
	s := &server{
		priv:      priv,
		serverPub: priv.PublicKey().Bytes(),
		stealHost: cfg.StealHost,
		allowed:   allowed,
		limiter:   ratelimit.New(rate, burst),
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	slog.Info("carrier up", "listen", cfg.Listen, "steal_host", cfg.StealHost, "short_ids", len(cfg.ShortIDs), "auth_rate", rate)
	return s.serve(ctx, ln)
}

// Serve runs the carrier on an already-open listener. It is used by tests and by
// callers that manage their own socket; Run is the usual entry point.
func Serve(ctx context.Context, ln net.Listener, cfg Config) error {
	priv, err := keys.DecodePrivate(cfg.PrivB64)
	if err != nil {
		return err
	}
	allowed := resolveAllowlist(cfg)
	rate, burst := cfg.AuthRate, cfg.AuthBurst
	if rate <= 0 {
		rate, burst = DefaultAuthRate, DefaultAuthBurst
	}
	s := &server{
		priv:      priv,
		serverPub: priv.PublicKey().Bytes(),
		stealHost: cfg.StealHost,
		allowed:   allowed,
		limiter:   ratelimit.New(rate, burst),
	}
	return s.serve(ctx, ln)
}

func (s *server) serve(ctx context.Context, ln net.Listener) error {
	s.preconn = preconnect.New(ctx, s.stealHost, 0) // default pool size
	go s.janitor(ctx)
	err := serve.Loop(ctx, ln, serve.DefaultDrain, s.handle)
	slog.Info("carrier stopped")
	return err
}

// janitor periodically evicts idle rate-limit buckets to bound memory.
func (s *server) janitor(ctx context.Context) {
	t := time.NewTicker(cleanupInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.limiter.Cleanup(cleanupIdle)
		}
	}
}

// resolveAllowlist picks cfg.Allowlist when set (dynamic, e.g. useracl.Store),
// otherwise builds a StaticAllowlist from cfg.ShortIDs (legacy behavior).
func resolveAllowlist(cfg Config) carrier.Allowlist {
	if cfg.Allowlist != nil {
		return cfg.Allowlist
	}
	ids := make(carrier.StaticAllowlist, 0, len(cfg.ShortIDs))
	for _, s := range cfg.ShortIDs {
		ids = append(ids, carrier.ParseShortID(s))
	}
	return ids
}

func (s *server) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)

	raw, err := readRecord(br)
	if err != nil {
		return
	}

	// Abuse limit: over the per-IP budget we skip the auth crypto entirely and
	// fall through to the steal-host splice — wire-identical to any unauth peer,
	// so this adds no probing oracle while bounding CPU-exhaustion floods.
	var sharedSecret []byte
	if s.limiter.Allow(peerIP(c)) {
		sharedSecret = s.authenticate(raw)
	}

	if sharedSecret != nil {
		slog.Info("auth ok -> tunnel", "peer", c.RemoteAddr().String())
		rw, err := s.authedTransport(c, br, raw, sharedSecret)
		if err != nil {
			slog.Debug("authed transport failed", "peer", c.RemoteAddr().String(), "err", err)
			return
		}
		defer rw.Close()
		serveTunnel(rw, tunnel.ServerSession(sharedSecret))
		return
	}
	slog.Debug("no auth -> fallback", "peer", c.RemoteAddr().String(), "steal_host", s.stealHost)
	spliceConn(c, br, raw, s.preconn)
}

// authenticate returns the shared secret for an authorized ClientHello, or nil.
func (s *server) authenticate(raw []byte) []byte {
	sid, xpub, perr := clienthello.Parse(raw)
	if perr != nil || len(xpub) != 32 || len(sid) < auth.TagLen {
		return nil
	}
	pub, kerr := ecdh.X25519().NewPublicKey(xpub)
	if kerr != nil {
		return nil
	}
	ss, derr := s.priv.ECDH(pub)
	if derr != nil {
		return nil
	}
	shortID, ok := auth.Open(ss, xpub, s.serverPub, sid[:auth.TagLen])
	if !ok || !carrier.AllowlistOrAny(s.allowed, shortID) {
		return nil
	}
	return ss
}

// peerIP extracts the source IP (without port) for rate-limit keying.
func peerIP(c net.Conn) string {
	if host, _, err := net.SplitHostPort(c.RemoteAddr().String()); err == nil {
		return host
	}
	return c.RemoteAddr().String()
}

// serveTunnel reads one inner request from the authenticated transport and
// performs egress. The transport is either the raw post-handshake stream
// (default build) or a Reality-hijacked TLS session (chimera_utls build).
// Vision-splicing: the relay payload is classified (TLS/plain) and relayed via
// vision.Splice, which preserves any peeked bytes and logs the flow type.
func serveTunnel(rw io.ReadWriteCloser, sess *tunnel.Session) {
	cmd, host, port, err := sess.ReadRequest(rw)
	if err != nil {
		return
	}
	if cmd == tunnel.CmdPing {
		_ = sess.WriteStatus(rw, true)
		return
	}
	target, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		_ = sess.WriteStatus(rw, false)
		return
	}
	defer target.Close()
	if err := sess.WriteStatus(rw, true); err != nil {
		return
	}
	vision.Splice(rw, target)
}

// spliceConn relays c to the steal-host using a pre-warmed connection from the
// pool (timing-equalized path). Falls back to a fresh dial if the pool is dry.
func spliceConn(c net.Conn, br *bufio.Reader, replay []byte, pool *preconnect.Pool) {
	ctx := context.Background()
	backend, err := pool.Get(ctx)
	if err != nil {
		return
	}
	defer backend.Close()
	if _, err := backend.Write(replay); err != nil {
		return
	}
	go func() { _, _ = io.Copy(backend, br) }()
	_, _ = io.Copy(c, backend)
}

// splice is kept for callers that manage their own backend connection.
func splice(c net.Conn, br *bufio.Reader, replay []byte, stealHost string) {
	backend, err := net.Dial("tcp", stealHost)
	if err != nil {
		return
	}
	defer backend.Close()
	if _, err := backend.Write(replay); err != nil {
		return
	}
	go func() { _, _ = io.Copy(backend, br) }()
	_, _ = io.Copy(c, backend)
}

// readRecord reads one full TLS record without consuming the rest of the stream.
func readRecord(br *bufio.Reader) ([]byte, error) {
	hdr, err := br.Peek(5)
	if err != nil {
		return nil, err
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	full := make([]byte, 5+recLen)
	if _, err := io.ReadFull(br, full); err != nil {
		return nil, err
	}
	return full, nil
}
