// Package carrier establishes a CHIMERA carrier connection from the client:
// it performs the stealth handshake (auth tag in ClientHello) and then issues an
// inner request (CONNECT or PING) over the same connection.
//
// The transport for the authenticated session is build-tag dependent (see
// transport_plain.go / transport_reality.go):
//   - default build: the inner protocol rides the post-handshake TCP stream;
//   - chimera_utls build: it rides INSIDE a real, Reality-hijacked TLS 1.3
//     session, so none of these bytes are visible on the wire.
package carrier

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"

	"chimera/internal/auth"
	"chimera/internal/tunnel"
)

// Allowlist decides whether a short ID may authenticate. Implementations must
// be safe for concurrent use, since the TCP and QUIC carriers call Allowed from
// per-connection goroutines. A nil Allowlist means "accept any" (PoC/legacy
// behavior); callers should check for nil before calling Allowed, or use the
// AllowlistOrAny helper.
type Allowlist interface {
	Allowed(sid []byte) bool
}

// StaticAllowlist is a fixed set of allowed short IDs decoded once at startup
// (the legacy -sid / short_ids: behavior). An empty StaticAllowlist accepts any
// short ID, matching the pre-existing PoC convenience.
type StaticAllowlist [][]byte

// Allowed reports whether sid matches one of the fixed short IDs.
func (a StaticAllowlist) Allowed(sid []byte) bool {
	if len(a) == 0 {
		return true // PoC convenience
	}
	for _, s := range a {
		if subtle.ConstantTimeCompare(s, sid) == 1 {
			return true
		}
	}
	return false
}

// AllowlistOrAny reports whether sid is authorized under allowed, treating a
// nil Allowlist (untyped, e.g. a caller that never constructed one) as
// accept-any — the same convenience as an empty StaticAllowlist.
func AllowlistOrAny(allowed Allowlist, sid []byte) bool {
	if allowed == nil {
		return true
	}
	return allowed.Allowed(sid)
}

// TokenVerifier is the controlplane-backed counterpart to Allowlist
// (ROADMAP2 §1): instead of checking a short ID against a locally-pushed
// list, it checks a capability token the client presents against the
// control-plane's public signing key plus a locally-cached, periodically
// polled revocation list — no per-connection network call or disk read.
// A server picks Allowlist (legacy/BYO, -auth-mode useracl) or
// TokenVerifier (-auth-mode controlplane) at startup, never both; see
// internal/server.Config.
type TokenVerifier interface {
	// VerifyToken reports whether token is validly signed, unexpired, not
	// revoked, and was issued for shortIDHex specifically (a token can't be
	// replayed under a different short ID recovered from a different
	// handshake).
	VerifyToken(token string, shortIDHex string) bool
}

// Config describes how to reach a CHIMERA server (normally from a chimera:// link).
type Config struct {
	Server       string // host:port
	PubB64       string // server static X25519 public key (base64url)
	SNI          string // steal-host SNI to present
	ShortIDHex   string // short ID as hex (optional)
	Transport    string // "tcp" (default), "quic", "quic-rudp" (reliable-FEC datagram bulk), or "auto" (race tcp+quic)
	Shaping      bool   // enable H3-video traffic shaping on the write path (QUIC only)
	Fp           string // browser fingerprint/profile name: TCP uTLS and QUIC Chrome-H3 selector
	BandwidthBps uint64 // QUIC ElasticCC Brutal fixed-rate target (bytes/s); 0 = adaptive
	// Token is the control-plane capability token (ROADMAP2 §1) to present
	// after the handshake when dialing a server running -auth-mode
	// controlplane. Empty for legacy (-auth-mode useracl) servers, which
	// never expect the CmdAuthToken frame at all.
	Token string
}

// QUICServerConfig configures the QUIC carrier server. It is defined here (rather
// than in internal/quic) so the QUIC code can be registered without the default
// build importing quic-go.
type QUICServerConfig struct {
	Listen       string
	PrivB64      string
	StealHost    string   // UDP fallback target for unauthenticated peers (later use)
	ShortIDs     []string // allowed short IDs as hex; empty = accept any (PoC)
	BandwidthBps uint64   // QUIC ElasticCC Brutal fixed-rate target (bytes/s); 0 = adaptive
	// Allowlist, if set, overrides ShortIDs with a dynamic allow-list (e.g.
	// internal/useracl.Store) so users can be added/revoked without a restart.
	Allowlist Allowlist
}

// UDPCarrier is a client-side UDP-association multiplexer over a single QUIC
// carrier connection. Each OpenAssoc binds one target (host:port) on the server
// and returns an assocID; datagrams ride the QUIC DATAGRAM channel (FEC-framed,
// loss-resilient) tagged with that assocID. One connection hosts many
// associations, so a SOCKS5 UDP ASSOCIATE relay can fan out to many targets.
type UDPCarrier interface {
	// OpenAssoc binds host:port on the server, returning the datagram assocID.
	OpenAssoc(host string, port uint16) (assocID uint16, err error)
	// Send forwards payload to the target bound to assocID (best-effort, unreliable).
	Send(assocID uint16, payload []byte) error
	// Receive blocks for the next inbound datagram (any association), returning its
	// assocID and payload. Returns an error when ctx is done or the carrier closes.
	Receive(ctx context.Context) (assocID uint16, payload []byte, err error)
	// Close tears down the carrier connection and all associations.
	Close() error
}

// QUIC carrier registry. internal/quic populates these in init() when the binary
// is built with -tags chimera_quic; otherwise they stay nil and selecting the
// QUIC transport reports a clear "built without QUIC support" error.
var (
	QUICDialConnect func(cfg Config, host string, port uint16) (net.Conn, error)
	// QUICDialConnectRUDP opens a CONNECT whose bulk relay rides the reliable-FEC
	// datagram transport (internal/rudp) over QUIC datagrams — the loss-resilient
	// bulk sub-mode selected by Transport "quic-rudp".
	QUICDialConnectRUDP func(cfg Config, host string, port uint16) (net.Conn, error)
	QUICPing            func(cfg Config) error
	QUICServe           func(ctx context.Context, cfg QUICServerConfig) error
	QUICDialUDP         func(cfg Config) (UDPCarrier, error)
)

// SSServerConfig configures the Shadowsocks-AEAD carrier server (ROADMAP2
// §3). Defined here (rather than in transport_shadowsocks.go) so it exists
// regardless of the chimera_ss build tag, same reason QUICServerConfig
// lives here instead of internal/quic -- callers can reference the type
// without importing quic-go/an SS implementation.
type SSServerConfig struct {
	Listen        string
	PrivB64       string
	ShortIDs      []string
	Allowlist     Allowlist
	TokenVerifier TokenVerifier
	AuthRate      float64
	AuthBurst     float64
}

// Shadowsocks-AEAD carrier registry (ROADMAP2 §3), populated by
// internal/carrier/transport_shadowsocks.go's init() when built with
// -tags chimera_ss; nil otherwise, same "graceful degrade to a clear
// error" contract as the QUIC registry above.
var (
	SSDialConnect func(cfg Config, host string, port uint16) (net.Conn, error)
	SSPing        func(cfg Config) error
	SSServe       func(ctx context.Context, cfg SSServerConfig) error
)

var errNoSS = errors.New("carrier: built without Shadowsocks-AEAD support (rebuild with -tags chimera_ss)")

// DoTServerConfig configures the DNS-over-TCP carrier server (ROADMAP2 §3).
// SNI doubles as the DNS query name the disguised traffic uses.
type DoTServerConfig struct {
	Listen        string
	PrivB64       string
	SNI           string
	ShortIDs      []string
	Allowlist     Allowlist
	TokenVerifier TokenVerifier
	AuthRate      float64
	AuthBurst     float64
}

// DNS-over-TCP carrier registry (ROADMAP2 §3), populated by
// internal/carrier/transport_dot.go's init() when built with -tags
// chimera_dot; nil otherwise.
var (
	DoTDialConnect func(cfg Config, host string, port uint16) (net.Conn, error)
	DoTPing        func(cfg Config) error
	DoTServe       func(ctx context.Context, cfg DoTServerConfig) error
)

var errNoDoT = errors.New("carrier: built without DNS-over-TCP support (rebuild with -tags chimera_dot)")

// FingerprintUpdater is registered by internal/reality (chimera_utls build) in
// its init(). Callers (e.g. config.Watch callbacks) invoke it to change the
// global uTLS fingerprint without restarting. No-op when nil (plain build).
var FingerprintUpdater func(name string)

// errNoQUIC is returned when the QUIC transport is requested from a binary that
// was built without the chimera_quic tag.
var errNoQUIC = errors.New("carrier: built without QUIC support (rebuild with -tags chimera_quic)")

// ParseShortID decodes the hex short ID, padded/truncated to auth.ShortIDLen.
func ParseShortID(s string) []byte {
	out := make([]byte, auth.ShortIDLen)
	b, err := hex.DecodeString(s)
	if err == nil {
		copy(out, b)
	}
	return out
}

// DialConnect opens a carrier and requests a tunnel to host:port. On success the
// returned conn is ready for bidirectional relay.
// Transport "auto" races QUIC and TCP; see DialRace.
func DialConnect(cfg Config, host string, port uint16) (net.Conn, error) {
	switch cfg.Transport {
	case "quic":
		if QUICDialConnect == nil {
			return nil, errNoQUIC
		}
		return QUICDialConnect(cfg, host, port)
	case "quic-rudp":
		if QUICDialConnectRUDP == nil {
			return nil, errNoQUIC
		}
		return QUICDialConnectRUDP(cfg, host, port)
	case "ss":
		if SSDialConnect == nil {
			return nil, errNoSS
		}
		return SSDialConnect(cfg, host, port)
	case "dot":
		if DoTDialConnect == nil {
			return nil, errNoDoT
		}
		return DoTDialConnect(cfg, host, port)
	case "auto":
		return DialRace(cfg, host, port)
	}
	conn, sess, err := establish(cfg)
	if err != nil {
		return nil, err
	}
	if err := presentToken(conn, sess, cfg.Token); err != nil {
		conn.Close()
		return nil, err
	}
	if err := sess.WriteConnect(conn, host, port); err != nil {
		conn.Close()
		return nil, err
	}
	ok, err := sess.ReadStatus(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if !ok {
		conn.Close()
		return nil, errors.New("carrier: server refused CONNECT (upstream dial failed)")
	}
	return conn, nil
}

// presentToken sends cfg.Token (ROADMAP2 §1) and waits for the server's
// accept/reject reply, when a token is configured at all -- a no-op
// against a legacy (-auth-mode useracl) server or when the caller never
// set cfg.Token, so this is fully backward compatible.
func presentToken(conn net.Conn, sess *tunnel.Session, token string) error {
	if token == "" {
		return nil
	}
	if err := sess.WriteAuthToken(conn, token); err != nil {
		return err
	}
	ok, err := sess.ReadStatus(conn)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("carrier: server rejected capability token")
	}
	return nil
}

// DialRace fires QUIC and TCP dials concurrently and returns the first successful
// connection. The losing connection (if it also succeeds) is closed immediately.
// If QUIC support is not compiled in, gracefully degrades to TCP only.
func DialRace(cfg Config, host string, port uint16) (net.Conn, error) {
	if QUICDialConnect == nil {
		tcpCfg := cfg
		tcpCfg.Transport = "tcp"
		return DialConnect(tcpCfg, host, port)
	}

	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 2)

	quicCfg := cfg
	quicCfg.Transport = "quic"
	go func() {
		c, err := DialConnect(quicCfg, host, port)
		ch <- result{c, err}
	}()

	tcpCfg := cfg
	tcpCfg.Transport = "tcp"
	go func() {
		c, err := DialConnect(tcpCfg, host, port)
		ch <- result{c, err}
	}()

	var firstErr error
	for i := 0; i < 2; i++ {
		r := <-ch
		if r.err == nil {
			go func() {
				// Drain and discard the loser.
				if r2 := (<-ch); r2.conn != nil {
					r2.conn.Close()
				}
			}()
			return r.conn, nil
		}
		firstErr = r.err
	}
	return nil, fmt.Errorf("carrier: both transports failed: %w", firstErr)
}

// Ping verifies the handshake and tunnel path end-to-end (client PoC).
// Transport "auto" tries QUIC first, then falls back to TCP on failure.
func Ping(cfg Config) error {
	switch cfg.Transport {
	case "quic":
		if QUICPing == nil {
			return errNoQUIC
		}
		return QUICPing(cfg)
	case "ss":
		if SSPing == nil {
			return errNoSS
		}
		return SSPing(cfg)
	case "dot":
		if DoTPing == nil {
			return errNoDoT
		}
		return DoTPing(cfg)
	case "auto":
		if QUICPing != nil {
			quicCfg := cfg
			quicCfg.Transport = "quic"
			if err := Ping(quicCfg); err == nil {
				return nil
			}
		}
		tcpCfg := cfg
		tcpCfg.Transport = "tcp"
		return Ping(tcpCfg)
	}
	conn, sess, err := establish(cfg)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := presentToken(conn, sess, cfg.Token); err != nil {
		return err
	}
	if err := sess.WritePing(conn); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	ok, err := sess.ReadStatus(conn)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("carrier: server did not acknowledge (auth not recognized?)")
	}
	return nil
}
