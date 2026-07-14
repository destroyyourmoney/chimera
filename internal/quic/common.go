//go:build chimera_quic

// Package quic implements the CHIMERA QUIC carrier — the loss-resilient transport
// that is CHIMERA's core differentiator (TCP-Reality collapses under packet loss;
// see docker/bench.sh). It mirrors the TCP carrier exactly at the inner-protocol
// layer: the authenticated session speaks the same tunnel.Session request protocol
// (CONNECT/PING + seeded padding), so the endpoint Pool and SOCKS inbound route
// over it unchanged.
//
// PoC scope (this increment): the authentication tag rides the first bytes of the
// first QUIC stream, and the QUIC handshake uses a self-signed certificate with
// ALPN "h3". This proves the carrier + tunnel + loss-resilience path end-to-end.
// Stealth parity — a Chrome-H3 QUIC Initial fingerprint (uquic), genuine steal-host
// SNI, and transparent UDP fallback for unauthenticated peers — is the explicit
// follow-up, mirroring how the TCP carrier added uTLS in Phase 1b after the path
// was proven. ElasticCC (loss≠congestion) and adaptive FEC layer on top of this.
//
// This file is built only with -tags chimera_quic so the default binary never
// imports quic-go.
package quic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/quic-go/quic-go"

	"chimera/internal/auth"
	"chimera/internal/carrier"
)

// alpn is the application protocol advertised in the QUIC/TLS handshake. "h3"
// keeps the carrier plausibly HTTP/3 while real ClientHello-Initial fingerprint
// parity is pending (uquic follow-up).
const alpn = "h3"

// prefaceLen is the fixed authentication preface written on the first stream:
// the client's ephemeral X25519 public key followed by the sealed auth tag.
const prefaceLen = 32 + auth.TagLen

// idleTimeout / keepAlive keep an otherwise-quiet carrier alive without churn.
const (
	idleTimeout = 30 * time.Second
	keepAlive   = 15 * time.Second
)

// quicConfig is the shared QUIC tuning for both ends.
// UseElasticCC: ElasticCC replaces Cubic so loss does not cut the congestion window.
// EnableDatagrams: RFC 9221 unreliable datagram payload path (UDP proxy via datagrams).
// Allow0RTT: server accepts 0-RTT session resumption (client stores session tickets
// via the process-level sessionCache in client.go).
// quicConfig builds the shared QUIC tuning. elasticBW > 0 puts ElasticCC into
// fixed-rate "Brutal" mode at that target (bytes/s) — set it to the link capacity
// to hold goodput under 30–40 % loss; 0 keeps adaptive estimation.
func quicConfig(elasticBW uint64) *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:     idleTimeout,
		KeepAlivePeriod:    keepAlive,
		EnableDatagrams:    true,
		UseElasticCC:       true,
		ElasticCCBandwidth: elasticBW,
		Allow0RTT:          true,
	}
}

// quicListener is the minimal interface satisfied by both *quic.Listener (1-RTT
// only) and *quic.EarlyListener (0-RTT capable). Both Accept() return (*Conn, error).
type quicListener interface {
	Accept(ctx context.Context) (*quic.Conn, error)
	Close() error
	Addr() net.Addr
}

// streamConn adapts a QUIC stream (+ its connection, for addresses) to net.Conn
// so the existing relay code (io.Copy, deadlines) works unchanged. Closing it
// tears down the whole connection, since the PoC uses one connection per stream.
type streamConn struct {
	*quic.Stream
	conn *quic.Conn
}

func (s *streamConn) LocalAddr() net.Addr  { return s.conn.LocalAddr() }
func (s *streamConn) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }

func (s *streamConn) Close() error {
	err := s.Stream.Close()
	_ = s.conn.CloseWithError(0, "")
	return err
}

// shortIDAllowed reports whether sid is authorized under allowed. A nil
// Allowlist (untyped) means accept-any, matching the PoC convenience of an
// empty StaticAllowlist.
func shortIDAllowed(allowed carrier.Allowlist, sid []byte) bool {
	return carrier.AllowlistOrAny(allowed, sid)
}

// serverTLS builds a self-signed TLS config for the QUIC listener. The cert is
// not yet a steal-host relay (parity follow-up); inside QUIC it is encrypted and
// invisible to a passive observer.
func serverTLS() (*tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("quic: gen cert key: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "chimera"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("quic: create cert: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
		NextProtos:   []string{alpn},
		MinVersion:   tls.VersionTLS13,
	}, nil
}
