//go:build chimera_quic

package quic

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"chimera/internal/auth"
	"chimera/internal/carrier"
	"chimera/internal/keys"
	"chimera/internal/shaper"
	"chimera/internal/tunnel"
)

const dialTimeout = 10 * time.Second

// sessionCaches holds one TLS ClientSessionCache per server address. Keying by
// address (not SNI) prevents cross-server ticket reuse: two CHIMERA servers with
// the same SNI but different TLS certs don't share entries. This enables 0-RTT on
// reconnect to the same server while keeping address-distinct caches isolated.
var (
	sessionCachesMu sync.Mutex
	sessionCaches   = map[string]tls.ClientSessionCache{}
)

func sessionCacheFor(addr string) tls.ClientSessionCache {
	sessionCachesMu.Lock()
	defer sessionCachesMu.Unlock()
	c, ok := sessionCaches[addr]
	if !ok {
		c = tls.NewLRUClientSessionCache(2)
		sessionCaches[addr] = c
	}
	return c
}

// DialConnect opens a QUIC carrier and requests a tunnel to host:port. The
// returned conn is ready for bidirectional relay. If cfg.Shaping is true the
// write path is wrapped in the H3-video traffic shaper (stealth envelope).
// Registered as the QUIC dialer in carrier so the endpoint Pool and SOCKS
// inbound use it transparently.
func DialConnect(cfg carrier.Config, host string, port uint16) (net.Conn, error) {
	sc, sess, err := establish(cfg)
	if err != nil {
		return nil, err
	}
	if err := sess.WriteConnect(sc, host, port); err != nil {
		sc.Close()
		return nil, err
	}
	ok, err := sess.ReadStatus(sc)
	if err != nil {
		sc.Close()
		return nil, err
	}
	if !ok {
		sc.Close()
		return nil, errors.New("quic carrier: server refused CONNECT (upstream dial failed)")
	}
	if cfg.Shaping {
		return shaper.WrapConn(sc, shaper.DefaultConfig()), nil
	}
	return sc, nil
}

// Ping verifies the QUIC handshake + tunnel path end-to-end (client PoC).
func Ping(cfg carrier.Config) error {
	sc, sess, err := establish(cfg)
	if err != nil {
		return err
	}
	defer sc.Close()
	if err := sess.WritePing(sc); err != nil {
		return err
	}
	_ = sc.SetReadDeadline(time.Now().Add(5 * time.Second))
	ok, err := sess.ReadStatus(sc)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("quic carrier: server did not acknowledge (auth not recognized?)")
	}
	return nil
}

// dial opens a QUIC connection to the server (no stream yet). Split out from
// authStream so one connection can host several authenticated streams — needed
// by the UDP-association multiplexer (udpclient.go), where many associations
// share a single carrier connection and its datagram channel.
func dial(cfg carrier.Config) (*quic.Conn, error) {
	fp := resolveQUICFingerprint(cfg.Fp)
	tlsConf := &tls.Config{
		InsecureSkipVerify: true, // self-signed PoC cert; parity follow-up replaces this
		NextProtos:         []string{fp.ALPN},
		ServerName:         cfg.SNI,
		// Per-address session cache enables 0-RTT on reconnect to the same server.
		// Using cfg.Server as the cache key (not SNI) prevents cross-server ticket reuse.
		ClientSessionCache: sessionCacheFor(cfg.Server),
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	// DialAddrEarly sends 0-RTT data on a resumed session, saving one RTT on
	// reconnect. On first connect (no cached ticket), it falls back to 1-RTT.
	return quic.DialAddrEarly(ctx, cfg.Server, tlsConf, quicConfigForFingerprint(cfg.BandwidthBps, fp))
}

// authStream opens a new stream on conn and writes the auth preface (ephemeral
// pub || sealed tag). The server authenticates every stream independently, so
// each association/CONNECT opens its own authenticated stream. Returns the stream
// as a net.Conn plus the per-session seeded-padding tunnel keyed by the shared
// secret — identical inner protocol to the TCP carrier.
func authStream(conn *quic.Conn, cfg carrier.Config) (*streamConn, *tunnel.Session, error) {
	serverPub, err := keys.DecodePublic(cfg.PubB64)
	if err != nil {
		return nil, nil, err
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ephPub := eph.PublicKey().Bytes()
	ss, err := eph.ECDH(serverPub)
	if err != nil {
		return nil, nil, err
	}
	tag, err := auth.Seal(ss, ephPub, serverPub.Bytes(), carrier.ParseShortID(cfg.ShortIDHex))
	if err != nil {
		return nil, nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, nil, err
	}

	preface := make([]byte, 0, prefaceLen)
	preface = append(preface, ephPub...)
	preface = append(preface, tag...)
	if _, err := stream.Write(preface); err != nil {
		return nil, nil, err
	}
	return &streamConn{Stream: stream, conn: conn}, tunnel.ClientSession(ss), nil
}

// establish performs the QUIC stealth handshake for a single stream: it dials the
// server, then opens an authenticated stream. Returns the stream as a net.Conn
// plus the per-session seeded-padding tunnel.
func establish(cfg carrier.Config) (*streamConn, *tunnel.Session, error) {
	conn, err := dial(cfg)
	if err != nil {
		return nil, nil, err
	}
	sc, sess, err := authStream(conn, cfg)
	if err != nil {
		_ = conn.CloseWithError(0, "")
		return nil, nil, err
	}
	return sc, sess, nil
}
