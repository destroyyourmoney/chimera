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

func dial(cfg carrier.Config) (*quic.Conn, error) {
	fp := resolveQUICFingerprint(cfg.Fp)
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{fp.ALPN},
		ServerName:         cfg.SNI,

		ClientSessionCache: sessionCacheFor(cfg.Server),
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	return quic.DialAddrEarly(ctx, cfg.Server, tlsConf, quicConfigForFingerprint(cfg.BandwidthBps, fp))
}

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
