//go:build chimera_quic

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

const alpn = "h3"

const prefaceLen = 32 + auth.TagLen

const (
	idleTimeout = 30 * time.Second
	keepAlive   = 15 * time.Second
)

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

type quicListener interface {
	Accept(ctx context.Context) (*quic.Conn, error)
	Close() error
	Addr() net.Addr
}

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

func shortIDAllowed(allowed carrier.Allowlist, sid []byte) bool {
	return carrier.AllowlistOrAny(allowed, sid)
}

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
