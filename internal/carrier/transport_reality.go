//go:build chimera_utls

package carrier

import (
	"net"

	"chimera/internal/keys"
	"chimera/internal/reality"
	"chimera/internal/tunnel"
)

func init() {
	FingerprintUpdater = func(name string) { _ = reality.SetFingerprint(name) }
}

func establish(cfg Config) (net.Conn, *tunnel.Session, error) {
	serverPub, err := keys.DecodePublic(cfg.PubB64)
	if err != nil {
		return nil, nil, err
	}

	if cfg.Fp != "" {

		_ = reality.SetFingerprint(cfg.Fp)
	}
	conn, err := net.DialTimeout("tcp", cfg.Server, DialTimeout)
	if err != nil {
		return nil, nil, err
	}
	tlsConn, ss, err := reality.ClientWrap(conn, serverPub, cfg.SNI, cfg.ShortIDHex)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	return tlsConn, tunnel.ClientSession(ss), nil
}
