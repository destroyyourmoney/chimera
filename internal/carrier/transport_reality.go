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

// establish performs the Reality handshake takeover: a live uTLS handshake that
// completes a real TLS 1.3 session with the server, authenticated by the shared
// secret. The inner protocol then rides INSIDE that TLS session so it is
// invisible on the wire. The fingerprint is selected per-connection from cfg.Fp
// (e.g. "chrome", "firefox"); empty defaults to the current Fingerprint global.
func establish(cfg Config) (net.Conn, *tunnel.Session, error) {
	serverPub, err := keys.DecodePublic(cfg.PubB64)
	if err != nil {
		return nil, nil, err
	}
	// Apply per-call fingerprint override if specified.
	if cfg.Fp != "" {
		// Best-effort: if the name is unknown we proceed with the current global.
		_ = reality.SetFingerprint(cfg.Fp)
	}
	conn, err := net.Dial("tcp", cfg.Server)
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
