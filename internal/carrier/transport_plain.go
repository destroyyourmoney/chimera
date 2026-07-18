//go:build !chimera_utls

package carrier

import (
	"crypto/ecdh"
	"crypto/rand"
	"net"

	"chimera/internal/auth"
	"chimera/internal/clienthello"
	"chimera/internal/keys"
	"chimera/internal/tunnel"
)

func establish(cfg Config) (net.Conn, *tunnel.Session, error) {
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
	tag, err := auth.Seal(ss, ephPub, serverPub.Bytes(), ParseShortID(cfg.ShortIDHex))
	if err != nil {
		return nil, nil, err
	}
	ch := clienthello.Active.BuildClientHello(cfg.SNI, tag, ephPub)

	conn, err := net.DialTimeout("tcp", cfg.Server, DialTimeout)
	if err != nil {
		return nil, nil, err
	}
	if _, err := conn.Write(ch); err != nil {
		conn.Close()
		return nil, nil, err
	}
	return conn, tunnel.ClientSession(ss), nil
}
