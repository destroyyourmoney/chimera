//go:build chimera_utls

package clienthello

import (
	"crypto/rand"
	"errors"
	"net"

	utls "github.com/refraction-networking/utls"
)

func init() { Active = utlsBuilder{} }

var errNoX25519 = errors.New("clienthello: uTLS hello has no X25519 key_share to bind")

type utlsBuilder struct{}

func (utlsBuilder) BuildClientHello(sni string, sessionID, x25519Pub []byte) []byte {
	rec, err := buildUTLS(sni, sessionID, x25519Pub)
	if err != nil {
		return Build(sni, sessionID, x25519Pub)
	}
	return rec
}

func buildUTLS(sni string, sessionID, x25519Pub []byte) ([]byte, error) {

	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()

	cfg := &utls.Config{ServerName: sni, MinVersion: utls.VersionTLS12, MaxVersion: utls.VersionTLS13}
	u := utls.UClient(local, cfg, utls.HelloChrome_Auto)
	if err := u.BuildHandshakeState(); err != nil {
		return nil, err
	}

	u.HandshakeState.Hello.SessionId = padSessionID(sessionID)

	if err := bindX25519KeyShare(u, x25519Pub); err != nil {
		return nil, err
	}

	if err := u.MarshalClientHello(); err != nil {
		return nil, err
	}
	return wrapRecord(u.HandshakeState.Hello.Raw), nil
}

func padSessionID(sessionID []byte) []byte {
	sid := make([]byte, 32)
	copy(sid, sessionID)
	if len(sessionID) < 32 {
		_, _ = rand.Read(sid[len(sessionID):])
	}
	return sid
}

func bindX25519KeyShare(u *utls.UConn, x25519Pub []byte) error {
	for _, ext := range u.Extensions {
		ks, ok := ext.(*utls.KeyShareExtension)
		if !ok {
			continue
		}
		for i := range ks.KeyShares {
			if ks.KeyShares[i].Group == utls.X25519 {
				data := make([]byte, len(x25519Pub))
				copy(data, x25519Pub)
				ks.KeyShares[i].Data = data
				return nil
			}
		}
	}
	return errNoX25519
}

func wrapRecord(handshake []byte) []byte {
	rec := make([]byte, 0, 5+len(handshake))
	rec = append(rec, 0x16, 0x03, 0x01, byte(len(handshake)>>8), byte(len(handshake)))
	return append(rec, handshake...)
}
