//go:build chimera_utls

// This file replaces the hand-rolled ClientHello builder with one backed by
// uTLS, giving the carrier a real Chrome fingerprint (JA3/JA4 parity) while still
// carrying the CHIMERA auth tag and ephemeral key. It is compiled in only under
// the `chimera_utls` build tag, so the default build keeps zero TLS dependencies.
//
// We do NOT drive a full uTLS handshake here — we only emit the ClientHello
// bytes. uTLS builds an authentic Chrome hello; we then overwrite two fields:
//   - SessionId            -> the CHIMERA auth tag (padded to 32 like Chrome's
//     TLS 1.3 compatibility-mode session id)
//   - the X25519 key_share -> our ephemeral public key, so the server recomputes
//     the same shared secret. Other key shares (e.g. the
//     X25519MLKEM768 hybrid) keep their real Chrome bytes
//     for fingerprint fidelity; the server ignores them.
package clienthello

import (
	"crypto/rand"
	"errors"
	"net"

	utls "github.com/refraction-networking/utls"
)

// init swaps the active builder when the chimera_utls tag is present. No caller
// changes; carrier.dialHandshake transparently emits Chrome-fingerprinted hellos.
func init() { Active = utlsBuilder{} }

var errNoX25519 = errors.New("clienthello: uTLS hello has no X25519 key_share to bind")

type utlsBuilder struct{}

// BuildClientHello builds a Chrome-fingerprinted ClientHello. On any uTLS error
// it falls back to the stdlib builder so the handshake is never broken (the
// fallback degrades fingerprint parity, not connectivity).
func (utlsBuilder) BuildClientHello(sni string, sessionID, x25519Pub []byte) []byte {
	rec, err := buildUTLS(sni, sessionID, x25519Pub)
	if err != nil {
		return Build(sni, sessionID, x25519Pub)
	}
	return rec
}

func buildUTLS(sni string, sessionID, x25519Pub []byte) ([]byte, error) {
	// uTLS needs a net.Conn, but BuildHandshakeState/MarshalClientHello do no I/O.
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()

	cfg := &utls.Config{ServerName: sni, MinVersion: utls.VersionTLS12, MaxVersion: utls.VersionTLS13}
	u := utls.UClient(local, cfg, utls.HelloChrome_Auto)
	if err := u.BuildHandshakeState(); err != nil {
		return nil, err
	}

	// SessionId is read from the hello header at marshal time, so set it here.
	u.HandshakeState.Hello.SessionId = padSessionID(sessionID)

	// Extensions are marshaled from u.Extensions (not hello.KeyShares), so the
	// X25519 share must be rebound inside the KeyShareExtension object.
	if err := bindX25519KeyShare(u, x25519Pub); err != nil {
		return nil, err
	}

	if err := u.MarshalClientHello(); err != nil {
		return nil, err
	}
	return wrapRecord(u.HandshakeState.Hello.Raw), nil
}

// padSessionID copies the auth tag and pads to 32 bytes with random, matching
// Chrome's compatibility-mode session id length.
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

// wrapRecord wraps a handshake message in a TLS record with legacy_record_version
// 0x0301 (TLS 1.0), exactly as Chrome frames its first flight.
func wrapRecord(handshake []byte) []byte {
	rec := make([]byte, 0, 5+len(handshake))
	rec = append(rec, 0x16, 0x03, 0x01, byte(len(handshake)>>8), byte(len(handshake)))
	return append(rec, handshake...)
}
