// Package auth implements the CHIMERA authentication tag that an authorized
// client embeds in the TLS ClientHello SessionID field.
//
// Mechanism (matches the Reality model):
//   - client generates an ephemeral X25519 key (also its TLS key_share)
//   - ss = X25519(eph_priv, server_static_pub)
//   - authKey, nonce = HKDF(ss)                ; nonce never travels
//   - tag = AES-256-GCM(authKey, nonce, timeWindow||shortID, AAD=eph_pub||server_pub)
//
// The server recomputes ss from its static private key and the client's
// key_share, derives the same authKey/nonce, opens the tag, and checks that the
// embedded shortID is in its allowed set. A peer without the server's static
// private key cannot forge a valid tag, and the field on the wire is
// indistinguishable from an ordinary 32-byte session ticket ID.
package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"time"
)

const (
	windowSeconds = 120               // time-window granularity (anti-replay)
	infoLabel     = "chimera-auth-v0" // HKDF context label
	// ShortIDLen is the length of the routing/auth short ID bound into the tag.
	ShortIDLen   = 4
	plaintextLen = 8 + ShortIDLen // uint64 window || shortID
	// TagLen is the AES-GCM output length the client writes into the SessionID.
	TagLen = plaintextLen + 16 // 12 + 16-byte GCM tag = 28 bytes
)

// nowFunc is a seam so tests can advance the clock to exercise replay windows.
var nowFunc = time.Now

// --- minimal HKDF-SHA256 (RFC 5869), standard library only ---

func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	return h.Sum(nil)
}

func hkdfExpand(prk, info []byte, n int) []byte {
	var out, t []byte
	for i := byte(1); len(out) < n; i++ {
		h := hmac.New(sha256.New, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{i})
		t = h.Sum(nil)
		out = append(out, t...)
	}
	return out[:n]
}

func deriveAEAD(ss, clientPub, serverPub []byte) (cipher.AEAD, []byte, error) {
	prk := hkdfExtract(serverPub, ss)
	km := hkdfExpand(prk, []byte(infoLabel), 32+12)
	block, err := aes.NewCipher(km[:32])
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	return aead, km[32:44], nil
}

func windowNow() uint64 { return uint64(nowFunc().Unix() / windowSeconds) }

func aad(clientPub, serverPub []byte) []byte {
	out := make([]byte, 0, len(clientPub)+len(serverPub))
	out = append(out, clientPub...)
	out = append(out, serverPub...)
	return out
}

// Seal builds the auth tag the client embeds in the SessionID. shortID is
// padded/truncated to ShortIDLen.
func Seal(ss, clientPub, serverPub, shortID []byte) ([]byte, error) {
	aead, nonce, err := deriveAEAD(ss, clientPub, serverPub)
	if err != nil {
		return nil, err
	}
	pt := make([]byte, plaintextLen)
	binary.BigEndian.PutUint64(pt[:8], windowNow())
	copy(pt[8:], shortID)
	return aead.Seal(nil, nonce, pt, aad(clientPub, serverPub)), nil
}

// Open verifies an auth tag. It returns the embedded shortID and true only for
// a valid tag inside the accepted time window. The full crypto path always runs
// to limit timing oracles; the caller still checks shortID membership.
func Open(ss, clientPub, serverPub, tag []byte) (shortID []byte, ok bool) {
	if len(tag) < TagLen {
		return nil, false
	}
	aead, nonce, err := deriveAEAD(ss, clientPub, serverPub)
	if err != nil {
		return nil, false
	}
	pt, err := aead.Open(nil, nonce, tag[:TagLen], aad(clientPub, serverPub))
	if err != nil {
		return nil, false
	}
	w := binary.BigEndian.Uint64(pt[:8])
	now := windowNow()
	if !(w == now || w+1 == now || w == now+1) { // tolerate one window of clock skew
		return nil, false
	}
	return pt[8 : 8+ShortIDLen], true
}
