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
	windowSeconds = 120
	infoLabel     = "chimera-auth-v0"

	ShortIDLen   = 4
	plaintextLen = 8 + ShortIDLen

	TagLen = plaintextLen + 16
)

var nowFunc = time.Now

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
	if !(w == now || w+1 == now || w == now+1) {
		return nil, false
	}
	return pt[8 : 8+ShortIDLen], true
}
