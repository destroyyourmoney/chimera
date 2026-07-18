package controlplane

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const TokenTTL = 24 * time.Hour

var b64 = base64.RawURLEncoding

type TokenPayload struct {
	ShortIDHex    string `json:"sid"`
	AccountIDHash string `json:"aih"`
	DevicePubKey  string `json:"dpk"`
	IssuedAt      int64  `json:"iat"`
	ExpiresAt     int64  `json:"exp"`
}

type Signer struct {
	priv ed25519.PrivateKey
}

func NewSigner(priv ed25519.PrivateKey) *Signer { return &Signer{priv: priv} }

func GenerateKeypair() (pub ed25519.PublicKey, priv ed25519.PrivateKey, err error) {
	return ed25519.GenerateKey(rand.Reader)
}

func (s *Signer) Sign(payload TokenPayload) (string, error) {
	now := time.Now()
	payload.IssuedAt = now.Unix()
	payload.ExpiresAt = now.Add(TokenTTL).Unix()
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("controlplane: marshal token payload: %w", err)
	}
	sig := ed25519.Sign(s.priv, body)
	return b64.EncodeToString(body) + "." + b64.EncodeToString(sig), nil
}

type Verifier struct {
	pubs []ed25519.PublicKey
}

func NewVerifier(pubs ...ed25519.PublicKey) *Verifier { return &Verifier{pubs: pubs} }

func (s *Signer) SignBytes(data []byte) string {
	return b64.EncodeToString(ed25519.Sign(s.priv, data))
}

func (v *Verifier) VerifyBytes(data []byte, sigB64 string) bool {
	sig, err := b64.DecodeString(sigB64)
	if err != nil {
		return false
	}
	for _, pub := range v.pubs {
		if ed25519.Verify(pub, data, sig) {
			return true
		}
	}
	return false
}

var (
	ErrTokenMalformed = errors.New("controlplane: malformed token")
	ErrTokenBadSig    = errors.New("controlplane: bad signature")
	ErrTokenExpired   = errors.New("controlplane: token expired")
)

func (v *Verifier) Verify(token string) (TokenPayload, error) {
	dot := -1
	for i := len(token) - 1; i >= 0; i-- {
		if token[i] == '.' {
			dot = i
			break
		}
	}
	if dot < 0 {
		return TokenPayload{}, ErrTokenMalformed
	}
	body, err := b64.DecodeString(token[:dot])
	if err != nil {
		return TokenPayload{}, ErrTokenMalformed
	}
	sig, err := b64.DecodeString(token[dot+1:])
	if err != nil {
		return TokenPayload{}, ErrTokenMalformed
	}

	verified := false
	for _, pub := range v.pubs {
		if ed25519.Verify(pub, body, sig) {
			verified = true
			break
		}
	}
	if !verified {
		return TokenPayload{}, ErrTokenBadSig
	}

	var p TokenPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return TokenPayload{}, ErrTokenMalformed
	}
	if time.Now().Unix() > p.ExpiresAt {
		return TokenPayload{}, ErrTokenExpired
	}
	return p, nil
}
