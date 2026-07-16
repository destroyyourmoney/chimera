// Capability tokens (ROADMAP2 §1): Ed25519-signed, stateless proof that a
// short ID is currently allowed to use the server fleet. A data-plane
// server verifies these with nothing but the control-plane's public key --
// no network call, no disk read, O(1) -- after internal/auth.Open has
// already authenticated the transport handshake itself. The two checks
// answer different questions: auth.Open proves "this client owns the
// X25519 key for this connection"; VerifyToken proves "this shortID is
// still entitled to use the fleet at all".
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

// TokenTTL is how long a redeemed token is valid before the client must
// call refresh -- short enough that a revoked account stops working
// quickly even without hitting the revocation list, long enough that the
// VPN keeps working through a brief control-plane outage (ROADMAP2 §1.2).
const TokenTTL = 24 * time.Hour

var b64 = base64.RawURLEncoding

// TokenPayload is the signed claim set. AccountIDHash lets a server-side
// audit correlate "how many devices used this account's tokens" without
// ever learning the account number itself -- it's sha256(number_hash),
// not the number or its direct hash.
type TokenPayload struct {
	ShortIDHex    string `json:"sid"`
	AccountIDHash string `json:"aih"`
	DevicePubKey  string `json:"dpk"` // base64
	IssuedAt      int64  `json:"iat"` // unix seconds
	ExpiresAt     int64  `json:"exp"` // unix seconds
}

// Signer holds the control-plane's Ed25519 private key and mints tokens.
// The private key is a deploy secret (ROADMAP2 §0.1 п.4) -- never
// committed, loaded from an operator-supplied file/env at startup.
type Signer struct {
	priv ed25519.PrivateKey
}

func NewSigner(priv ed25519.PrivateKey) *Signer { return &Signer{priv: priv} }

// GenerateKeypair creates a fresh Ed25519 signing key -- used by `chimera-
// control-cli keys generate` and by the rotation procedure (ROADMAP2 §0.1
// п.4): generate a new pair, deploy the new public key to servers/clients
// alongside the old one during a grace window, then retire the old key.
func GenerateKeypair() (pub ed25519.PublicKey, priv ed25519.PrivateKey, err error) {
	return ed25519.GenerateKey(rand.Reader)
}

// Sign issues a token good for [TokenTTL] from now.
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

// Verifier checks tokens against one or more Ed25519 public keys.
// Supporting more than one key is what makes key rotation possible without
// a flag day: during the grace window a server is configured with both the
// outgoing and incoming public keys, so tokens signed by either verify
// (ROADMAP2 §0.1 п.4's rotation procedure).
type Verifier struct {
	pubs []ed25519.PublicKey
}

func NewVerifier(pubs ...ed25519.PublicKey) *Verifier { return &Verifier{pubs: pubs} }

// SignBytes signs an arbitrary payload (e.g. the mirror-address list, §0.1
// п.5) with the same key used for capability tokens -- a client that
// trusts the control-plane's public key can verify a fetched mirror list
// wasn't substituted by an on-path attacker, the same way it verifies
// tokens.
func (s *Signer) SignBytes(data []byte) string {
	return b64.EncodeToString(ed25519.Sign(s.priv, data))
}

// VerifyBytes checks an arbitrary payload's signature against any of the
// verifier's known public keys.
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

// Verify checks the token's signature and expiry (but not revocation --
// that's a separate, deliberately optional layer, see Revocations) and
// returns its payload.
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
