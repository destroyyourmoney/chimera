// Package keys generates and encodes the server's static X25519 keypair.
//
// The private key never leaves the server. The public key is what an operator
// embeds in a chimera:// share link; a client mixes it with a fresh ephemeral
// key to derive the shared secret that authenticates the handshake (see package
// auth). Keys are encoded with base64url-without-padding so they survive intact
// inside a URL.
package keys

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// enc is base64url without padding: URL-safe and fixed-length for 32-byte keys.
var enc = base64.RawURLEncoding

// GenerateX25519 returns a fresh X25519 keypair encoded as base64url strings.
func GenerateX25519() (priv, pub string, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate x25519 key: %w", err)
	}
	return enc.EncodeToString(k.Bytes()), enc.EncodeToString(k.PublicKey().Bytes()), nil
}

// DecodePrivate parses a base64url-encoded X25519 private key.
func DecodePrivate(b64 string) (*ecdh.PrivateKey, error) {
	raw, err := enc.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	k, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return k, nil
}

// DecodePublic parses a base64url-encoded X25519 public key.
func DecodePublic(b64 string) (*ecdh.PublicKey, error) {
	raw, err := enc.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	k, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	return k, nil
}

// EncodePublic returns the base64url encoding of a raw 32-byte public key.
func EncodePublic(raw []byte) string { return enc.EncodeToString(raw) }
