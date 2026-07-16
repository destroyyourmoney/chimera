// Signing-key file I/O (ROADMAP2 §0.1 п.4): the private key is a deploy
// secret, never committed -- these helpers just move raw Ed25519 key bytes
// to/from disk so `cmd/chimera-control` and `chimera-control-cli keys` can
// share one format. Rotation procedure: `keys generate` a new pair, deploy
// its public key alongside the current one (data-plane servers and clients
// both accept either during the grace window, see NewVerifier accepting
// multiple keys), then retire the old private key once every server/client
// has the new public key.
package controlplane

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// SavePrivateKey writes priv as hex to path with 0600 permissions.
func SavePrivateKey(path string, priv ed25519.PrivateKey) error {
	if err := os.WriteFile(path, []byte(hex.EncodeToString(priv)), 0o600); err != nil {
		return fmt.Errorf("controlplane: write private key: %w", err)
	}
	return nil
}

// LoadPrivateKey reads a hex-encoded Ed25519 private key from path.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("controlplane: read private key: %w", err)
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("controlplane: decode private key: %w", err)
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("controlplane: private key at %s has wrong length", path)
	}
	return ed25519.PrivateKey(b), nil
}

// SavePublicKey writes pub as hex to path -- this is the file distributed
// to data-plane servers (-controlplane-pubkey) and embedded in client
// builds, never the private key.
func SavePublicKey(path string, pub ed25519.PublicKey) error {
	if err := os.WriteFile(path, []byte(hex.EncodeToString(pub)), 0o644); err != nil {
		return fmt.Errorf("controlplane: write public key: %w", err)
	}
	return nil
}

// LoadPublicKey reads a hex-encoded Ed25519 public key from path.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("controlplane: read public key: %w", err)
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("controlplane: decode public key: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("controlplane: public key at %s has wrong length", path)
	}
	return ed25519.PublicKey(b), nil
}

// ParsePublicKeyHex decodes a public key given directly as a hex string
// (e.g. from a CLI flag) rather than a file path.
func ParsePublicKeyHex(hexStr string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(strings.TrimSpace(hexStr))
	if err != nil {
		return nil, fmt.Errorf("controlplane: decode public key: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("controlplane: public key has wrong length")
	}
	return ed25519.PublicKey(b), nil
}
