package controlplane

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

func SavePrivateKey(path string, priv ed25519.PrivateKey) error {
	if err := os.WriteFile(path, []byte(hex.EncodeToString(priv)), 0o600); err != nil {
		return fmt.Errorf("controlplane: write private key: %w", err)
	}
	return nil
}

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

func SavePublicKey(path string, pub ed25519.PublicKey) error {
	if err := os.WriteFile(path, []byte(hex.EncodeToString(pub)), 0o644); err != nil {
		return fmt.Errorf("controlplane: write public key: %w", err)
	}
	return nil
}

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
