package nethelper

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

const tokenDir = "chimera"
const tokenFile = "helper.token"

func TokenPath() (string, error) {
	dir := os.Getenv("ProgramData")
	if dir == "" {
		return "", fmt.Errorf("nethelper: %%ProgramData%% is not set")
	}
	return filepath.Join(dir, tokenDir, tokenFile), nil
}

func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("nethelper: generate token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func WriteToken(token string) error {
	path, err := TokenPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("nethelper: create token dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		return fmt.Errorf("nethelper: write token: %w", err)
	}
	return nil
}

func ReadToken() (string, error) {
	path, err := TokenPath()
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("nethelper: read token: %w", err)
	}
	return string(b), nil
}
