package nethelper

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// tokenDir/tokenFile: the shared secret lives under the machine-wide
// %ProgramData% directory, NOT a per-user directory like %LocalAppData%.
// chimera-helper runs as LocalSystem once installed, which has its own
// profile entirely separate from the interactively logged-in user's -- a
// per-user path written by the (user-token, UAC-elevated) installer would
// resolve to a different directory than the same path resolved by the
// SYSTEM-account service trying to read it back. %ProgramData% is the one
// location both agree on: fixed regardless of account, and by default
// readable (though not writable) by ordinary unprivileged processes, which
// is exactly the access the unprivileged tray app needs.
//
// This does mean any process running as any locally logged-in user can read
// the token -- an acceptable tradeoff for the single-user desktop this app
// targets (equivalent to the %LocalAppData% threat model), but worth
// hardening with an explicit restrictive ACL (e.g. via
// golang.org/x/sys/windows or icacls at install time) if this ever needs to
// hold up on a shared/multi-user machine.
const tokenDir = "chimera"
const tokenFile = "helper.token"

// TokenPath returns the path chimera-helper writes its shared secret to and
// the tray app reads it from.
func TokenPath() (string, error) {
	dir := os.Getenv("ProgramData")
	if dir == "" {
		return "", fmt.Errorf("nethelper: %%ProgramData%% is not set")
	}
	return filepath.Join(dir, tokenDir, tokenFile), nil
}

// GenerateToken returns a fresh random 32-byte hex-encoded secret.
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("nethelper: generate token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// WriteToken persists token to TokenPath, creating its parent directory if
// needed. Called once by `chimera-helper install` (elevated) and again
// whenever the service starts with no existing token on disk.
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

// ReadToken loads the shared secret the tray app authenticates requests
// with. Returns an error if chimera-helper has never been installed/started.
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
