// Package subscription parses CHIMERA server subscription files: newline-delimited
// lists of chimera:// URIs, optionally authenticated with an HMAC-SHA256 signature
// so the operator can distribute and auto-rotate endpoint lists securely.
//
// File format:
//
//	#!chimera-subscription-v1
//	# sig: <hex(HMAC-SHA256(body, key))>   ← optional; omit for unsigned subs
//	chimera://...
//	chimera://...
//
// The "#!chimera-subscription-v1" header is required. The "# sig:" line is
// optional; if absent the subscription is accepted unsigned (for local files).
// If a key is passed to Load and the sig line is present, the signature is
// verified before any URIs are parsed.
package subscription

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"chimera/internal/carrier"
	"chimera/internal/link"
)

const header = "#!chimera-subscription-v1"

// Load reads a subscription file from path, optionally verifies its HMAC-SHA256
// signature (pass nil key to skip verification), and returns the parsed carrier
// Configs. The returned configs have Transport set to "auto" if not explicitly
// specified in the URI.
func Load(path string, hmacKey []byte) ([]carrier.Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("subscription: open %q: %w", path, err)
	}
	defer f.Close()
	return parse(f, hmacKey)
}

// Parse reads a subscription from an io.Reader. Exported for testing.
func Parse(r io.Reader, hmacKey []byte) ([]carrier.Config, error) {
	return parse(r, hmacKey)
}

func parse(r io.Reader, hmacKey []byte) ([]carrier.Config, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("subscription: read: %w", err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))

	// First line must be the magic header.
	if !scanner.Scan() {
		return nil, fmt.Errorf("subscription: empty file")
	}
	if scanner.Text() != header {
		return nil, fmt.Errorf("subscription: missing header %q", header)
	}

	// Collect body lines (everything after the header) for signature verification.
	var bodyLines, sigHex []byte
	var uris []string

	// Second pass: find optional sig comment and URI lines.
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "# sig:") {
			sigHex = []byte(strings.TrimSpace(strings.TrimPrefix(trimmed, "# sig:")))
			continue
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		bodyLines = append(bodyLines, []byte(line+"\n")...)
		uris = append(uris, trimmed)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("subscription: scan: %w", err)
	}

	// Verify HMAC-SHA256 if both a key and a sig line are present.
	if hmacKey != nil && len(sigHex) > 0 {
		want, err := hex.DecodeString(string(sigHex))
		if err != nil {
			return nil, fmt.Errorf("subscription: invalid sig hex: %w", err)
		}
		mac := hmac.New(sha256.New, hmacKey)
		mac.Write(bodyLines)
		got := mac.Sum(nil)
		if !hmac.Equal(got, want) {
			return nil, fmt.Errorf("subscription: HMAC-SHA256 signature mismatch — file may have been tampered with")
		}
	}

	if len(uris) == 0 {
		return nil, fmt.Errorf("subscription: no chimera:// URIs found")
	}

	cfgs := make([]carrier.Config, 0, len(uris))
	for _, uri := range uris {
		p, err := link.Parse(uri)
		if err != nil {
			return nil, fmt.Errorf("subscription: invalid URI %q: %w", uri, err)
		}
		cfg := carrier.Config{
			Server:     p.Host + ":" + p.Port,
			PubB64:     p.Pbk,
			SNI:        p.Sni,
			ShortIDHex: p.Sid,
			Transport:  p.Mode,
			Fp:         p.Fp,
			Token:      p.Token,
		}
		if cfg.Transport == "" {
			cfg.Transport = "auto"
		}
		if cfg.SNI == "" {
			cfg.SNI = "www.microsoft.com"
		}
		cfgs = append(cfgs, cfg)
	}
	return cfgs, nil
}

// Sign computes the HMAC-SHA256 signature of the body lines (one chimera:// URI
// per line) and returns the hex-encoded result. Embed this in the subscription
// file as "# sig: <result>" immediately after the header line.
func Sign(uris []string, key []byte) string {
	var body []byte
	for _, u := range uris {
		body = append(body, []byte(u+"\n")...)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
