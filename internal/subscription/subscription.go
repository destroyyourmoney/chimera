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

func Load(path string, hmacKey []byte) ([]carrier.Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("subscription: open %q: %w", path, err)
	}
	defer f.Close()
	return parse(f, hmacKey)
}

func Parse(r io.Reader, hmacKey []byte) ([]carrier.Config, error) {
	return parse(r, hmacKey)
}

func parse(r io.Reader, hmacKey []byte) ([]carrier.Config, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("subscription: read: %w", err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))

	if !scanner.Scan() {
		return nil, fmt.Errorf("subscription: empty file")
	}
	if scanner.Text() != header {
		return nil, fmt.Errorf("subscription: missing header %q", header)
	}

	var bodyLines, sigHex []byte
	var uris []string

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

func Sign(uris []string, key []byte) string {
	var body []byte
	for _, u := range uris {
		body = append(body, []byte(u+"\n")...)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
