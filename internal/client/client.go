// Package client is the CHIMERA client PoC: it performs the stealth handshake
// against a server and issues a single PING over the carrier to confirm that
// authentication and the tunnel path work end-to-end. Real traffic goes through
// the SOCKS5 inbound (package socks); this command exists for diagnostics.
package client

import (
	"fmt"

	"chimera/internal/carrier"
)

// Config mirrors carrier.Config for the diagnostic client.
type Config struct {
	Server     string
	PubB64     string
	SNI        string
	ShortIDHex string
	Transport  string
	Fp         string
	// Token is the control-plane capability token (ROADMAP2 §1), needed
	// only against a server running -auth-mode controlplane.
	Token string
}

// Run performs one handshake + PING and reports the result.
func Run(cfg Config) error {
	c := carrier.Config{
		Server:     cfg.Server,
		PubB64:     cfg.PubB64,
		SNI:        cfg.SNI,
		ShortIDHex: cfg.ShortIDHex,
		Transport:  cfg.Transport,
		Fp:         cfg.Fp,
		Token:      cfg.Token,
	}
	if err := carrier.Ping(c); err != nil {
		return fmt.Errorf("carrier ping failed: %w", err)
	}
	fmt.Printf("OK: handshake + tunnel PING succeeded against %s (sni=%s)\n", cfg.Server, cfg.SNI)
	return nil
}
