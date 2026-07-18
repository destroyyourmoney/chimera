package client

import (
	"fmt"

	"chimera/internal/carrier"
)

type Config struct {
	Server     string
	PubB64     string
	SNI        string
	ShortIDHex string
	Transport  string
	Fp         string

	Token string
}

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
