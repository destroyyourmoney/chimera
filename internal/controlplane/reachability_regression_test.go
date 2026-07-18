package controlplane

import (
	"context"
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	"chimera/internal/carrier"
	"chimera/internal/keys"
	"chimera/internal/server"
)

func TestReachabilityPreflight_MissingTokenOrShortID(t *testing.T) {
	db := newTestDB(t)
	accounts := NewAccountStore(db)
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	signer := NewSigner(priv)

	number, err := accounts.CreateAccount(time.Now().Add(24*time.Hour), 5)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}

	redeemed, err := accounts.Redeem(number, "reachability-regression-device")
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	token, err := signer.Sign(TokenPayload{
		ShortIDHex:    redeemed.ShortIDHex,
		AccountIDHash: redeemed.AccountIDHash,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	dataplaneVerifier := NewServerVerifier([]ed25519.PublicKey{pub}, "")

	stealAddr := startFakeStealHost(t)
	serverPriv, serverPub, err := keys.GenerateX25519()
	if err != nil {
		t.Fatalf("GenerateX25519: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = server.Serve(ctx, ln, server.Config{
			StealHost:     stealAddr,
			PrivB64:       serverPriv,
			TokenVerifier: dataplaneVerifier,
		})
	}()
	srvAddr := ln.Addr().String()

	base := carrier.Config{Server: srvAddr, PubB64: serverPub, SNI: "example.com"}

	t.Run("no token, no short ID -- the original bug (catalog link with no tok= at all)", func(t *testing.T) {
		cfg := base
		if err := carrier.Ping(cfg); err == nil {
			t.Fatal("expected the preflight ping to fail with no token presented at all")
		} else {
			t.Logf("got (expected) error: %v", err)
		}
	})

	t.Run("token present but short ID missing -- the first fix alone is not enough", func(t *testing.T) {
		cfg := base
		cfg.Token = token

		if err := carrier.Ping(cfg); err == nil {
			t.Fatal("expected the preflight ping to fail when the embedded short ID doesn't match the token's")
		} else {
			t.Logf("got (expected) error: %v", err)
		}
	})

	t.Run("token and matching short ID -- fully fixed", func(t *testing.T) {
		cfg := base
		cfg.Token = token
		cfg.ShortIDHex = redeemed.ShortIDHex
		if err := carrier.Ping(cfg); err != nil {
			t.Fatalf("expected the preflight ping to succeed once both token and short ID are stitched on: %v", err)
		}
	})
}
