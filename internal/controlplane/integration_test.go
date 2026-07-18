package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"chimera/internal/carrier"
	"chimera/internal/keys"
	"chimera/internal/server"
)

const integrationStealBanner = "STEAL-HOST-REAL-RESPONSE"

func startFakeStealHost(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake steal host listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte(integrationStealBanner))
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestIntegrationRedeemDialRevoke(t *testing.T) {

	db := newTestDB(t)
	accounts := NewAccountStore(db)
	catalog := NewCatalogStore(db)
	revocations := NewRevocationStore(db)
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	signer := NewSigner(priv)
	verifier := NewVerifier(pub)
	api := NewAPI(accounts, catalog, revocations, signer, verifier, nil)
	cpSrv := httptest.NewServer(api.Mux())
	defer cpSrv.Close()

	number, err := accounts.CreateAccount(time.Now().Add(24*time.Hour), 5)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}

	devicePub := base64.StdEncoding.EncodeToString([]byte("integration-test-device"))
	redeemBody, _ := json.Marshal(map[string]string{"account_number": number, "device_pubkey": devicePub})
	resp, err := http.Post(cpSrv.URL+"/v1/session/redeem", "application/json", bytes.NewReader(redeemBody))
	if err != nil {
		t.Fatalf("POST redeem: %v", err)
	}
	var redeemResp struct {
		Token string `json:"token"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&redeemResp); err != nil {
		t.Fatalf("decode redeem response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("redeem: expected 200, got %d: %s", resp.StatusCode, redeemResp.Error)
	}
	token := redeemResp.Token
	if token == "" {
		t.Fatal("redeem: expected a non-empty token")
	}
	payload, err := verifier.Verify(token)
	if err != nil {
		t.Fatalf("locally re-verifying the redeemed token: %v", err)
	}
	shortIDHex := payload.ShortIDHex

	dataplaneVerifier := NewServerVerifier([]ed25519.PublicKey{pub}, cpSrv.URL)

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

	cfg := carrier.Config{
		Server:     srvAddr,
		PubB64:     serverPub,
		SNI:        "example.com",
		ShortIDHex: shortIDHex,
		Token:      token,
	}

	if err := carrier.Ping(cfg); err != nil {
		t.Fatalf("expected ping with a freshly-redeemed token to succeed: %v", err)
	}

	if err := revocations.Revoke(shortIDHex); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	dataplaneVerifier.poll()

	if err := carrier.Ping(cfg); err == nil {
		t.Fatal("expected ping to fail after the short id was revoked")
	}
}
