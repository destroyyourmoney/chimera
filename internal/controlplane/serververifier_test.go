package controlplane

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestServerVerifierAcceptsValidToken(t *testing.T) {
	pub, priv, _ := GenerateKeypair()
	signer := NewSigner(priv)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"revocations": []RevocationEntry{}, "etag": 0})
	}))
	defer srv.Close()

	v := NewServerVerifier([]ed25519.PublicKey{pub}, srv.URL)
	tok, err := signer.Sign(TokenPayload{ShortIDHex: "deadbeef"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !v.VerifyToken(tok, "deadbeef") {
		t.Fatal("expected valid token to verify")
	}
	if v.VerifyToken(tok, "wrongsid") {
		t.Fatal("expected token to be rejected for a mismatched short id")
	}
}

func TestServerVerifierRejectsRevokedShortID(t *testing.T) {
	pub, priv, _ := GenerateKeypair()
	signer := NewSigner(priv)

	revoked := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if revoked {
			json.NewEncoder(w).Encode(map[string]any{
				"revocations": []RevocationEntry{{ShortIDHex: "deadbeef", RevokedAt: time.Now().Unix()}},
				"etag":        1,
			})
		} else {
			json.NewEncoder(w).Encode(map[string]any{"revocations": []RevocationEntry{}, "etag": 0})
		}
	}))
	defer srv.Close()

	v := NewServerVerifier([]ed25519.PublicKey{pub}, srv.URL)
	tok, err := signer.Sign(TokenPayload{ShortIDHex: "deadbeef"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	v.poll() // synchronous, deterministic for the test instead of racing Watch's ticker
	if v.VerifyToken(tok, "deadbeef") {
		t.Fatal("expected revoked short id to be rejected")
	}
}
