package controlplane

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	signer := NewSigner(priv)
	verifier := NewVerifier(pub)

	tok, err := signer.Sign(TokenPayload{ShortIDHex: "deadbeef", AccountIDHash: "abc", DevicePubKey: "xyz"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	payload, err := verifier.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if payload.ShortIDHex != "deadbeef" || payload.AccountIDHash != "abc" || payload.DevicePubKey != "xyz" {
		t.Fatalf("payload mismatch: %+v", payload)
	}
	if payload.ExpiresAt-payload.IssuedAt != int64(TokenTTL.Seconds()) {
		t.Fatalf("expected TTL of %v, got issued=%d expires=%d", TokenTTL, payload.IssuedAt, payload.ExpiresAt)
	}
}

func TestVerifyRejectsBitFlip(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	signer := NewSigner(priv)
	verifier := NewVerifier(pub)

	tok, err := signer.Sign(TokenPayload{ShortIDHex: "deadbeef"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	flipped := []byte(tok)
	// Flip a bit inside the payload segment (before the '.').
	for i, c := range flipped {
		if c == '.' {
			break
		}
		flipped[i] ^= 0x01
		break
	}
	if _, err := verifier.Verify(string(flipped)); err == nil {
		t.Fatal("expected an error verifying a tampered token, got nil")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	_, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	otherPub, _, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	signer := NewSigner(priv)
	verifier := NewVerifier(otherPub) // wrong public key

	tok, err := signer.Sign(TokenPayload{ShortIDHex: "deadbeef"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := verifier.Verify(tok); err != ErrTokenBadSig {
		t.Fatalf("expected ErrTokenBadSig, got %v", err)
	}
}

func TestVerifyAcceptsEitherKeyDuringRotation(t *testing.T) {
	oldPub, oldPriv, _ := GenerateKeypair()
	newPub, newPriv, _ := GenerateKeypair()

	// Grace-window verifier trusts both the outgoing and incoming key.
	verifier := NewVerifier(newPub, oldPub)

	oldTok, err := NewSigner(oldPriv).Sign(TokenPayload{ShortIDHex: "old"})
	if err != nil {
		t.Fatalf("Sign (old): %v", err)
	}
	newTok, err := NewSigner(newPriv).Sign(TokenPayload{ShortIDHex: "new"})
	if err != nil {
		t.Fatalf("Sign (new): %v", err)
	}
	if _, err := verifier.Verify(oldTok); err != nil {
		t.Fatalf("expected old-key token to verify during grace window: %v", err)
	}
	if _, err := verifier.Verify(newTok); err != nil {
		t.Fatalf("expected new-key token to verify: %v", err)
	}
}

func TestVerifyRejectsMalformedToken(t *testing.T) {
	pub, _, _ := GenerateKeypair()
	verifier := NewVerifier(pub)
	if _, err := verifier.Verify("not-a-real-token"); err != ErrTokenMalformed {
		t.Fatalf("expected ErrTokenMalformed, got %v", err)
	}
}

func TestVerifyRejectsExpiredToken(t *testing.T) {
	pub, priv, _ := GenerateKeypair()
	verifier := NewVerifier(pub)

	// Sign() always stamps IssuedAt/ExpiresAt as "now" + TTL, so an expired
	// token is built by hand here, replicating Sign's body+signature
	// encoding directly, to exercise Verify's expiry check in isolation.
	payload := TokenPayload{
		ShortIDHex: "deadbeef",
		IssuedAt:   time.Now().Add(-2 * TokenTTL).Unix(),
		ExpiresAt:  time.Now().Add(-TokenTTL).Unix(),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	sig := ed25519.Sign(priv, body)
	tok := b64.EncodeToString(body) + "." + b64.EncodeToString(sig)

	if _, err := verifier.Verify(tok); err != ErrTokenExpired {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestSignBytesVerifyBytesRoundTrip(t *testing.T) {
	pub, priv, _ := GenerateKeypair()
	signer := NewSigner(priv)
	verifier := NewVerifier(pub)

	data := []byte(`["mirror1.example.com","mirror2.example.com"]`)
	sig := signer.SignBytes(data)
	if !verifier.VerifyBytes(data, sig) {
		t.Fatal("expected VerifyBytes to accept a signature it just produced")
	}
	if verifier.VerifyBytes([]byte("tampered"), sig) {
		t.Fatal("expected VerifyBytes to reject a signature over different data")
	}
}
