package clienthello

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestBuildParseRoundTrip(t *testing.T) {
	sessionID := make([]byte, 28)
	x25519Pub := make([]byte, 32)
	_, _ = rand.Read(sessionID)
	_, _ = rand.Read(x25519Pub)

	raw := Build("www.microsoft.com", sessionID, x25519Pub)
	sid, pub, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// SessionID is padded to 32 bytes; the first len(sessionID) bytes must match.
	if !bytes.Equal(sid[:len(sessionID)], sessionID) {
		t.Errorf("sessionID prefix mismatch\n got:  %x\n want: %x", sid[:len(sessionID)], sessionID)
	}
	if !bytes.Equal(pub, x25519Pub) {
		t.Errorf("key_share mismatch\n got:  %x\n want: %x", pub, x25519Pub)
	}
}

// FuzzParse asserts the server-side parser never panics on untrusted input.
// This is the hardening primitive that faces active probers and garbage.
func FuzzParse(f *testing.F) {
	seed := Build("example.com", bytes.Repeat([]byte{0xab}, 28), bytes.Repeat([]byte{0xcd}, 32))
	f.Add(seed)
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x00})
	f.Add([]byte{})
	f.Add([]byte{0x16})

	f.Fuzz(func(t *testing.T, raw []byte) {
		// Must not panic. Errors and partial results are fine.
		_, _, _ = Parse(raw)
	})
}
