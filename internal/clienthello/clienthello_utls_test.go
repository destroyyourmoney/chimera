//go:build chimera_utls

package clienthello

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestUTLSBuilderIsActive confirms the build tag swapped in the uTLS builder.
func TestUTLSBuilderIsActive(t *testing.T) {
	if _, ok := Active.(utlsBuilder); !ok {
		t.Fatalf("Active builder is %T, want utlsBuilder under chimera_utls tag", Active)
	}
}

// TestUTLSHelloCarriesAuthFields builds a Chrome-fingerprinted hello and verifies
// the server-side parser recovers the injected auth tag and ephemeral key.
func TestUTLSHelloCarriesAuthFields(t *testing.T) {
	tag := make([]byte, 28) // auth.TagLen-sized
	eph := make([]byte, 32)
	_, _ = rand.Read(tag)
	_, _ = rand.Read(eph)

	rec := Active.BuildClientHello("www.microsoft.com", tag, eph)

	sid, xpub, err := Parse(rec)
	if err != nil {
		t.Fatalf("server parser rejected uTLS hello: %v", err)
	}
	if !bytes.Equal(sid[:len(tag)], tag) {
		t.Errorf("session id prefix = %x, want auth tag %x", sid[:len(tag)], tag)
	}
	if !bytes.Equal(xpub, eph) {
		t.Errorf("x25519 key_share = %x, want injected eph %x", xpub, eph)
	}
}

// TestUTLSFingerprintIsChromeClass asserts the hello is materially richer than
// the 3-cipher stdlib hello — a proxy for real JA3/JA4 parity.
func TestUTLSFingerprintIsChromeClass(t *testing.T) {
	tag := make([]byte, 28)
	eph := make([]byte, 32)
	utlsRec := Active.BuildClientHello("example.com", tag, eph)
	stdRec := Build("example.com", tag, eph)

	if len(utlsRec) <= len(stdRec) {
		t.Fatalf("uTLS hello (%d bytes) not larger than stdlib hello (%d bytes); fingerprint likely not applied",
			len(utlsRec), len(stdRec))
	}
	// Chrome offers GREASE + many cipher suites; the stdlib builder offers 3.
	if cs := cipherSuiteCount(t, utlsRec); cs < 8 {
		t.Errorf("uTLS hello has %d cipher suites, expected a Chrome-class count", cs)
	}
}

// cipherSuiteCount re-parses the record enough to count offered cipher suites.
func cipherSuiteCount(t *testing.T, rec []byte) int {
	t.Helper()
	c := &cur{b: rec}
	c.u8()          // record type
	c.need(2)       // record version
	c.need(c.u16()) // record body -> but we need to descend; re-walk instead
	// Simpler: walk the handshake directly.
	h := &cur{b: rec[5:]}
	h.u8()         // handshake type
	h.u24()        // handshake length
	h.need(2)      // legacy_version
	h.need(32)     // random
	h.need(h.u8()) // session id
	suites := h.need(h.u16())
	if h.e != nil {
		t.Fatalf("failed to walk cipher suites: %v", h.e)
	}
	return len(suites) / 2
}
