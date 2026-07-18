//go:build chimera_utls

package clienthello

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestUTLSBuilderIsActive(t *testing.T) {
	if _, ok := Active.(utlsBuilder); !ok {
		t.Fatalf("Active builder is %T, want utlsBuilder under chimera_utls tag", Active)
	}
}

func TestUTLSHelloCarriesAuthFields(t *testing.T) {
	tag := make([]byte, 28)
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

func TestUTLSFingerprintIsChromeClass(t *testing.T) {
	tag := make([]byte, 28)
	eph := make([]byte, 32)
	utlsRec := Active.BuildClientHello("example.com", tag, eph)
	stdRec := Build("example.com", tag, eph)

	if len(utlsRec) <= len(stdRec) {
		t.Fatalf("uTLS hello (%d bytes) not larger than stdlib hello (%d bytes); fingerprint likely not applied",
			len(utlsRec), len(stdRec))
	}

	if cs := cipherSuiteCount(t, utlsRec); cs < 8 {
		t.Errorf("uTLS hello has %d cipher suites, expected a Chrome-class count", cs)
	}
}

func cipherSuiteCount(t *testing.T, rec []byte) int {
	t.Helper()
	c := &cur{b: rec}
	c.u8()
	c.need(2)
	c.need(c.u16())

	h := &cur{b: rec[5:]}
	h.u8()
	h.u24()
	h.need(2)
	h.need(32)
	h.need(h.u8())
	suites := h.need(h.u16())
	if h.e != nil {
		t.Fatalf("failed to walk cipher suites: %v", h.e)
	}
	return len(suites) / 2
}
