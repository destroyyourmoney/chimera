//go:build chimera_utls

package reality

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

// TestParseServerHello_Crafted feeds a hand-built ServerHello handshake
// message through the parser and checks every field is extracted correctly,
// independent of any live network probe.
func TestParseServerHello_Crafted(t *testing.T) {
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i)
	}
	keyShareKey := make([]byte, 32)
	for i := range keyShareKey {
		keyShareKey[i] = 0xAA
	}

	// extensions, in wire order: supported_versions (0x002b), key_share (0x0033)
	supportedVersions := []byte{0x03, 0x04} // TLS 1.3
	keyShareData := append([]byte{0x00, 0x1d /* x25519 */, 0x00, 0x20 /* len */}, keyShareKey...)

	var ext []byte
	ext = append(ext, 0x00, 0x2b, 0x00, byte(len(supportedVersions)))
	ext = append(ext, supportedVersions...)
	ext = append(ext, 0x00, 0x33, 0x00, byte(len(keyShareData)))
	ext = append(ext, keyShareData...)

	var body []byte
	body = append(body, 0x03, 0x03) // legacy_version
	body = append(body, random...)
	body = append(body, 0x00)                   // legacy_session_id_echo len 0
	body = append(body, 0x13, 0x01)             // cipher_suite TLS_AES_128_GCM_SHA256
	body = append(body, 0x00)                   // legacy_compression_method
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	msg := append([]byte{handshakeTypeServerHello, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)

	tmpl, err := ParseServerHello(msg)
	if err != nil {
		t.Fatalf("ParseServerHello: %v", err)
	}
	if tmpl.LegacyVersion != 0x0303 {
		t.Errorf("LegacyVersion = %#x, want 0x0303", tmpl.LegacyVersion)
	}
	if tmpl.CipherSuite != 0x1301 {
		t.Errorf("CipherSuite = %#x, want 0x1301", tmpl.CipherSuite)
	}
	if tmpl.CompressionMethod != 0 {
		t.Errorf("CompressionMethod = %d, want 0", tmpl.CompressionMethod)
	}
	if len(tmpl.Extensions) != 2 {
		t.Fatalf("Extensions = %d entries, want 2", len(tmpl.Extensions))
	}
	if tmpl.Extensions[0].Type != 0x002b || tmpl.Extensions[1].Type != 0x0033 {
		t.Errorf("extension order/types = %#x, %#x; want 0x2b, 0x33",
			tmpl.Extensions[0].Type, tmpl.Extensions[1].Type)
	}
	if tmpl.KeyShareGroup != 0x001d {
		t.Errorf("KeyShareGroup = %#x, want 0x001d (x25519)", tmpl.KeyShareGroup)
	}
}

// TestParseServerHello_HelloRetryRequest confirms a HelloRetryRequest --
// wire-identical to a ServerHello (handshake_type=2) except for its magic
// Random value and a bare-group key_share -- is rejected with
// errHelloRetryRequest rather than silently parsed into a template whose
// KeyShareGroup looks valid but was never paired with an actual key
// exchange. See probe.go's errHelloRetryRequest doc comment.
func TestParseServerHello_HelloRetryRequest(t *testing.T) {
	// HRR key_share extension content is just a 2-byte NamedGroup, no
	// length-prefixed public key (RFC 8446 §4.1.4).
	keyShareData := []byte{0x00, 0x1d} // x25519, selected_group only
	supportedVersions := []byte{0x03, 0x04}

	var ext []byte
	ext = append(ext, 0x00, 0x2b, 0x00, byte(len(supportedVersions)))
	ext = append(ext, supportedVersions...)
	ext = append(ext, 0x00, 0x33, 0x00, byte(len(keyShareData)))
	ext = append(ext, keyShareData...)

	var body []byte
	body = append(body, 0x03, 0x03) // legacy_version
	body = append(body, helloRetryRequestRandom[:]...)
	body = append(body, 0x00)       // legacy_session_id_echo len 0
	body = append(body, 0x13, 0x01) // cipher_suite TLS_AES_128_GCM_SHA256
	body = append(body, 0x00)       // legacy_compression_method
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	msg := append([]byte{handshakeTypeServerHello, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)

	tmpl, err := ParseServerHello(msg)
	if !errors.Is(err, errHelloRetryRequest) {
		t.Fatalf("ParseServerHello error = %v, want errHelloRetryRequest", err)
	}
	if tmpl != nil {
		t.Errorf("ParseServerHello returned non-nil template %+v alongside errHelloRetryRequest", tmpl)
	}
}

// TestParseServerHello_NotServerHello confirms a non-ServerHello handshake
// message (e.g. Certificate) is rejected rather than silently misparsed.
func TestParseServerHello_NotServerHello(t *testing.T) {
	msg := []byte{0x0b, 0x00, 0x00, 0x01, 0x00} // handshake type 11 = Certificate
	if _, err := ParseServerHello(msg); err == nil {
		t.Fatal("expected error for non-ServerHello message")
	}
}

// localTLS13Server starts a loopback crypto/tls TLS 1.3 server with a
// self-signed cert for host, returning its address. It never sends anything
// past the handshake, mirroring what a real probe needs.
func localTLS13Server(t *testing.T, host string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// The probe only writes a ClientHello and reads the
				// ServerHello, then closes -- Handshake() will error once
				// that happens, which is expected and ignored.
				_ = c.(*tls.Conn).Handshake()
			}(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

// TestProbeServerHello_LiveLoopback probes a real local TLS 1.3 server and
// checks the parsed template has the fields a genuine ServerHello must have.
func TestProbeServerHello_LiveLoopback(t *testing.T) {
	addr := localTLS13Server(t, "example.test")

	dial := func() (net.Conn, error) { return net.Dial("tcp", addr) }
	tmpl, err := ProbeServerHello(dial, "example.test")
	if err != nil {
		t.Fatalf("ProbeServerHello: %v", err)
	}
	if tmpl.LegacyVersion != 0x0303 {
		t.Errorf("LegacyVersion = %#x, want 0x0303 (TLS1.3 SH always sets legacy_version=1.2)", tmpl.LegacyVersion)
	}
	if tmpl.CompressionMethod != 0 {
		t.Errorf("CompressionMethod = %d, want 0", tmpl.CompressionMethod)
	}
	if tmpl.KeyShareGroup == 0 {
		t.Error("KeyShareGroup = 0, want a negotiated group (TLS1.3 SH must include key_share)")
	}
	foundSupportedVersions := false
	for _, e := range tmpl.Extensions {
		if e.Type == 0x002b {
			foundSupportedVersions = true
			if len(e.Data) != 2 || e.Data[0] != 0x03 || e.Data[1] != 0x04 {
				t.Errorf("supported_versions data = %x, want 0304", e.Data)
			}
		}
	}
	if !foundSupportedVersions {
		t.Error("ServerHello missing supported_versions extension")
	}
	if tmpl.CapturedAt.IsZero() {
		t.Error("CapturedAt not set")
	}
}

// TestServerHelloTemplateFor_Caches confirms repeated calls for the same SNI
// hit the cache instead of re-probing.
func TestServerHelloTemplateFor_Caches(t *testing.T) {
	addr := localTLS13Server(t, "cache.test")

	probeCache.mu.Lock()
	delete(probeCache.m, "cache.test")
	probeCache.mu.Unlock()

	dials := 0
	dial := func() (net.Conn, error) {
		dials++
		return net.Dial("tcp", addr)
	}

	if _, err := ServerHelloTemplateFor(dial, "cache.test"); err != nil {
		t.Fatalf("first ServerHelloTemplateFor: %v", err)
	}
	if _, err := ServerHelloTemplateFor(dial, "cache.test"); err != nil {
		t.Fatalf("second ServerHelloTemplateFor: %v", err)
	}
	if dials != 1 {
		t.Errorf("dial called %d times, want 1 (second call should hit cache)", dials)
	}
}

// TestSetFingerprint_InvalidatesTemplateCache confirms that pinning a new
// impersonated browser (as the Этап 5 fingerprint pipeline does at runtime)
// drops cached ServerHelloTemplates, since they were captured against the
// previous ClientHello (docs/reality-serverhello-engine.md Phase 4).
func TestSetFingerprint_InvalidatesTemplateCache(t *testing.T) {
	origFingerprint := Fingerprint
	t.Cleanup(func() { Fingerprint = origFingerprint })

	addr := localTLS13Server(t, "drift.test")
	dials := 0
	dial := func() (net.Conn, error) {
		dials++
		return net.Dial("tcp", addr)
	}

	if _, err := ServerHelloTemplateFor(dial, "drift.test"); err != nil {
		t.Fatalf("first ServerHelloTemplateFor: %v", err)
	}
	if dials != 1 {
		t.Fatalf("dials = %d after first probe, want 1", dials)
	}

	if err := SetFingerprint("chrome131"); err != nil {
		t.Fatalf("SetFingerprint: %v", err)
	}

	if _, err := ServerHelloTemplateFor(dial, "drift.test"); err != nil {
		t.Fatalf("ServerHelloTemplateFor after SetFingerprint: %v", err)
	}
	if dials != 2 {
		t.Errorf("dials = %d after SetFingerprint + probe, want 2 (cache should have been invalidated)", dials)
	}
}
