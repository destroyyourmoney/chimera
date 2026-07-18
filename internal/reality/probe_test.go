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

func TestParseServerHello_Crafted(t *testing.T) {
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i)
	}
	keyShareKey := make([]byte, 32)
	for i := range keyShareKey {
		keyShareKey[i] = 0xAA
	}

	supportedVersions := []byte{0x03, 0x04}
	keyShareData := append([]byte{0x00, 0x1d, 0x00, 0x20}, keyShareKey...)

	var ext []byte
	ext = append(ext, 0x00, 0x2b, 0x00, byte(len(supportedVersions)))
	ext = append(ext, supportedVersions...)
	ext = append(ext, 0x00, 0x33, 0x00, byte(len(keyShareData)))
	ext = append(ext, keyShareData...)

	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, random...)
	body = append(body, 0x00)
	body = append(body, 0x13, 0x01)
	body = append(body, 0x00)
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

func TestParseServerHello_HelloRetryRequest(t *testing.T) {

	keyShareData := []byte{0x00, 0x1d}
	supportedVersions := []byte{0x03, 0x04}

	var ext []byte
	ext = append(ext, 0x00, 0x2b, 0x00, byte(len(supportedVersions)))
	ext = append(ext, supportedVersions...)
	ext = append(ext, 0x00, 0x33, 0x00, byte(len(keyShareData)))
	ext = append(ext, keyShareData...)

	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, helloRetryRequestRandom[:]...)
	body = append(body, 0x00)
	body = append(body, 0x13, 0x01)
	body = append(body, 0x00)
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

func TestParseServerHello_NotServerHello(t *testing.T) {
	msg := []byte{0x0b, 0x00, 0x00, 0x01, 0x00}
	if _, err := ParseServerHello(msg); err == nil {
		t.Fatal("expected error for non-ServerHello message")
	}
}

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

				_ = c.(*tls.Conn).Handshake()
			}(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

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
