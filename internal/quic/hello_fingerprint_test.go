//go:build chimera_quic

package quic

import (
	"testing"
	"time"

	"chimera/internal/carrier"
)

func TestInitialClientHelloHarnessComparesCurrentAndChromeReference(t *testing.T) {
	addr, pub := startServer(t)
	const sni = "example.com"
	got := make(chan []byte, 1)
	restore := SetInitialCryptoDataTracer(func(p []byte) {
		select {
		case got <- p:
		default:
		}
	})
	defer restore()

	cfg := carrier.Config{Server: addr, PubB64: pub, SNI: sni, Transport: "quic", Fp: "chrome-h3"}
	if err := Ping(cfg); err != nil {
		t.Fatalf("ping over quic carrier: %v", err)
	}

	var currentRaw []byte
	select {
	case currentRaw = <-got:
	case <-time.After(3 * time.Second):
		t.Fatal("Initial CRYPTO tracer was not called")
	}
	current, err := SummarizeClientHello(currentRaw)
	if err != nil {
		t.Fatalf("summarize current ClientHello: %v", err)
	}
	referenceRaw, err := BuildChromeH3ClientHelloReference(sni)
	if err != nil {
		t.Fatalf("build Chrome-H3 reference ClientHello: %v", err)
	}
	reference, err := SummarizeClientHello(referenceRaw)
	if err != nil {
		t.Fatalf("summarize Chrome-H3 reference ClientHello: %v", err)
	}

	if current.SNI != sni {
		t.Fatalf("current SNI = %q, want %q", current.SNI, sni)
	}
	if reference.SNI != sni {
		t.Fatalf("reference SNI = %q, want %q", reference.SNI, sni)
	}
	if len(current.ALPN) != 1 || current.ALPN[0] != alpn {
		t.Fatalf("current ALPN = %v, want [%s]", current.ALPN, alpn)
	}
	if len(reference.ALPN) != 1 || reference.ALPN[0] != alpn {
		t.Fatalf("reference ALPN = %v, want [%s]", reference.ALPN, alpn)
	}
	if !current.HasQUICParams {
		t.Fatal("current ClientHello is missing quic_transport_parameters")
	}
	if !reference.HasQUICParams {
		t.Fatal("reference ClientHello is missing quic_transport_parameters")
	}

	diffs := DiffClientHelloSummaries(current, reference)
	if len(diffs) != 0 {
		t.Fatalf("current ClientHello differs from Chrome-H3 reference: %+v", diffs)
	}
}

func TestSummarizeClientHelloRejectsInvalidInput(t *testing.T) {
	if _, err := SummarizeClientHello([]byte{0xff, 0x00}); err == nil {
		t.Fatal("expected invalid ClientHello to fail")
	}
}
