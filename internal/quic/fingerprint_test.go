//go:build chimera_quic

package quic

import "testing"

func TestResolveQUICFingerprintChromeAliases(t *testing.T) {
	for _, name := range []string{"", "chrome", "chrome-h3", "chrome120", "chrome131", "edge"} {
		fp := resolveQUICFingerprint(name)
		if fp.ID != QUICChromeH3 {
			t.Fatalf("resolveQUICFingerprint(%q) = %q, want %q", name, fp.ID, QUICChromeH3)
		}
		if fp.ALPN != alpn {
			t.Fatalf("resolveQUICFingerprint(%q) ALPN = %q, want %q", name, fp.ALPN, alpn)
		}
		if fp.InitialPacketSize < 1200 {
			t.Fatalf("resolveQUICFingerprint(%q) InitialPacketSize = %d, want >= 1200", name, fp.InitialPacketSize)
		}
	}
}

func TestQUICConfigAppliesFingerprintWithoutDisablingCarrierFeatures(t *testing.T) {
	fp := resolveQUICFingerprint("chrome")
	cfg := quicConfigForFingerprint(12345, fp)
	if cfg.InitialPacketSize != fp.InitialPacketSize {
		t.Fatalf("InitialPacketSize = %d, want %d", cfg.InitialPacketSize, fp.InitialPacketSize)
	}
	if !cfg.EnableDatagrams {
		t.Fatal("fingerprint config disabled datagrams")
	}
	if !cfg.UseElasticCC {
		t.Fatal("fingerprint config disabled ElasticCC")
	}
	if cfg.ElasticCCBandwidth != 12345 {
		t.Fatalf("ElasticCCBandwidth = %d, want 12345", cfg.ElasticCCBandwidth)
	}
	if !cfg.Allow0RTT {
		t.Fatal("fingerprint config disabled 0-RTT")
	}
	if cfg.InitialClientHelloProfile != string(QUICChromeH3) {
		t.Fatalf("InitialClientHelloProfile = %q, want %q", cfg.InitialClientHelloProfile, QUICChromeH3)
	}
}

func TestQUICConfigDefaultUsesStdlibClientHelloPath(t *testing.T) {
	cfg := quicConfig(0)
	if cfg.InitialClientHelloProfile != "" {
		t.Fatalf("InitialClientHelloProfile = %q, want empty stdlib fallback", cfg.InitialClientHelloProfile)
	}
}

func TestQUICFingerprintCarriesForwardPortContract(t *testing.T) {
	fp := resolveQUICFingerprint("chrome")
	if len(fp.TransportParams) == 0 {
		t.Fatal("expected transport-parameter order contract")
	}
	if len(fp.InitialFrames) == 0 {
		t.Fatal("expected Initial frame layout contract")
	}
	if fp.InitialFrames[0] != "crypto" {
		t.Fatalf("first Initial frame = %q, want crypto", fp.InitialFrames[0])
	}
}
