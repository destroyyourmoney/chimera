package subscription

import (
	"strings"
	"testing"
)

const testURI = "chimera://example.com:443?pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=&sni=www.microsoft.com&mode=auto"

func TestParse_BasicURI(t *testing.T) {
	body := header + "\n" + testURI + "\n"
	cfgs, err := Parse(strings.NewReader(body), nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfgs) != 1 {
		t.Fatalf("want 1 config, got %d", len(cfgs))
	}
	if cfgs[0].Server != "example.com:443" {
		t.Errorf("server = %q", cfgs[0].Server)
	}
	if cfgs[0].Transport != "auto" {
		t.Errorf("transport = %q, want auto", cfgs[0].Transport)
	}
}

func TestParse_MultipleURIs(t *testing.T) {
	body := header + "\n" + testURI + "\n" + testURI + "\n"
	cfgs, err := Parse(strings.NewReader(body), nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfgs) != 2 {
		t.Fatalf("want 2 configs, got %d", len(cfgs))
	}
}

func TestParse_CommentsIgnored(t *testing.T) {
	body := header + "\n# comment\n\n" + testURI + "\n"
	cfgs, err := Parse(strings.NewReader(body), nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfgs) != 1 {
		t.Fatalf("want 1 config, got %d", len(cfgs))
	}
}

func TestParse_MissingHeader(t *testing.T) {
	body := testURI + "\n"
	if _, err := Parse(strings.NewReader(body), nil); err == nil {
		t.Fatal("expected error for missing header, got nil")
	}
}

func TestParse_HMACVerification(t *testing.T) {
	key := []byte("secret")
	uris := []string{testURI}
	sig := Sign(uris, key)

	body := header + "\n# sig: " + sig + "\n" + testURI + "\n"

	// Correct key → success.
	if _, err := Parse(strings.NewReader(body), key); err != nil {
		t.Fatalf("valid sig rejected: %v", err)
	}

	// Wrong key → failure.
	if _, err := Parse(strings.NewReader(body), []byte("wrong")); err == nil {
		t.Fatal("expected HMAC mismatch, got nil")
	}
}

func TestParse_HMACAbsentKeyIgnored(t *testing.T) {
	// No sig line + no key → no verification, accepted.
	body := header + "\n" + testURI + "\n"
	if _, err := Parse(strings.NewReader(body), nil); err != nil {
		t.Fatalf("unsigned sub rejected: %v", err)
	}
}

func TestSign_Roundtrip(t *testing.T) {
	key := []byte("roundtrip-key")
	uris := []string{testURI, testURI}
	sig1 := Sign(uris, key)
	sig2 := Sign(uris, key)
	if sig1 != sig2 {
		t.Error("Sign is not deterministic")
	}
}
