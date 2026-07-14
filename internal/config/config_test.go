package config_test

import (
	"os"
	"testing"

	"chimera/internal/config"
)

func writeTmp(t *testing.T, body string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "chimera-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(body); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

func TestLoadServer_Full(t *testing.T) {
	path := writeTmp(t, `
listen: ":8443"
steal_host: "www.example.com:443"
priv: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
short_ids:
  - "deadbeef"
  - "cafebabe"
transport: "quic"
verbose: true
rate_limit:
  rate: 3.0
  burst: 7.0
`)
	cfg, err := config.LoadServer(path)
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if cfg.Listen != ":8443" {
		t.Errorf("Listen: got %q want %q", cfg.Listen, ":8443")
	}
	if cfg.Transport != "quic" {
		t.Errorf("Transport: got %q want %q", cfg.Transport, "quic")
	}
	if len(cfg.ShortIDs) != 2 {
		t.Errorf("ShortIDs: got %d want 2", len(cfg.ShortIDs))
	}
	if cfg.RateLimit.Rate != 3.0 {
		t.Errorf("RateLimit.Rate: got %f want 3.0", cfg.RateLimit.Rate)
	}
}

func TestLoadServer_Minimal(t *testing.T) {
	path := writeTmp(t, `
priv: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
steal_host: "www.example.com:443"
`)
	cfg, err := config.LoadServer(path)
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if cfg.Listen != "" {
		t.Errorf("expected empty Listen, got %q", cfg.Listen)
	}
}

func TestLoadServer_UnknownField(t *testing.T) {
	path := writeTmp(t, `
priv: "key"
bogus_field: true
`)
	_, err := config.LoadServer(path)
	if err == nil {
		t.Fatal("expected error on unknown field, got nil")
	}
}

func TestLoadServer_MissingFile(t *testing.T) {
	_, err := config.LoadServer("/nonexistent/path.yaml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}
