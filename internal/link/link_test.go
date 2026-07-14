package link

import "testing"

func TestBuildParseRoundTrip(t *testing.T) {
	cases := []Profile{
		{
			AuthID: "550e8400-e29b-41d4-a716-446655440000",
			Host:   "203.0.113.7", Port: "443", Pbk: "HD-Fk6tO4ZgiocibdM4GqOydco80pKlcEz49ISHnWUc",
			Sid: "0a1b2c3d", Sni: "www.microsoft.com", Fp: "chrome", Mode: "auto", Tag: "My Server",
		},
		{ // minimal: no auth id, no short id, no tag
			Host: "example.com", Port: "8443", Pbk: "abc", Sni: "cdn.example", Fp: "chrome", Mode: "tcp",
		},
		{ // IPv6 host
			Host: "2001:db8::1", Port: "443", Pbk: "k", Sni: "h", Fp: "chrome", Mode: "quic", Tag: "v6",
		},
	}
	for _, want := range cases {
		uri := Build(want)
		got, err := Parse(uri)
		if err != nil {
			t.Fatalf("Parse(%q): %v", uri, err)
		}
		if got != want {
			t.Errorf("round trip mismatch\n uri:  %s\n got:  %+v\n want: %+v", uri, got, want)
		}
	}
}

func TestParseRejectsWrongScheme(t *testing.T) {
	if _, err := Parse("https://example.com/"); err == nil {
		t.Fatal("expected error for non-chimera scheme")
	}
}
