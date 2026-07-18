package main

import (
	"encoding/json"
	"testing"

	"chimera/internal/link"
)

func testLinkURI() string {
	return link.Build(link.Profile{
		Host: "203.0.113.7", Port: "443", Pbk: "HD-Fk6tO4ZgiocibdM4GqOydco80pKlcEz49ISHnWUc",
		Sid: "0a1b2c3d", Sni: "www.microsoft.com", Fp: "chrome", Mode: "auto", Tag: "test",
	})
}

func TestChimeraParseLink_Valid(t *testing.T) {
	out := ChimeraParseLink(cString(testLinkURI()))
	defer ChimeraFreeString(out)

	var env linkEnvelope
	if err := json.Unmarshal([]byte(cGoString(out)), &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if env.Error != "" {
		t.Fatalf("unexpected error: %s", env.Error)
	}
	if env.Result == "" {
		t.Fatal("expected non-empty result JSON for a valid link")
	}
}

func TestChimeraParseLink_Malformed(t *testing.T) {
	out := ChimeraParseLink(cString("https://not-a-chimera-link/"))
	defer ChimeraFreeString(out)

	var env linkEnvelope
	if err := json.Unmarshal([]byte(cGoString(out)), &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if env.Error == "" {
		t.Fatal("expected an error for a malformed link")
	}
	if env.Result != "" {
		t.Errorf("expected empty result alongside an error, got %q", env.Result)
	}
}

func TestChimeraTunnelLifecycle(t *testing.T) {
	envOut := ChimeraNewTunnelFromLink(cString(testLinkURI()))
	defer ChimeraFreeString(envOut)

	var env handleEnvelope
	if err := json.Unmarshal([]byte(cGoString(envOut)), &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if env.Error != "" {
		t.Fatalf("NewTunnelFromLink error: %s", env.Error)
	}
	if env.Handle == 0 {
		t.Fatal("expected non-zero handle")
	}
	handle := env.Handle

	stateOut := ChimeraStateJSON(cLonglong(handle))
	var snap map[string]any
	if err := json.Unmarshal([]byte(cGoString(stateOut)), &snap); err != nil {
		t.Fatalf("unmarshal state: %v", err)
	}
	ChimeraFreeString(stateOut)
	if snap["state"] != "disconnected" {
		t.Errorf("state before Connect = %v, want disconnected", snap["state"])
	}

	connErr := ChimeraConnect(cLonglong(handle))
	defer ChimeraFreeString(connErr)
	if cGoString(connErr) == "" {
		t.Fatal("expected Connect to an unreachable test-net address to fail")
	}

	ChimeraFreeHandle(cLonglong(handle))
	ChimeraFreeHandle(cLonglong(handle))
}

func TestChimeraUnknownHandle_DoesNotPanic(t *testing.T) {
	const bogus = 999999999

	out := ChimeraStateJSON(cLonglong(bogus))
	defer ChimeraFreeString(out)
	if cGoString(out) == "" {
		t.Error("expected a default state JSON for an unknown handle")
	}

	ChimeraStop(cLonglong(bogus))

	errOut := ChimeraConnect(cLonglong(bogus))
	defer ChimeraFreeString(errOut)
	if cGoString(errOut) == "" {
		t.Error("expected an error string for an unknown handle")
	}
}
