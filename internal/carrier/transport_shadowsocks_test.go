//go:build chimera_ss

package carrier_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"chimera/internal/carrier"
	"chimera/internal/keys"
)

func startSSServer(t *testing.T, cfg carrier.SSServerConfig) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Bind an ephemeral port ourselves so the test doesn't race SSServe's
	// own net.Listen -- SSServe takes cfg.Listen as a dial address string,
	// so resolve a free port up front.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	cfg.Listen = addr

	ready := make(chan struct{})
	go func() {
		// SSServe itself does the real net.Listen; give it a moment before
		// the caller dials.
		close(ready)
		_ = carrier.SSServe(ctx, cfg)
	}()
	<-ready
	time.Sleep(50 * time.Millisecond)
	return addr
}

func TestSSAuthorizedPingRoundTrip(t *testing.T) {
	priv, pub, err := keys.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	addr := startSSServer(t, carrier.SSServerConfig{PrivB64: priv, ShortIDs: []string{"0a1b2c3d"}})

	cfg := carrier.Config{Server: addr, PubB64: pub, ShortIDHex: "0a1b2c3d", Transport: "ss"}
	if err := carrier.Ping(cfg); err != nil {
		t.Fatalf("expected authorized ping to succeed: %v", err)
	}
}

func TestSSUnauthorizedShortIDRejected(t *testing.T) {
	priv, pub, err := keys.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	addr := startSSServer(t, carrier.SSServerConfig{PrivB64: priv, ShortIDs: []string{"0a1b2c3d"}})

	cfg := carrier.Config{Server: addr, PubB64: pub, ShortIDHex: "ffffffff", Transport: "ss"}
	if err := carrier.Ping(cfg); err == nil {
		t.Fatal("expected ping with an unauthorized short id to fail")
	}
}

func TestSSConnectRelays(t *testing.T) {
	priv, pub, err := keys.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		c, err := echoLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c)
	}()

	addr := startSSServer(t, carrier.SSServerConfig{PrivB64: priv, ShortIDs: []string{"0a1b2c3d"}})
	host, portStr, _ := net.SplitHostPort(echoLn.Addr().String())
	var port uint16
	for _, c := range portStr {
		port = port*10 + uint16(c-'0')
	}

	cfg := carrier.Config{Server: addr, PubB64: pub, ShortIDHex: "0a1b2c3d", Transport: "ss"}
	conn, err := carrier.DialConnect(cfg, host, port)
	if err != nil {
		t.Fatalf("DialConnect: %v", err)
	}
	defer conn.Close()

	msg := []byte("hello over shadowsocks-aead")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("expected echo of %q, got %q", msg, buf)
	}
}

type fakeTokenVerifier struct {
	valid map[string]string // token -> allowed shortIDHex
}

func (f fakeTokenVerifier) VerifyToken(token, shortIDHex string) bool {
	return f.valid[token] == shortIDHex
}

func TestSSControlPlaneTokenMode(t *testing.T) {
	priv, pub, err := keys.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	verifier := fakeTokenVerifier{valid: map[string]string{"good-token": "0a1b2c3d"}}
	addr := startSSServer(t, carrier.SSServerConfig{PrivB64: priv, TokenVerifier: verifier})

	okCfg := carrier.Config{Server: addr, PubB64: pub, ShortIDHex: "0a1b2c3d", Transport: "ss", Token: "good-token"}
	if err := carrier.Ping(okCfg); err != nil {
		t.Fatalf("expected valid token to succeed: %v", err)
	}

	badCfg := carrier.Config{Server: addr, PubB64: pub, ShortIDHex: "0a1b2c3d", Transport: "ss", Token: "wrong-token"}
	if err := carrier.Ping(badCfg); err == nil {
		t.Fatal("expected invalid token to fail")
	}
}
