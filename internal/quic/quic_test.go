//go:build chimera_quic

package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	h3 "github.com/quic-go/quic-go/http3"

	"chimera/internal/carrier"
	"chimera/internal/keys"
)

func startServer(t *testing.T) (addr, pubB64 string) {
	t.Helper()
	return startServerWithFallback(t, "")
}

func startServerWithFallback(t *testing.T, stealHost string) (addr, pubB64 string) {
	t.Helper()
	privB64, pubB64, err := keys.GenerateX25519()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	priv, err := keys.DecodePrivate(privB64)
	if err != nil {
		t.Fatalf("decode priv: %v", err)
	}
	tlsConf, err := serverTLS()
	if err != nil {
		t.Fatalf("server tls: %v", err)
	}
	ln, err := quic.ListenAddrEarly("127.0.0.1:0", tlsConf, quicConfig(0))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = serveListenerWithFallback(ctx, ln, priv, priv.PublicKey().Bytes(), nil, stealHost) }()
	t.Cleanup(cancel)
	return ln.Addr().String(), pubB64
}

func startEcho(t *testing.T) (host string, port uint16) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	pn, _ := strconv.Atoi(p)
	return h, uint16(pn)
}

func TestQUICPingLoopback(t *testing.T) {
	addr, pub := startServer(t)
	cfg := carrier.Config{Server: addr, PubB64: pub, SNI: "example.com", Transport: "quic"}
	if err := Ping(cfg); err != nil {
		t.Fatalf("ping over quic carrier: %v", err)
	}
}

func TestQUICInitialCryptoTracerSeesClientHelloSNI(t *testing.T) {
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

	select {
	case data := <-got:
		if len(data) == 0 || data[0] != 1 {
			t.Fatalf("expected TLS ClientHello handshake message, got %x", data[:min(len(data), 8)])
		}
		if !bytes.Contains(data, []byte(sni)) {
			t.Fatalf("Initial CRYPTO data does not contain SNI %q", sni)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Initial CRYPTO tracer was not called")
	}
}

func TestQUICConnectRelay(t *testing.T) {
	addr, pub := startServer(t)
	echoHost, echoPort := startEcho(t)
	cfg := carrier.Config{Server: addr, PubB64: pub, SNI: "example.com", Transport: "quic"}

	conn, err := DialConnect(cfg, echoHost, echoPort)
	if err != nil {
		t.Fatalf("dial connect: %v", err)
	}
	defer conn.Close()

	msg := []byte("chimera-over-quic")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo mismatch: got %q want %q", got, msg)
	}
}

func TestQUICRejectsBadAuth(t *testing.T) {
	addr, _ := startServer(t)

	_, wrongPub, err := keys.GenerateX25519()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	cfg := carrier.Config{Server: addr, PubB64: wrongPub, SNI: "example.com", Transport: "quic"}
	if err := Ping(cfg); err == nil {
		t.Fatal("expected ping to fail with mismatched server key, got nil")
	}
}

func TestQUICFallbackToStealHost(t *testing.T) {

	stealLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("steal-host listen: %v", err)
	}
	t.Cleanup(func() { _ = stealLn.Close() })

	received := make(chan []byte, 1)
	go func() {
		c, err := stealLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 256)
		n, _ := c.Read(buf)
		received <- buf[:n]
	}()

	stealHost := stealLn.Addr().String()
	addr, _ := startServerWithFallback(t, stealHost)

	_, wrongPub, err := keys.GenerateX25519()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	cfg := carrier.Config{Server: addr, PubB64: wrongPub, SNI: "example.com", Transport: "quic"}
	_ = Ping(cfg)

	select {
	case data := <-received:
		if len(data) == 0 {
			t.Fatal("steal-host received empty data")
		}

	case <-time.After(3 * time.Second):
		t.Fatal("steal-host did not receive any data within 3s; fallback may not have fired")
	}
}

func TestQUICH3ProbeFallbackServesStealHost(t *testing.T) {
	stealAddr := startH3StealHost(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/probe" {
			t.Errorf("unexpected fallback path: %s", r.URL.Path)
		}
		w.Header().Set("X-Steal-Host", "ok")
		_, _ = io.WriteString(w, "h3-steal-host")
	}))
	addr, _ := startServerWithFallback(t, stealAddr)

	rt := &h3.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         "example.com",
			InsecureSkipVerify: true,
			NextProtos:         []string{h3.NextProtoH3},
		},
		QUICConfig: &quic.Config{MaxIdleTimeout: 5 * time.Second},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddrEarly(ctx, addr, tlsCfg, cfg)
		},
	}
	defer rt.Close()
	req, err := http.NewRequest(http.MethodGet, "https://example.com/probe", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "example.com"
	resp, err := rt.RoundTripOpt(req, h3.RoundTripOpt{})
	if err != nil {
		t.Fatalf("h3 probe round trip: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", resp.StatusCode, body)
	}
	if got := resp.Header.Get("X-Steal-Host"); got != "ok" {
		t.Fatalf("fallback header = %q, want ok", got)
	}
	if string(body) != "h3-steal-host" {
		t.Fatalf("body = %q, want h3-steal-host", body)
	}
}

func startH3StealHost(t *testing.T, handler http.Handler) string {
	t.Helper()
	tlsConf, err := serverTLS()
	if err != nil {
		t.Fatalf("h3 steal tls: %v", err)
	}
	ln, err := quic.ListenAddrEarly("127.0.0.1:0", h3.ConfigureTLSConfig(tlsConf), quicConfig(0))
	if err != nil {
		t.Fatalf("h3 steal listen: %v", err)
	}
	srv := &h3.Server{Handler: handler, IdleTimeout: 5 * time.Second}
	go func() { _ = srv.ServeListener(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
	})
	return ln.Addr().String()
}
