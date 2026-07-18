package server_test

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"chimera/internal/carrier"
	"chimera/internal/clienthello"
	"chimera/internal/keys"
	"chimera/internal/server"
)

type countConn struct {
	net.Conn
	rx, tx atomic.Int64
}

func (c *countConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.rx.Add(int64(n))
	return n, err
}

func (c *countConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.tx.Add(int64(n))
	return n, err
}

const stealBanner = "STEAL-HOST-REAL-RESPONSE"

func fakeSteal(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake steal listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte(stealBanner))
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func startServer(t *testing.T, priv, sid, stealAddr string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		_ = server.Serve(ctx, ln, server.Config{
			StealHost: stealAddr, PrivB64: priv, ShortIDs: []string{sid},
		})
	}()
	return ln.Addr().String()
}

func TestAuthorizedTunnelPing(t *testing.T) {
	priv, pub, err := keys.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	stealAddr, stopSteal := fakeSteal(t)
	defer stopSteal()
	srvAddr := startServer(t, priv, "0a1b2c3d", stealAddr)

	cfg := carrier.Config{Server: srvAddr, PubB64: pub, SNI: "example.com", ShortIDHex: "0a1b2c3d"}
	if err := carrier.Ping(cfg); err != nil {
		t.Fatalf("authorized ping should succeed: %v", err)
	}
}

func TestUnauthorizedIsSplicedToStealHost(t *testing.T) {
	priv, _, err := keys.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	stealAddr, stopSteal := fakeSteal(t)
	defer stopSteal()
	srvAddr := startServer(t, priv, "0a1b2c3d", stealAddr)

	conn, err := net.Dial("tcp", srvAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ch := clienthello.Build("example.com", make([]byte, 28), make([]byte, 32))
	if _, err := conn.Write(ch); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(stealBanner))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("expected steal-host banner via splice: %v", err)
	}
	if string(buf) != stealBanner {
		t.Fatalf("got %q, want steal banner %q", buf, stealBanner)
	}
}

func TestWrongShortIDFallsBack(t *testing.T) {
	priv, pub, err := keys.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	stealAddr, stopSteal := fakeSteal(t)
	defer stopSteal()
	srvAddr := startServer(t, priv, "0a1b2c3d", stealAddr)

	cfg := carrier.Config{Server: srvAddr, PubB64: pub, SNI: "example.com", ShortIDHex: "deadbeef"}
	if err := carrier.Ping(cfg); err == nil {
		t.Fatal("ping with disallowed shortID should not authenticate")
	}
}

func TestSessionStartupByteCount(t *testing.T) {
	const maxBytes = 20 * 1024

	priv, pub, err := keys.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	stealAddr, stopSteal := fakeSteal(t)
	defer stopSteal()
	srvAddr := startServer(t, priv, "aabbccdd", stealAddr)

	serverConn, err := net.DialTimeout("tcp", srvAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial server: %v", err)
	}
	counted := &countConn{Conn: serverConn}

	relayLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	defer relayLn.Close()
	go func() {
		c, err := relayLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		defer counted.Close()
		done := make(chan struct{}, 2)
		go func() { io.Copy(counted, c); done <- struct{}{} }()
		go func() { io.Copy(c, counted); done <- struct{}{} }()
		<-done
	}()

	cfg := carrier.Config{Server: relayLn.Addr().String(), PubB64: pub, SNI: "example.com", ShortIDHex: "aabbccdd"}
	if err := carrier.Ping(cfg); err != nil {
		t.Fatalf("ping: %v", err)
	}

	total := counted.rx.Load() + counted.tx.Load()
	t.Logf("session startup bytes: tx=%d rx=%d total=%d", counted.tx.Load(), counted.rx.Load(), total)
	if total > maxBytes {
		t.Errorf("session startup used %d bytes (max %d): padding may be too large", total, maxBytes)
	}
}
