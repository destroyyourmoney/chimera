package preconnect_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"chimera/internal/preconnect"
)

func startTCPEcho(t *testing.T) (addr string, close func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { c.Close() }()
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestPool_GetWarm(t *testing.T) {
	addr, closeServer := startTCPEcho(t)
	defer closeServer()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	p := preconnect.New(ctx, addr, 2)
	time.Sleep(200 * time.Millisecond)

	c, err := p.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	c.Close()
}

func TestPool_GetDegradedOnEmpty(t *testing.T) {
	addr, closeServer := startTCPEcho(t)
	defer closeServer()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	p := preconnect.New(ctx, addr, 1)

	c1, err := p.Get(ctx)
	if err != nil {
		t.Fatalf("Get 1: %v", err)
	}
	c1.Close()

	c2, err := p.Get(ctx)
	if err != nil {
		t.Fatalf("Get 2 (degraded): %v", err)
	}
	c2.Close()
}

func TestPool_GetDiscardsStaleConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				time.AfterFunc(30*time.Millisecond, func() { c.Close() })
				buf := make([]byte, 64)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if _, err := c.Write(buf[:n]); err != nil {
						return
					}
				}
			}(c)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	p := preconnect.New(ctx, ln.Addr().String(), 2)

	time.Sleep(150 * time.Millisecond)

	c, err := p.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer c.Close()

	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("Get returned a stale connection: write failed: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("Get returned a stale/unusable connection: no echo response came back: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("unexpected echo response: got %q, want %q", buf, "ping")
	}
}

func TestPool_ContextCancel(t *testing.T) {
	addr, closeServer := startTCPEcho(t)
	defer closeServer()

	ctx, cancel := context.WithCancel(context.Background())
	_ = preconnect.New(ctx, addr, 2)
	cancel()
	time.Sleep(50 * time.Millisecond)
}
