package preconnect_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"chimera/internal/preconnect"
)

// startTCPEcho starts a TCP echo server and returns its address and a close func.
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
	time.Sleep(200 * time.Millisecond) // let pool warm up

	c, err := p.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	c.Close()
}

func TestPool_GetDegradedOnEmpty(t *testing.T) {
	addr, closeServer := startTCPEcho(t)
	defer closeServer()

	// Zero-size pool always falls through to direct dial.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	p := preconnect.New(ctx, addr, 1)
	// Don't wait for warm-up — immediately drain.
	c1, err := p.Get(ctx)
	if err != nil {
		t.Fatalf("Get 1: %v", err)
	}
	c1.Close()

	// Second get might dial directly if pool not yet refilled.
	c2, err := p.Get(ctx)
	if err != nil {
		t.Fatalf("Get 2 (degraded): %v", err)
	}
	c2.Close()
}

// TestPool_GetDiscardsStaleConnection reproduces the production bug found
// while testing the anti-probing fallback splice against a real CDN
// (Akamai/www.microsoft.com): pooled connections that sat idle long enough
// for the peer to close them were still handed out by Get, so the splice
// wrote the replayed ClientHello into an already-dead socket and the
// fallback silently broke — the real steal-host's response never came back —
// instead of relaying a genuine response. Here the test server closes every
// accepted connection shortly after accepting it (simulating that CDN
// idle-close behavior) but echoes anything it reads before that; Get, called
// only after that close window has passed, must return a connection that
// completes a real round trip — a plain non-nil return (or a write that
// happens to still succeed into a half-closed socket) is not enough to prove
// that, which is why this checks for the echo rather than just the write.
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
				time.AfterFunc(30*time.Millisecond, func() { c.Close() }) // simulate a short-lived CDN idle timeout
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
	// Let every pooled connection go stale (closed peer-side) before Get is
	// ever called — this is exactly the "unauthenticated probe arrives after
	// the pool has been sitting idle for a while" scenario from production.
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
	cancel() // pool should drain silently, no panic
	time.Sleep(50 * time.Millisecond)
}
