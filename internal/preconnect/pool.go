// Package preconnect maintains a pool of pre-established TCP connections to the
// steal-host so that both the authorized tunnel path and the unauthenticated
// fallback path consume a warm connection with equivalent latency.
//
// Without pre-warming, the fallback path dials the steal-host on demand. An
// active prober that measures RTT differences between recognized (instant tunnel
// takeover) and unrecognized (dial latency + TLS replay) connections can infer
// that the server is acting as a proxy even if wire bytes are identical.
//
// With this pool, the server keeps N connections live. Both paths grab from the
// pool. If the pool is empty (cold start or exhaustion), a fresh dial is used
// as a graceful fallback.
package preconnect

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"
)

const (
	defaultPoolSize   = 3
	refillDelay       = 200 * time.Millisecond // back-off before refilling after a dial failure
	connectTimeout    = 5 * time.Second
	keepAliveInterval = 30 * time.Second
	// staleCheckTimeout bounds the liveness probe in Get. It's a local read on
	// an already-established socket (no network round trip needed to learn
	// "no data waiting yet"), so this only matters when the peer has in fact
	// closed the connection, in which case the read returns immediately.
	staleCheckTimeout = 20 * time.Millisecond
)

// Pool is a concurrent-safe pool of pre-established TCP connections to a fixed
// target address. Connections are replaced asynchronously after they are taken.
type Pool struct {
	addr    string
	size    int
	ch      chan net.Conn
	mu      sync.Mutex
	inflight int // active background dialers to avoid a refill stampede
}

// New creates a Pool of size connections to addr and starts warming immediately.
// Cancel ctx to drain and stop the pool.
func New(ctx context.Context, addr string, size int) *Pool {
	if size <= 0 {
		size = defaultPoolSize
	}
	p := &Pool{
		addr: addr,
		size: size,
		ch:   make(chan net.Conn, size),
	}
	for range size {
		p.startDial(ctx)
	}
	return p
}

// Get returns a warm connection, skipping any pooled connection that has gone
// stale while sitting idle. A connection that never starts a TLS handshake
// looks like an anomaly to some real CDN edges (Akamai in particular), which
// close it within seconds — well inside how long it can sit unused in this
// pool waiting for an unauthenticated probe. Handing out a dead connection
// silently broke the whole point of this pool: the fallback splice would
// dial-then-immediately-EOF instead of relaying the steal-host's real
// response, which is a bigger tell to an active prober than the dial-latency
// difference this pool exists to hide.
//
// If every pooled connection is stale (or the pool is empty) this falls back
// to a synchronous dial, same as the pre-existing empty-pool behavior.
// The caller owns the returned connection and must close it when done.
func (p *Pool) Get(ctx context.Context) (net.Conn, error) {
	for {
		select {
		case c := <-p.ch:
			p.startDial(ctx) // replace consumed connection
			if isAlive(c) {
				return c, nil
			}
			slog.Debug("preconnect: discarding stale pooled connection", "target", p.addr)
			c.Close()
			continue // try the next pooled connection, if any
		default:
			// Pool empty (or every pooled connection was stale) — dial
			// synchronously (degraded mode, timing not equalized).
			slog.Debug("preconnect pool empty, dialing directly", "target", p.addr)
			return dialWithTimeout(p.addr)
		}
	}
}

// isAlive reports whether c is still open, without consuming any bytes a real
// peer might send once the splice actually starts relaying. A short read
// deadline distinguishes "no data waiting yet" (alive, the expected steady
// state for an idle pooled connection) from "peer closed/reset" (dead).
func isAlive(c net.Conn) bool {
	_ = c.SetReadDeadline(time.Now().Add(staleCheckTimeout))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	one := make([]byte, 1)
	_, err := c.Read(one)
	switch {
	case err == nil:
		// The peer sent data before we ever wrote anything, which shouldn't
		// happen on a raw TCP connection to a TLS host with no handshake
		// started — and we've now consumed a byte the eventual splice would
		// need, so this connection can't be handed out as-is either way.
		return false
	case isTimeoutErr(err):
		return true // no data waiting; the connection is open, as expected
	default:
		return false // EOF / reset / other error: the peer closed it
	}
}

func isTimeoutErr(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

// startDial asynchronously dials addr and puts the result into the channel.
func (p *Pool) startDial(ctx context.Context) {
	p.mu.Lock()
	p.inflight++
	p.mu.Unlock()

	go func() {
		defer func() {
			p.mu.Lock()
			p.inflight--
			p.mu.Unlock()
		}()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			c, err := dialWithTimeout(p.addr)
			if err != nil {
				slog.Debug("preconnect dial failed, retrying", "target", p.addr, "err", err)
				select {
				case <-ctx.Done():
					return
				case <-time.After(refillDelay):
					continue
				}
			}
			select {
			case p.ch <- c:
				return
			case <-ctx.Done():
				c.Close()
				return
			}
		}
	}()
}

func dialWithTimeout(addr string) (net.Conn, error) {
	d := net.Dialer{
		Timeout:   connectTimeout,
		KeepAlive: keepAliveInterval,
	}
	return d.Dial("tcp", addr)
}
