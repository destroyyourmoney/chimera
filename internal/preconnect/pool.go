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
	refillDelay       = 200 * time.Millisecond
	connectTimeout    = 5 * time.Second
	keepAliveInterval = 30 * time.Second

	staleCheckTimeout = 20 * time.Millisecond
)

type Pool struct {
	addr     string
	size     int
	ch       chan net.Conn
	mu       sync.Mutex
	inflight int
}

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

func (p *Pool) Get(ctx context.Context) (net.Conn, error) {
	for {
		select {
		case c := <-p.ch:
			p.startDial(ctx)
			if isAlive(c) {
				return c, nil
			}
			slog.Debug("preconnect: discarding stale pooled connection", "target", p.addr)
			c.Close()
			continue
		default:

			slog.Debug("preconnect pool empty, dialing directly", "target", p.addr)
			return dialWithTimeout(p.addr)
		}
	}
}

func isAlive(c net.Conn) bool {
	_ = c.SetReadDeadline(time.Now().Add(staleCheckTimeout))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	one := make([]byte, 1)
	_, err := c.Read(one)
	switch {
	case err == nil:

		return false
	case isTimeoutErr(err):
		return true
	default:
		return false
	}
}

func isTimeoutErr(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

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
