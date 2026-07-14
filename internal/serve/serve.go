// Package serve provides a graceful TCP accept loop shared by the CHIMERA
// carrier server and the local SOCKS5 inbound. On context cancellation it stops
// accepting, unblocks in-flight handlers by closing their connections, and waits
// up to a drain deadline for them to finish before returning cleanly.
package serve

import (
	"context"
	"net"
	"sync"
	"time"
)

// DefaultDrain bounds how long Loop waits for in-flight handlers on shutdown.
const DefaultDrain = 5 * time.Second

// Loop accepts connections on ln until ctx is cancelled, running handle in its
// own goroutine per connection. A cancelled context is a clean shutdown and
// returns nil; any other accept error is returned as-is.
func Loop(ctx context.Context, ln net.Listener, drain time.Duration, handle func(net.Conn)) error {
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		conns = make(map[net.Conn]struct{})
		live  = true
	)

	// On shutdown: stop accepting and unblock every in-flight handler.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
		mu.Lock()
		live = false
		for c := range conns {
			_ = c.SetDeadline(time.Now()) // unblock io.Copy without racing Close
		}
		mu.Unlock()
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break // listener closed by graceful shutdown
			}
			return err
		}

		mu.Lock()
		if !live { // raced with shutdown
			mu.Unlock()
			_ = c.Close()
			continue
		}
		conns[c] = struct{}{}
		mu.Unlock()

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				mu.Lock()
				delete(conns, c)
				mu.Unlock()
			}()
			handle(c)
		}()
	}

	// Bounded drain of in-flight handlers.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(drain):
	}
	return nil
}
