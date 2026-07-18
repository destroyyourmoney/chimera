package serve

import (
	"context"
	"net"
	"sync"
	"time"
)

const DefaultDrain = 5 * time.Second

func Loop(ctx context.Context, ln net.Listener, drain time.Duration, handle func(net.Conn)) error {
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		conns = make(map[net.Conn]struct{})
		live  = true
	)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
		mu.Lock()
		live = false
		for c := range conns {
			_ = c.SetDeadline(time.Now())
		}
		mu.Unlock()
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			return err
		}

		mu.Lock()
		if !live {
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

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(drain):
	}
	return nil
}
