package rudp

import (
	"context"
	"errors"
	"math/rand"
	"sync"
	"time"
)

type pipeParams struct {
	loss    float64
	dupRate float64
	reorder float64
	minLat  time.Duration
	jitter  time.Duration
}

type pipeCore struct {
	mu     sync.Mutex
	rnd    *rand.Rand
	params pipeParams
	closed bool
}

type pipeEnd struct {
	core  *pipeCore
	inbox chan []byte
	peer  *pipeEnd
}

var errPipeClosed = errors.New("rudp: pipe closed")

func newLossyPipe(seed int64, p pipeParams) (*pipeEnd, *pipeEnd) {
	if p.minLat <= 0 {
		p.minLat = 200 * time.Microsecond
	}
	core := &pipeCore{rnd: rand.New(rand.NewSource(seed)), params: p}
	a := &pipeEnd{core: core, inbox: make(chan []byte, 1<<16)}
	b := &pipeEnd{core: core, inbox: make(chan []byte, 1<<16)}
	a.peer, b.peer = b, a
	return a, b
}

func (e *pipeEnd) Send(frame []byte) error {
	e.core.mu.Lock()
	if e.core.closed {
		e.core.mu.Unlock()
		return errPipeClosed
	}
	p := e.core.params
	drop := e.core.rnd.Float64() < p.loss
	dup := e.core.rnd.Float64() < p.dupRate
	late := e.core.rnd.Float64() < p.reorder
	e.core.mu.Unlock()

	if drop {
		return nil
	}
	cp := append([]byte(nil), frame...)
	lat := p.minLat
	if late {
		lat += p.jitter
	}
	e.deliver(cp, lat)
	if dup {
		e.deliver(append([]byte(nil), frame...), p.minLat)
	}
	return nil
}

func (e *pipeEnd) deliver(cp []byte, lat time.Duration) {
	time.AfterFunc(lat, func() {
		e.core.mu.Lock()
		closed := e.core.closed
		e.core.mu.Unlock()
		if closed {
			return
		}
		select {
		case e.peer.inbox <- cp:
		default:
		}
	})
}

func (e *pipeEnd) Recv(ctx context.Context) ([]byte, error) {
	select {
	case b := <-e.inbox:
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (e *pipeEnd) Close() error {
	e.core.mu.Lock()
	e.core.closed = true
	e.core.mu.Unlock()
	return nil
}
