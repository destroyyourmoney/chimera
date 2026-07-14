package rudp

import (
	"context"
	"errors"
	"math/rand"
	"sync"
	"time"
)

// lossyPipe is an in-memory, full-duplex Datagram pair with configurable drop,
// reorder, duplication, and latency. It lets rudp be exercised against
// adversarial loss with zero network or QUIC dependency — the core of the
// phase 0–2 property tests.
//
// Each endpoint's Send enqueues onto the peer's delivery channel after applying
// the impairment model; Recv dequeues from its own channel. Both endpoints
// share one rand source guarded by a mutex so seeded runs are reproducible.
type pipeParams struct {
	loss    float64 // drop probability per frame [0,1]
	dupRate float64 // probability a delivered frame is also duplicated
	reorder float64 // probability a frame is delayed (jittered) to reorder
	minLat  time.Duration
	jitter  time.Duration // extra latency applied to reordered frames
}

type pipeCore struct {
	mu     sync.Mutex
	rnd    *rand.Rand
	params pipeParams
	closed bool
}

type pipeEnd struct {
	core  *pipeCore
	inbox chan []byte // frames destined for this end
	peer  *pipeEnd    // where this end's Send delivers
}

var errPipeClosed = errors.New("rudp: pipe closed")

// newLossyPipe returns the two ends of an impaired datagram link.
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
		return nil // best-effort: a dropped frame is not an error
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

// deliver schedules cp onto the peer's inbox after lat, off the Send path so
// reordering actually happens (a later frame with less latency overtakes it).
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
		default: // inbox full: model as a drop rather than block forever
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
