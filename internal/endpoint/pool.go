// Package endpoint provides health-aware routing across multiple CHIMERA server
// endpoints — the first rung of CHIMERA's adaptive-resilience model.
//
// Censorship in practice is not a single permanent block: endpoint IPs get
// burned, throttled, or briefly nulled, then recover. A single-endpoint client
// dies with its IP. A Pool keeps several endpoints, routes each new stream to
// the healthiest one, silently fails over when a dial fails, applies exponential
// backoff to bad endpoints, and promotes them back automatically once their
// backoff expires — so the user's session survives an endpoint dying mid-flight
// with no manual reconnect.
//
// This is deliberately carrier-agnostic: today every endpoint is a TCP-Reality
// carrier, but the same Pool will later balance heterogeneous carriers (QUIC/H3)
// once those land.
package endpoint

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"chimera/internal/carrier"
)

const (
	baseBackoff = 2 * time.Second
	maxBackoff  = 5 * time.Minute
	maxShift    = 8 // cap exponential backoff growth (2s << 8 ≈ 8.5min -> clamped)
	rttAlpha    = 8 // EWMA smoothing: new = (old*(α-1) + sample)/α
)

var (
	errNoEndpoints = errors.New("endpoint: pool is empty")
	errNoUDP       = errors.New("endpoint: UDP requires the QUIC transport (rebuild with -tags chimera_quic)")
)

// DialFunc opens a stream to host:port through one endpoint. It is a seam so the
// Pool can be tested without real network I/O.
type DialFunc func(cfg carrier.Config, host string, port uint16) (net.Conn, error)

// UDPDialFunc opens a UDP-association carrier through one endpoint. Seam for tests.
type UDPDialFunc func(cfg carrier.Config) (carrier.UDPCarrier, error)

// defaultUDPDial coerces an endpoint to QUIC (UDP datagrams require it) and opens
// a UDP carrier, or reports a clear error when QUIC support is absent.
func defaultUDPDial(c carrier.Config) (carrier.UDPCarrier, error) {
	if carrier.QUICDialUDP == nil {
		return nil, errNoUDP
	}
	c.Transport = "quic"
	return carrier.QUICDialUDP(c)
}

type endpoint struct {
	cfg       carrier.Config
	fails     int
	downUntil time.Time
	rtt       time.Duration // EWMA of successful dial latency
	lastErr   error
}

func (e *endpoint) healthy(now time.Time) bool { return !now.Before(e.downUntil) }

// Pool routes streams across endpoints by health and latency.
type Pool struct {
	mu      sync.Mutex
	eps     []*endpoint
	dial    DialFunc
	dialUDP UDPDialFunc
	now     func() time.Time
}

// NewPool builds a Pool over the given endpoint configs (must be non-empty).
func NewPool(cfgs []carrier.Config) *Pool {
	eps := make([]*endpoint, len(cfgs))
	for i, c := range cfgs {
		eps[i] = &endpoint{cfg: c}
	}
	return &Pool{
		eps:     eps,
		dial:    func(c carrier.Config, h string, p uint16) (net.Conn, error) { return carrier.DialConnect(c, h, p) },
		dialUDP: defaultUDPDial,
		now:     time.Now,
	}
}

// DialUDPCarrier opens a UDP-association carrier through the healthiest endpoint,
// failing over to the next on error. UDP datagrams require the QUIC transport, so
// each endpoint is dialed as QUIC. A UDP-dial failure does NOT mark the endpoint
// unhealthy (it may be perfectly healthy for TCP CONNECT) — it just advances to
// the next candidate.
func (p *Pool) DialUDPCarrier() (carrier.UDPCarrier, error) {
	order := p.candidates()
	if len(order) == 0 {
		return nil, errNoEndpoints
	}
	var lastErr error
	for _, e := range order {
		uc, err := p.dialUDP(e.cfg)
		if err != nil {
			lastErr = err
			continue
		}
		return uc, nil
	}
	return nil, fmt.Errorf("endpoint: no endpoint could open a UDP carrier: %w", lastErr)
}

// DialConnect opens a tunnel to host:port through the healthiest endpoint,
// failing over to the next on error. Returns an error only if every endpoint failed.
func (p *Pool) DialConnect(host string, port uint16) (net.Conn, error) {
	order := p.candidates()
	if len(order) == 0 {
		return nil, errNoEndpoints
	}
	var lastErr error
	for _, e := range order {
		start := p.now()
		conn, err := p.dial(e.cfg, host, port)
		if err != nil {
			p.markFail(e, err)
			lastErr = err
			continue
		}
		p.markOK(e, p.now().Sub(start))
		return conn, nil
	}
	return nil, fmt.Errorf("endpoint: all %d endpoints failed: %w", len(order), lastErr)
}

// AddEndpoints appends endpoints for configs whose Server is not already present
// (deduped). Returns the number added. Safe for concurrent use — this is the
// runtime side of auto-provisioning (telemetry rotation → provision → AddEndpoints).
func (p *Pool) AddEndpoints(cfgs []carrier.Config) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	have := make(map[string]bool, len(p.eps))
	for _, e := range p.eps {
		have[e.cfg.Server] = true
	}
	added := 0
	for _, c := range cfgs {
		if have[c.Server] {
			continue
		}
		p.eps = append(p.eps, &endpoint{cfg: c})
		have[c.Server] = true
		added++
	}
	return added
}

// RemoveEndpoints drops endpoints whose Server matches any in servers. It never
// empties the pool (if removal would leave zero endpoints, nothing is removed) so
// the dialer always has a candidate for forward progress. Returns the count removed.
func (p *Pool) RemoveEndpoints(servers []string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	drop := make(map[string]bool, len(servers))
	for _, s := range servers {
		drop[s] = true
	}
	kept := make([]*endpoint, 0, len(p.eps))
	for _, e := range p.eps {
		if !drop[e.cfg.Server] {
			kept = append(kept, e)
		}
	}
	if len(kept) == 0 {
		return 0 // refuse to empty the pool
	}
	removed := len(p.eps) - len(kept)
	p.eps = kept
	return removed
}

// SetFingerprint updates the browser fingerprint/profile on every endpoint in
// place. New dials pick up the new cfg.Fp; existing connections continue with
// the profile they were created with.
func (p *Pool) SetFingerprint(fp string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.eps {
		e.cfg.Fp = fp
	}
}

// candidates returns a snapshot of endpoints ordered best-first: healthy ones by
// ascending EWMA latency, then backed-off ones by soonest recovery (so a fully
// down pool is still retried, enabling recovery).
func (p *Pool) candidates() []*endpoint {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	out := make([]*endpoint, len(p.eps))
	copy(out, p.eps)
	sort.SliceStable(out, func(i, j int) bool {
		hi, hj := out[i].healthy(now), out[j].healthy(now)
		if hi != hj {
			return hi // healthy before unhealthy
		}
		if hi {
			return out[i].rtt < out[j].rtt // both healthy: faster first
		}
		return out[i].downUntil.Before(out[j].downUntil) // both down: recover-soonest first
	})
	return out
}

func (p *Pool) markFail(e *endpoint, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e.fails++
	shift := e.fails - 1
	if shift > maxShift {
		shift = maxShift
	}
	backoff := baseBackoff << shift
	if backoff > maxBackoff || backoff <= 0 {
		backoff = maxBackoff
	}
	e.downUntil = p.now().Add(backoff)
	e.lastErr = err
}

func (p *Pool) markOK(e *endpoint, sample time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e.fails = 0
	e.downUntil = time.Time{}
	e.lastErr = nil
	if e.rtt == 0 {
		e.rtt = sample
	} else {
		e.rtt = (e.rtt*(rttAlpha-1) + sample) / rttAlpha
	}
}

// DialRaceConnect fires dials to all currently healthy endpoints concurrently and
// returns the first successful connection. When QUIC and TCP endpoints for the
// same server coexist (created by NewAutoPool), this implements mode=auto: the
// faster transport wins. Endpoints that lose the race but succeed are closed.
// If no healthy endpoint succeeds, backed-off endpoints are tried serially (same
// recovery behaviour as DialConnect) to ensure forward progress.
func (p *Pool) DialRaceConnect(host string, port uint16) (net.Conn, error) {
	order := p.candidates()
	if len(order) == 0 {
		return nil, errNoEndpoints
	}
	now := p.now()

	var healthy, unhealthy []*endpoint
	for _, e := range order {
		if e.healthy(now) {
			healthy = append(healthy, e)
		} else {
			unhealthy = append(unhealthy, e)
		}
	}

	if len(healthy) > 0 {
		type result struct {
			conn net.Conn
			err  error
			ep   *endpoint
			rtt  time.Duration
		}
		ch := make(chan result, len(healthy))
		for _, e := range healthy {
			e := e
			go func() {
				start := p.now()
				conn, err := p.dial(e.cfg, host, port)
				ch <- result{conn, err, e, p.now().Sub(start)}
			}()
		}

		for i := 0; i < len(healthy); i++ {
			r := <-ch
			if r.err == nil {
				p.markOK(r.ep, r.rtt)
				remaining := len(healthy) - i - 1
				go func() {
					for j := 0; j < remaining; j++ {
						if r2 := <-ch; r2.conn != nil {
							r2.conn.Close()
						} else if r2.err != nil {
							p.markFail(r2.ep, r2.err)
						}
					}
				}()
				return r.conn, nil
			}
			p.markFail(r.ep, r.err)
		}
	}

	// All healthy endpoints failed — try backed-off ones serially.
	var lastErr error
	for _, e := range unhealthy {
		start := p.now()
		conn, err := p.dial(e.cfg, host, port)
		if err != nil {
			p.markFail(e, err)
			lastErr = err
			continue
		}
		p.markOK(e, p.now().Sub(start))
		return conn, nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("endpoint: all %d endpoints failed: %w", len(order), lastErr)
	}
	return nil, fmt.Errorf("endpoint: all %d endpoints failed", len(order))
}

// Stat is a point-in-time view of one endpoint, for telemetry/tests.
type Stat struct {
	Server  string
	Healthy bool
	Fails   int
	RTT     time.Duration
}

// Stats returns a snapshot of every endpoint's health.
func (p *Pool) Stats() []Stat {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	out := make([]Stat, len(p.eps))
	for i, e := range p.eps {
		out[i] = Stat{Server: e.cfg.Server, Healthy: e.healthy(now), Fails: e.fails, RTT: e.rtt}
	}
	return out
}
