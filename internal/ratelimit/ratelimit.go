// Package ratelimit is a per-key token-bucket limiter used to bound abuse of the
// server's authentication crypto path (X25519 + AES-GCM per connection).
//
// Stealth note: being over the limit is NOT a wire-visible event. The server
// treats a throttled connection exactly like any unauthenticated one — it is
// spliced transparently to the steal-host. The limiter only decides whether to
// spend CPU on the auth attempt, never how the connection looks on the wire, so
// it adds no probing oracle.
package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter is a thread-safe per-key token bucket. Keys are typically client IPs.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens refilled per second
	burst   float64 // bucket capacity
	now     func() time.Time
}

// New returns a Limiter refilling rate tokens/sec with the given burst capacity.
// A non-positive rate disables limiting (Allow always returns true).
func New(rate, burst float64) *Limiter {
	return &Limiter{
		buckets: make(map[string]*bucket),
		rate:    rate,
		burst:   burst,
		now:     time.Now,
	}
}

// Allow consumes one token for key, returning true if a token was available.
func (l *Limiter) Allow(key string) bool {
	if l.rate <= 0 {
		return true // limiting disabled
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		// First sight: full bucket minus this request.
		l.buckets[key] = &bucket{tokens: l.burst - 1, last: now}
		return true
	}
	// Refill based on elapsed time, capped at burst.
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// Cleanup evicts buckets idle for at least idle and refilled to capacity, so a
// connection flood from many distinct IPs cannot grow the map without bound.
func (l *Limiter) Cleanup(idle time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := l.now().Add(-idle)
	for k, b := range l.buckets {
		if b.last.Before(cutoff) {
			delete(l.buckets, k)
		}
	}
}

// Size reports the number of tracked keys (for tests and telemetry).
func (l *Limiter) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
