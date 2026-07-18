package ratelimit

import (
	"testing"
	"time"
)

func TestBurstThenThrottle(t *testing.T) {
	l := New(1, 3)
	base := time.Unix(1000, 0)
	l.now = func() time.Time { return base }

	for i := 0; i < 3; i++ {
		if !l.Allow("1.2.3.4") {
			t.Fatalf("burst request %d unexpectedly throttled", i)
		}
	}
	if l.Allow("1.2.3.4") {
		t.Fatal("4th request should be throttled (burst exhausted)")
	}
}

func TestRefillOverTime(t *testing.T) {
	l := New(2, 2)
	base := time.Unix(0, 0)
	l.now = func() time.Time { return base }

	if !l.Allow("ip") || !l.Allow("ip") {
		t.Fatal("burst should allow 2")
	}
	if l.Allow("ip") {
		t.Fatal("3rd should be throttled")
	}

	base = base.Add(time.Second)
	if !l.Allow("ip") || !l.Allow("ip") {
		t.Fatal("after refill, 2 more should pass")
	}
	if l.Allow("ip") {
		t.Fatal("tokens should be exhausted again")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	l := New(1, 1)
	base := time.Unix(0, 0)
	l.now = func() time.Time { return base }
	if !l.Allow("a") {
		t.Fatal("first key should pass")
	}
	if !l.Allow("b") {
		t.Fatal("second key should have its own bucket")
	}
}

func TestDisabledWhenRateZero(t *testing.T) {
	l := New(0, 0)
	for i := 0; i < 1000; i++ {
		if !l.Allow("x") {
			t.Fatal("rate 0 must disable limiting")
		}
	}
	if l.Size() != 0 {
		t.Fatal("disabled limiter should not allocate buckets")
	}
}

func TestCleanupEvictsIdle(t *testing.T) {
	l := New(1, 1)
	base := time.Unix(0, 0)
	l.now = func() time.Time { return base }
	l.Allow("stale")
	l.Allow("fresh")

	base = base.Add(10 * time.Minute)
	l.Allow("fresh")
	l.Cleanup(5 * time.Minute)

	if l.Size() != 1 {
		t.Fatalf("expected 1 bucket after cleanup, got %d", l.Size())
	}
}
