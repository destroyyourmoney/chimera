package shaper

import (
	"bytes"
	"io"
	"sync"
	"testing"
	"time"
)

type collectWriter struct {
	mu  sync.Mutex
	buf []byte
}

func (c *collectWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.buf = append(c.buf, p...)
	c.mu.Unlock()
	return len(p), nil
}

func (c *collectWriter) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]byte, len(c.buf))
	copy(cp, c.buf)
	return cp
}

func TestShaper_AllBytesDelivered(t *testing.T) {
	dst := &collectWriter{}
	sw := New(dst, ShapeConfig{BurstBytes: 1024, BurstInterval: 10 * time.Millisecond})

	payload := bytes.Repeat([]byte("x"), 4*1024)
	if _, err := sw.Write(payload); err != nil {
		t.Fatal(err)
	}
	sw.Close()
	time.Sleep(50 * time.Millisecond)

	got := dst.Bytes()
	if !bytes.Equal(got, payload) {
		t.Fatalf("shaper lost bytes: got %d bytes, want %d", len(got), len(payload))
	}
}

func TestShaper_BurstsDoNotExceedBurstSize(t *testing.T) {
	var mu sync.Mutex
	var writeSizes []int
	dst := &callbackWriter{fn: func(p []byte) {
		mu.Lock()
		writeSizes = append(writeSizes, len(p))
		mu.Unlock()
	}}

	cfg := ShapeConfig{BurstBytes: 512, BurstInterval: 20 * time.Millisecond}
	sw := New(dst, cfg)

	_, _ = sw.Write(bytes.Repeat([]byte("a"), 2048))
	time.Sleep(100 * time.Millisecond)
	sw.Close()

	mu.Lock()
	defer mu.Unlock()
	for _, sz := range writeSizes {
		if sz > cfg.BurstBytes {
			t.Errorf("burst write %d exceeded BurstBytes %d", sz, cfg.BurstBytes)
		}
	}
}

func TestShaper_CloseFlushesAll(t *testing.T) {
	dst := &collectWriter{}
	sw := New(dst, ShapeConfig{BurstBytes: 1, BurstInterval: 1 * time.Hour})

	payload := []byte("hello")
	_, _ = sw.Write(payload)
	sw.Close()
	time.Sleep(20 * time.Millisecond)

	got := dst.Bytes()
	if !bytes.Equal(got, payload) {
		t.Fatalf("Close did not flush; got %q want %q", got, payload)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.BurstBytes <= 0 {
		t.Fatal("BurstBytes must be positive")
	}
	if cfg.BurstInterval <= 0 {
		t.Fatal("BurstInterval must be positive")
	}
}

func TestShaper_WriterImplementsIOWriter(t *testing.T) {
	var _ io.Writer = New(io.Discard, DefaultConfig())
}

func TestShaper_BurstCadenceAndRate(t *testing.T) {
	type rec struct {
		at time.Time
		n  int
	}
	var mu sync.Mutex
	var recs []rec
	dst := &callbackWriter{fn: func(p []byte) {
		mu.Lock()
		recs = append(recs, rec{time.Now(), len(p)})
		mu.Unlock()
	}}

	const burst = 4096
	const interval = 20 * time.Millisecond
	const window = 200 * time.Millisecond
	sw := New(dst, ShapeConfig{BurstBytes: burst, BurstInterval: interval})

	feeder := time.NewTicker(2 * time.Millisecond)
	deadline := time.After(window)
feed:
	for {
		select {
		case <-feeder.C:
			_, _ = sw.Write(bytes.Repeat([]byte("x"), burst))
		case <-deadline:
			break feed
		}
	}
	feeder.Stop()

	mu.Lock()
	inWindow := append([]rec(nil), recs...)
	mu.Unlock()

	sw.Close()
	time.Sleep(40 * time.Millisecond)

	expected := int(window / interval)
	if len(inWindow) < expected/2 {
		t.Fatalf("too few bursts: got %d, want ≈%d (spaced cadence)", len(inWindow), expected)
	}
	if len(inWindow) > expected*2 {
		t.Fatalf("too many bursts: got %d, want ≈%d (not interval-gated?)", len(inWindow), expected)
	}

	var out int
	for i, r := range inWindow {
		if r.n > burst {
			t.Errorf("burst %d size %d exceeded BurstBytes %d", i, r.n, burst)
		}
		out += r.n
	}

	capRate := float64(burst) / interval.Seconds()
	gotRate := float64(out) / window.Seconds()
	if gotRate > capRate*1.6 {
		t.Fatalf("output rate %.0f B/s exceeds cap %.0f B/s (shaping not enforced)", gotRate, capRate)
	}
}

type callbackWriter struct {
	fn func([]byte)
}

func (c *callbackWriter) Write(p []byte) (int, error) {
	c.fn(p)
	return len(p), nil
}
