// Package shaper implements a traffic-shaping writer for the QUIC carrier that
// emits data in discrete bursts to mimic an H3 video-streaming profile.
//
// DPI systems that profile QUIC flows by inter-packet gap and burst size are
// confounded when CHIMERA's traffic pattern looks like progressive video download:
// large bursts at a plausible bitrate separated by short quiet intervals.
//
// The shaper is applied on the write path of the QUIC connection. It does NOT
// affect the tunnel protocol — auth, CONNECT, and PING messages are still sent
// immediately (they are tiny compared to a burst). Only bulk relay bytes are shaped.
//
// Shape parameters match a realistic ~7 Mbit/s H3/H2 video stream. The sustained
// rate is exactly BurstBytes/BurstInterval, so the defaults are kept internally
// consistent: 220 KB released every 250 ms = 880 KB/s ≈ 7.0 Mbit/s, in spaced
// ON/OFF bursts (a quiet gap between each). This caps shaped throughput at the
// video bitrate — the camouflage/throughput tradeoff is the point; shaping is
// opt-in.
//
// The 880 KB/s figure is not arbitrary: it was measured from a real live Twitch
// broadcast capture (Chrome NetLog vantage, see docs/h3-video-cadence-vantage.md)
// — a 113s window of actual CDN video-segment bytes (101.9 MB over a real
// CloudFront/live-video edge) averaged 878.5 KB/s sustained, and at the ~50-100ms
// micro-burst granularity comparable to this shaper's window size, real bursts
// clustered around 58-127 KB every 70-130 ms — the same order of magnitude as
// BurstBytes/BurstInterval here. Real H3 video also has a much coarser, HLS-
// segment-scale ON/OFF envelope (multi-MB bursts every few seconds) that this
// shaper deliberately does not replicate, since a live tunnel cannot go idle for
// seconds at a time without stalling the traffic it's carrying — see the doc for
// the full comparison and that caveat.
//
// These are tunable via ShapeConfig for future adaptive shaping.
package shaper

import (
	"io"
	"net"
	"sync"
	"time"
)

const (
	defaultBurstBytes    = 220 * 1024 // 220 KB per burst window
	defaultBurstInterval = 250 * time.Millisecond
	// Effective sustained rate = defaultBurstBytes / defaultBurstInterval
	//                          = 220 KB / 250 ms = 880 KB/s ≈ 7.0 Mbit/s.
)

// ShapeConfig holds tunable shaping parameters.
type ShapeConfig struct {
	BurstBytes    int           // bytes released per burst window
	BurstInterval time.Duration // time between burst windows
}

// DefaultConfig returns the H3-video-profile defaults.
func DefaultConfig() ShapeConfig {
	return ShapeConfig{
		BurstBytes:    defaultBurstBytes,
		BurstInterval: defaultBurstInterval,
	}
}

// Conn wraps a net.Conn and shapes writes through a shaping Writer. Read and other
// methods are passed through unchanged. Close flushes the shaper and closes the
// underlying connection.
type Conn struct {
	net.Conn
	sw *Writer
}

// WrapConn creates a shaping Conn over c with the given config.
func WrapConn(c net.Conn, cfg ShapeConfig) *Conn {
	return &Conn{Conn: c, sw: New(c, cfg)}
}

// Write shapes p through the burst writer.
func (sc *Conn) Write(p []byte) (int, error) { return sc.sw.Write(p) }

// Close flushes the shaper and closes the underlying connection.
func (sc *Conn) Close() error {
	sc.sw.Close()
	return sc.Conn.Close()
}

// Writer wraps an io.Writer and shapes writes into H3-video-profile bursts.
// Writes do not block — data is buffered internally and flushed by the shaper
// goroutine. Close flushes and signals the shaper to stop.
type Writer struct {
	w    io.Writer
	cfg  ShapeConfig
	buf  []byte
	mu   sync.Mutex
	done chan struct{}
	once sync.Once
}

// New creates a shaping writer over w with the given config and starts the
// background flush goroutine. The caller must call Close when done.
func New(w io.Writer, cfg ShapeConfig) *Writer {
	sw := &Writer{
		w:    w,
		cfg:  cfg,
		done: make(chan struct{}),
	}
	go sw.run()
	return sw
}

// Write buffers p; the background goroutine releases it on the burst cadence.
// Writes never block. Crucially, Write does NOT flush — flushing is strictly
// interval-gated so the on-wire profile is spaced bursts, not whatever cadence the
// application happens to write at.
func (sw *Writer) Write(p []byte) (int, error) {
	sw.mu.Lock()
	sw.buf = append(sw.buf, p...)
	sw.mu.Unlock()
	return len(p), nil
}

// Close drains any remaining buffered bytes and stops the shaper goroutine.
func (sw *Writer) Close() error {
	sw.once.Do(func() { close(sw.done) })
	return nil
}

// run is the shaper's background goroutine. It releases at most BurstBytes every
// BurstInterval — the sustained rate cap and the ON/OFF video cadence both fall out
// of this single rule. Excess stays buffered and rides out on subsequent windows.
func (sw *Writer) run() {
	ticker := time.NewTicker(sw.cfg.BurstInterval)
	defer ticker.Stop()
	for {
		select {
		case <-sw.done:
			sw.drainAll() // flush everything still buffered on close
			return
		case <-ticker.C:
			sw.flush(sw.cfg.BurstBytes)
		}
	}
}

// drainAll writes all remaining buffered bytes (used on Close).
func (sw *Writer) drainAll() {
	sw.mu.Lock()
	chunk := sw.buf
	sw.buf = nil
	sw.mu.Unlock()
	if len(chunk) > 0 {
		_, _ = sw.w.Write(chunk)
	}
}

func (sw *Writer) flush(limit int) {
	sw.mu.Lock()
	if len(sw.buf) == 0 {
		sw.mu.Unlock()
		return
	}
	n := len(sw.buf)
	if n > limit {
		n = limit
	}
	chunk := sw.buf[:n]
	sw.buf = sw.buf[n:]
	sw.mu.Unlock()
	_, _ = sw.w.Write(chunk)
}
