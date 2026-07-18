package shaper

import (
	"io"
	"net"
	"sync"
	"time"
)

const (
	defaultBurstBytes    = 220 * 1024
	defaultBurstInterval = 250 * time.Millisecond
)

type ShapeConfig struct {
	BurstBytes    int
	BurstInterval time.Duration
}

func DefaultConfig() ShapeConfig {
	return ShapeConfig{
		BurstBytes:    defaultBurstBytes,
		BurstInterval: defaultBurstInterval,
	}
}

type Conn struct {
	net.Conn
	sw *Writer
}

func WrapConn(c net.Conn, cfg ShapeConfig) *Conn {
	return &Conn{Conn: c, sw: New(c, cfg)}
}

func (sc *Conn) Write(p []byte) (int, error) { return sc.sw.Write(p) }

func (sc *Conn) Close() error {
	sc.sw.Close()
	return sc.Conn.Close()
}

type Writer struct {
	w    io.Writer
	cfg  ShapeConfig
	buf  []byte
	mu   sync.Mutex
	done chan struct{}
	once sync.Once
}

func New(w io.Writer, cfg ShapeConfig) *Writer {
	sw := &Writer{
		w:    w,
		cfg:  cfg,
		done: make(chan struct{}),
	}
	go sw.run()
	return sw
}

func (sw *Writer) Write(p []byte) (int, error) {
	sw.mu.Lock()
	sw.buf = append(sw.buf, p...)
	sw.mu.Unlock()
	return len(p), nil
}

func (sw *Writer) Close() error {
	sw.once.Do(func() { close(sw.done) })
	return nil
}

func (sw *Writer) run() {
	ticker := time.NewTicker(sw.cfg.BurstInterval)
	defer ticker.Stop()
	for {
		select {
		case <-sw.done:
			sw.drainAll()
			return
		case <-ticker.C:
			sw.flush(sw.cfg.BurstBytes)
		}
	}
}

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
