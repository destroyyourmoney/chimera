// Package vision provides TLS-flow detection for the inner relay stream (Vision-splicing).
//
// When a CHIMERA client tunnels HTTPS traffic, the relay payload begins with a TLS
// ClientHello. Without special handling this produces a TLS-in-TLS layering that is
// detectable by entropy analysis — the outer session already looks like TLS, and now
// the inner payload does too.
//
// Vision-splicing solves this by classifying the relay payload at tunnel establishment
// time and, in builds where the outer session carries its own TLS (chimera_utls),
// treating the inner stream in "splice mode": relay bytes pass through without any
// additional framing, padding is minimised, and record boundaries are preserved.
//
// In the default (non-utls) build the inner protocol already rides an unencrypted
// stream, so Vision classification is still performed for telemetry but the relay
// behaviour is identical to the non-Vision path.
package vision

import (
	"bufio"
	"io"
	"log/slog"
	"sync"
)

// relayBufPool holds 32 KB relay buffers reused across Splice calls.
// This matches io.Copy's default buffer size and avoids per-relay allocations.
var relayBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

// Flow describes the detected inner traffic type.
type Flow int

const (
	FlowUnknown  Flow = iota
	FlowTLS           // inner stream opens with a TLS 1.x ClientHello
	FlowPlain         // inner stream does not look like TLS
)

func (f Flow) String() string {
	switch f {
	case FlowTLS:
		return "tls"
	case FlowPlain:
		return "plain"
	default:
		return "unknown"
	}
}

// peekLen is the minimum prefix we need to classify.
const peekLen = 6

// Classify peeks at the first bytes in br without consuming them. The bufio.Reader
// must be freshly created over the relay ReadWriter so that Peek does not block
// waiting for bytes already consumed by the tunnel control exchange.
//
// TLS detection: content-type 0x16 (handshake) + legacy_record_version 0x0301–0x0303
// + length(2) + handshake_type 0x01 (ClientHello) at byte offset 5.
func Classify(br *bufio.Reader) Flow {
	hdr, err := br.Peek(peekLen)
	if err != nil || len(hdr) < peekLen {
		return FlowUnknown
	}
	if hdr[0] == 0x16 && hdr[1] == 0x03 && hdr[2] <= 0x03 && hdr[5] == 0x01 {
		return FlowTLS
	}
	return FlowPlain
}

// copyBuf copies from src to dst using a pooled buffer to avoid per-call allocation.
func copyBuf(dst io.Writer, src io.Reader) {
	bp := relayBufPool.Get().(*[]byte)
	_, _ = io.CopyBuffer(dst, src, *bp)
	relayBufPool.Put(bp)
}

// Splice performs a bidirectional relay of the tunnel payload and returns when
// either direction closes. It wraps the inbound read side in br (so any already-peeked
// bytes are naturally re-read), and writes in both directions directly.
// Relay buffers are drawn from a sync.Pool to avoid per-relay allocation.
//
// slog is used for a single Debug line with the detected flow, available to
// operators debugging TLS-in-TLS issues without adding per-byte overhead.
func Splice(rw io.ReadWriteCloser, target io.ReadWriteCloser) {
	br := bufio.NewReader(rw)
	flow := Classify(br)
	slog.Debug("vision splice", "flow", flow)

	done := make(chan struct{}, 2)
	go func() {
		copyBuf(target, br) // client → target; re-reads peeked bytes naturally
		done <- struct{}{}
	}()
	go func() {
		copyBuf(rw, target) // target → client
		done <- struct{}{}
	}()
	<-done
}
