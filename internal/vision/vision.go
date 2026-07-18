package vision

import (
	"bufio"
	"io"
	"log/slog"
	"sync"
)

var relayBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

type Flow int

const (
	FlowUnknown Flow = iota
	FlowTLS
	FlowPlain
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

const peekLen = 6

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

func copyBuf(dst io.Writer, src io.Reader) {
	bp := relayBufPool.Get().(*[]byte)
	_, _ = io.CopyBuffer(dst, src, *bp)
	relayBufPool.Put(bp)
}

func Splice(rw io.ReadWriteCloser, target io.ReadWriteCloser) {
	br := bufio.NewReader(rw)
	flow := Classify(br)
	slog.Debug("vision splice", "flow", flow)

	done := make(chan struct{}, 2)
	go func() {
		copyBuf(target, br)
		done <- struct{}{}
	}()
	go func() {
		copyBuf(rw, target)
		done <- struct{}{}
	}()
	<-done
}
