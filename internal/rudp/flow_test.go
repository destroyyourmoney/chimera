package rudp

import (
	"bytes"
	"io"
	"sync"
	"testing"
	"time"
)

// TestFlowControlSlowReader proves the flow-control window bounds receiver
// memory and never deadlocks: a deliberately slow reader must still receive the
// whole stream byte-exact, and the receiver's out-of-order buffer must stay near
// the advertised cap rather than growing with the transfer size.
func TestFlowControlSlowReader(t *testing.T) {
	cfg := fastConfig()
	cfg.MaxRecvSegments = 64 // tight cap to force back-pressure
	endA, endB := newLossyPipe(11, pipeParams{loss: 0.1, minLat: 300 * time.Microsecond})
	sender := NewConn(endA, cfg)
	receiver := NewConn(endB, cfg)

	payload := randomPayload(1<<20, 11)

	var (
		got     bytes.Buffer
		maxBuf  int
		readErr error
		wg      sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := receiver.Read(buf)
			got.Write(buf[:n])
			receiver.mu.Lock()
			if len(receiver.rcvBuf) > maxBuf {
				maxBuf = len(receiver.rcvBuf)
			}
			receiver.mu.Unlock()
			time.Sleep(200 * time.Microsecond) // slow consumer
			if err == io.EOF {
				return
			}
			if err != nil {
				readErr = err
				return
			}
		}
	}()

	if _, err := sender.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := sender.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	wg.Wait()
	if readErr != nil {
		t.Fatalf("read: %v", readErr)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("not byte-exact: got %d, want %d", got.Len(), len(payload))
	}
	// The out-of-order buffer must stay bounded by the flow-control cap (plus a
	// little slack for the zero-window probe), not scale with the 1 MB transfer.
	if maxBuf > int(cfg.MaxRecvSegments)+16 {
		t.Fatalf("receiver buffer exceeded flow-control cap: peak=%d cap=%d", maxBuf, cfg.MaxRecvSegments)
	}
	t.Logf("slow reader OK: peak rcvBuf=%d (cap=%d)", maxBuf, cfg.MaxRecvSegments)
}

// TestNoRetransmitStorm asserts the phase-3 congestion control keeps
// retransmissions proportional to actual loss instead of the spurious-retransmit
// storm an unpaced window + tight RTO produced. At ~12 % loss the retransmit
// count should be within a small multiple of the lost-segment count, not orders
// of magnitude above it.
func TestNoRetransmitStorm(t *testing.T) {
	if testing.Short() {
		t.Skip("storm check skipped in -short")
	}
	const loss = 0.12
	snd, _ := runTransfer(t, randomPayload(2<<20, 71), 71, pipeParams{
		loss: loss, minLat: 400 * time.Microsecond,
	}, fastConfig())

	// ~Sent*loss segments are genuinely lost; allow generous headroom for
	// ACK loss and tail effects, but nothing like the old ~150x storm.
	expectedLost := float64(snd.Sent) * loss
	if float64(snd.Retransmits) > expectedLost*4+200 {
		t.Fatalf("retransmit storm: sent=%d retransmits=%d (expected ≈%.0f lost)",
			snd.Sent, snd.Retransmits, expectedLost)
	}
	t.Logf("no storm: sent=%d retransmits=%d (≈%.0f lost)", snd.Sent, snd.Retransmits, expectedLost)
}
