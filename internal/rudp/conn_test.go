package rudp

import (
	"bytes"
	"crypto/sha256"
	"io"
	"math/rand"
	"sync"
	"testing"
	"time"
)

// fastConfig keeps RTOs small so lossy transfers finish quickly in tests while
// still exercising the full retransmit machinery. FEC is on so the property
// tests cover the encode/decode path too.
func fastConfig() Config {
	c := fastConfigNoFEC()
	c.FEC = true
	return c
}

func fastConfigNoFEC() Config {
	return Config{
		MSS:    1100,
		Window: 1024,
		MinRTO: 5 * time.Millisecond,
		MaxRTO: 200 * time.Millisecond,
	}
}

// transfer streams payload from a writer Conn to a reader Conn over the given
// pipe params and asserts the received bytes equal the sent bytes exactly.
func transfer(t *testing.T, payload []byte, seed int64, p pipeParams) {
	t.Helper()
	endA, endB := newLossyPipe(seed, p)
	sender := NewConn(endA, fastConfig())
	receiver := NewConn(endB, fastConfig())

	var (
		got     []byte
		readErr error
		wg      sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		got, readErr = io.ReadAll(receiver)
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
	if len(got) != len(payload) {
		t.Fatalf("length mismatch: got %d, want %d", len(got), len(payload))
	}
	if sha256.Sum256(got) != sha256.Sum256(payload) {
		t.Fatalf("payload mismatch (seed=%d, loss=%.2f)", seed, p.loss)
	}
	_ = receiver.Close()
}

func randomPayload(n int, seed int64) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

func TestTransferCleanLink(t *testing.T) {
	transfer(t, randomPayload(2<<20, 1), 1, pipeParams{})
}

func TestTransferEmpty(t *testing.T) {
	transfer(t, nil, 2, pipeParams{})
}

func TestTransferLoss20(t *testing.T) {
	transfer(t, randomPayload(2<<20, 3), 3, pipeParams{loss: 0.20, minLat: 500 * time.Microsecond})
}

func TestTransferLoss40(t *testing.T) {
	transfer(t, randomPayload(2<<20, 4), 4, pipeParams{loss: 0.40, minLat: 500 * time.Microsecond})
}

// TestTransferAdversarial combines loss, reordering, duplication, and jitter —
// the property that received == sent must hold under all of them at once.
func TestTransferAdversarial(t *testing.T) {
	p := pipeParams{
		loss:    0.30,
		dupRate: 0.10,
		reorder: 0.25,
		minLat:  300 * time.Microsecond,
		jitter:  4 * time.Millisecond,
	}
	transfer(t, randomPayload(2<<20, 5), 5, p)
}

// TestTransferProperty sweeps random seeds and impairment levels; each must
// deliver the exact bytes. This is the core correctness guarantee for phase 1.
func TestTransferProperty(t *testing.T) {
	if testing.Short() {
		t.Skip("property sweep skipped in -short")
	}
	losses := []float64{0, 0.1, 0.2, 0.4}
	for _, loss := range losses {
		for seed := int64(0); seed < 4; seed++ {
			p := pipeParams{
				loss:    loss,
				dupRate: 0.05,
				reorder: 0.2,
				minLat:  300 * time.Microsecond,
				jitter:  3 * time.Millisecond,
			}
			size := 256<<10 + int(seed)*7919
			transfer(t, randomPayload(size, seed*131+7), seed*131+7, p)
		}
	}
}

// TestOrderedNoDuplicates verifies the reorder buffer delivers a recognizable
// sequence exactly once and in order, even with heavy reordering and dup.
func TestOrderedNoDuplicates(t *testing.T) {
	const n = 50000
	payload := make([]byte, n*4)
	for i := 0; i < n; i++ {
		payload[i*4] = byte(i >> 24)
		payload[i*4+1] = byte(i >> 16)
		payload[i*4+2] = byte(i >> 8)
		payload[i*4+3] = byte(i)
	}
	endA, endB := newLossyPipe(99, pipeParams{
		loss: 0.15, dupRate: 0.2, reorder: 0.3,
		minLat: 200 * time.Microsecond, jitter: 5 * time.Millisecond,
	})
	sender := NewConn(endA, fastConfig())
	receiver := NewConn(endB, fastConfig())

	var got []byte
	done := make(chan struct{})
	go func() { got, _ = io.ReadAll(receiver); close(done) }()

	if _, err := sender.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	sender.Close()
	<-done

	if !bytes.Equal(got, payload) {
		t.Fatalf("stream not byte-exact: got %d bytes, want %d", len(got), len(payload))
	}
	_ = receiver.Close()
}

func TestReadDeadline(t *testing.T) {
	endA, endB := newLossyPipe(7, pipeParams{})
	sender := NewConn(endA, fastConfig())
	receiver := NewConn(endB, fastConfig())
	defer sender.Close()
	defer receiver.Close()

	receiver.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	start := time.Now()
	_, err := receiver.Read(make([]byte, 16))
	if ne, ok := err.(interface{ Timeout() bool }); !ok || !ne.Timeout() {
		t.Fatalf("expected timeout error, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("deadline took too long: %v", elapsed)
	}
}

func TestWriteAfterCloseFails(t *testing.T) {
	endA, _ := newLossyPipe(8, pipeParams{loss: 1.0}) // everything drops
	c := NewConn(endA, fastConfig())
	// Close blocks until FIN acked; with total loss that never happens, so run
	// it in the background and instead assert Write rejects once sndFin is set.
	go c.Close()
	// Give Close a moment to set sndFin.
	time.Sleep(20 * time.Millisecond)
	if _, err := c.Write([]byte("late")); err == nil {
		t.Fatal("expected Write after Close to fail")
	}
	c.teardown(nil) // unblock the background Close
}
