package rudp

import (
	"bytes"
	"io"
	"sync"
	"testing"
	"time"
)

func TestFlowControlSlowReader(t *testing.T) {
	cfg := fastConfig()
	cfg.MaxRecvSegments = 64
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
			time.Sleep(200 * time.Microsecond)
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

	if maxBuf > int(cfg.MaxRecvSegments)+16 {
		t.Fatalf("receiver buffer exceeded flow-control cap: peak=%d cap=%d", maxBuf, cfg.MaxRecvSegments)
	}
	t.Logf("slow reader OK: peak rcvBuf=%d (cap=%d)", maxBuf, cfg.MaxRecvSegments)
}

func TestNoRetransmitStorm(t *testing.T) {
	if testing.Short() {
		t.Skip("storm check skipped in -short")
	}
	const loss = 0.12
	snd, _ := runTransfer(t, randomPayload(2<<20, 71), 71, pipeParams{
		loss: loss, minLat: 400 * time.Microsecond,
	}, fastConfig())

	expectedLost := float64(snd.Sent) * loss
	if float64(snd.Retransmits) > expectedLost*4+200 {
		t.Fatalf("retransmit storm: sent=%d retransmits=%d (expected ≈%.0f lost)",
			snd.Sent, snd.Retransmits, expectedLost)
	}
	t.Logf("no storm: sent=%d retransmits=%d (≈%.0f lost)", snd.Sent, snd.Retransmits, expectedLost)
}
