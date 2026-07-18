package rudp

import (
	"crypto/sha256"
	"io"
	"sync"
	"testing"
	"time"
)

func runTransfer(t *testing.T, payload []byte, seed int64, p pipeParams, cfg Config) (sndStats, rcvStats Stats) {
	t.Helper()
	endA, endB := newLossyPipe(seed, p)
	sender := NewConn(endA, cfg)
	receiver := NewConn(endB, cfg)

	var (
		got []byte
		wg  sync.WaitGroup
	)
	wg.Add(1)
	go func() { defer wg.Done(); got, _ = io.ReadAll(receiver) }()

	if _, err := sender.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := sender.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	wg.Wait()

	if sha256.Sum256(got) != sha256.Sum256(payload) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", len(got), len(payload))
	}
	sndStats, rcvStats = sender.Stats(), receiver.Stats()
	_ = receiver.Close()
	return sndStats, rcvStats
}

func TestFECRecoversWithoutRetransmit(t *testing.T) {
	p := pipeParams{loss: 0.10, minLat: 400 * time.Microsecond}
	_, rcv := runTransfer(t, randomPayload(2<<20, 21), 21, p, fastConfig())
	if rcv.FECRecovered == 0 {
		t.Fatal("expected FEC to recover at least some segments without retransmit")
	}
	t.Logf("FEC recovered %d segments without retransmission", rcv.FECRecovered)
}

func TestFECReducesRetransmissions(t *testing.T) {
	if testing.Short() {
		t.Skip("comparison skipped in -short")
	}
	const seed = 33
	p := pipeParams{loss: 0.12, minLat: 400 * time.Microsecond}
	payload := randomPayload(2<<20, seed)

	withFEC, rcv := runTransfer(t, payload, seed, p, fastConfig())
	noFEC, _ := runTransfer(t, payload, seed, p, fastConfigNoFEC())

	t.Logf("retransmits: FEC=%d (recovered=%d, parity=%d) vs noFEC=%d",
		withFEC.Retransmits, rcv.FECRecovered, withFEC.ParitySent, noFEC.Retransmits)
	if rcv.FECRecovered == 0 {
		t.Fatal("FEC recovered nothing")
	}
	if withFEC.Retransmits >= noFEC.Retransmits {
		t.Fatalf("FEC did not reduce retransmissions: FEC=%d, noFEC=%d",
			withFEC.Retransmits, noFEC.Retransmits)
	}
}

func TestFECByteExactHighLoss(t *testing.T) {
	p := pipeParams{loss: 0.40, dupRate: 0.05, reorder: 0.2,
		minLat: 400 * time.Microsecond, jitter: 3 * time.Millisecond}
	_, rcv := runTransfer(t, randomPayload(2<<20, 44), 44, p, fastConfig())
	t.Logf("at 40%% loss: FEC recovered %d segments", rcv.FECRecovered)
}
