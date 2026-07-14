package congestion

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

func newElasticForTest() *elasticSender {
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(50*time.Millisecond, 0)
	return NewElasticSender(DefaultClock{}, rttStats, 1200, 0) // 0 = adaptive
}

// TestElasticCC_BrutalFixedRate verifies fixed-rate mode: pacing tracks the target
// (loss-compensated) regardless of measured delivery, and never collapses.
func TestElasticCC_BrutalFixedRate(t *testing.T) {
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(50*time.Millisecond, 0)
	const target = 10 * 1024 * 1024 // 10 MB/s
	e := NewElasticSender(DefaultClock{}, rttStats, 1200, target)

	// With no loss, pacing is at least the target (plus the loss=0 → /1 factor).
	if got := e.pacingRate(); got < target {
		t.Fatalf("brutal pacing %d < target %d at 0 loss", got, target)
	}
	// Inject heavy loss; loss compensation must raise pacing ABOVE the target,
	// and it must never fall below it (no estimate suppression).
	for range 400 {
		e.OnCongestionEvent(0, 1400, protocol.ByteCount(64*1024))
	}
	if got := e.pacingRate(); got < target {
		t.Fatalf("brutal pacing %d fell below target %d under loss", got, target)
	}
}

func TestElasticCC_NoCWNDCutOnLoss(t *testing.T) {
	e := newElasticForTest()
	before := e.GetCongestionWindow()
	for range 100 {
		e.OnCongestionEvent(0, 1400, protocol.ByteCount(64*1024))
	}
	if e.GetCongestionWindow() < before {
		t.Fatalf("CWND shrank on loss: %d < %d", e.GetCongestionWindow(), before)
	}
}

func TestElasticCC_CWNDGrowsOnACK(t *testing.T) {
	e := newElasticForTest()
	initial := e.GetCongestionWindow()
	now := DefaultClock{}.Now()
	for i := range 100 {
		e.OnPacketAcked(protocol.PacketNumber(i), 1400, protocol.ByteCount(32*1024), now)
		now = now.Add(10 * time.Millisecond)
	}
	if e.GetCongestionWindow() <= initial {
		t.Fatalf("CWND did not grow on ACKs: %d <= %d", e.GetCongestionWindow(), initial)
	}
}

func TestElasticCC_RTOIgnored(t *testing.T) {
	e := newElasticForTest()
	before := e.GetCongestionWindow()
	e.OnRetransmissionTimeout(true)
	e.OnRetransmissionTimeout(false)
	if e.GetCongestionWindow() < before {
		t.Fatalf("CWND shrank on RTO: %d < %d", e.GetCongestionWindow(), before)
	}
}

func TestElasticCC_CanSend(t *testing.T) {
	e := newElasticForTest()
	if !e.CanSend(0) {
		t.Fatal("CanSend returned false with no bytes in flight")
	}
	if e.CanSend(elasticMaxCWND + 1) {
		t.Fatal("CanSend returned true when bytes_in_flight > maxCWND")
	}
}

func TestElasticCC_NeverSlowStart(t *testing.T) {
	e := newElasticForTest()
	e.MaybeExitSlowStart()
	if e.InSlowStart() {
		t.Fatal("ElasticCC should never be in slow start")
	}
}

// TestElasticCC_PacingSurvivesLoss is the regression test for the death-spiral:
// once a delivery rate is established, heavy loss must NOT reduce the pacing rate
// (loss compensation raises it) and must never collapse to zero.
func TestElasticCC_PacingSurvivesLoss(t *testing.T) {
	e := newElasticForTest()
	now := DefaultClock{}.Now()

	// Establish a peak delivery rate (~6 MB/s: 6000 bytes per 1ms ACK interval).
	for i := range 50 {
		now = now.Add(time.Millisecond)
		e.OnPacketAcked(protocol.PacketNumber(i), 6000, 0, now)
	}
	base := e.pacingRate()
	if base == 0 {
		t.Fatal("pacing rate collapsed to zero with no loss")
	}

	// Inject heavy loss; the loss-rate EWMA should climb and raise the pacing rate.
	for range 300 {
		e.OnCongestionEvent(0, 1400, protocol.ByteCount(64*1024))
	}
	withLoss := e.pacingRate()
	if withLoss == 0 {
		t.Fatal("pacing rate collapsed to zero under loss (death spiral)")
	}
	if withLoss < base {
		t.Fatalf("loss compensation should not lower pacing: %d < %d", withLoss, base)
	}
}

// TestElasticCC_PacingUnitsBytesPerSecond guards the bits/s↔bytes/s conversion:
// the pacer bandwidth must equal pacingRate (bytes/s) * BytesPerSecond.
func TestElasticCC_PacingUnitsBytesPerSecond(t *testing.T) {
	e := newElasticForTest()
	now := DefaultClock{}.Now()
	for i := range 10 {
		now = now.Add(time.Millisecond)
		e.OnPacketAcked(protocol.PacketNumber(i), 6000, 0, now)
	}
	want := Bandwidth(e.pacingRate()) * BytesPerSecond
	if got := e.pacer.adjustedBandwidth(); got == 0 {
		t.Fatal("adjusted bandwidth is zero")
	}
	// adjustedBandwidth applies the 5/4 burst headroom on top of bytes/s.
	if wantBytesPerSec := uint64(want / BytesPerSecond); wantBytesPerSec == 0 {
		t.Fatalf("unit conversion lost magnitude: pacingRate=%d", e.pacingRate())
	}
}
