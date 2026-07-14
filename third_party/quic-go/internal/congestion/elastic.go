package congestion

// ElasticCC is a rate-based congestion controller for adversarial-loss environments
// (DPI throttling, GFW, wireless). Core invariant: packet loss is NOT a congestion
// signal and never triggers a congestion-window cut.
//
// Why this design (and what the first cut got wrong):
//   - Loss must not cut CWND — OnCongestionEvent/OnRetransmissionTimeout are no-ops
//     for the window. The window only ever grows (slow-start-forever, capped).
//   - The PACING rate, not CWND, is the real rate limiter (BBR/Brutal model). The
//     bandwidth estimate is a PEAK-HOLD of delivery-rate samples, so it never
//     collapses under loss the way an ACK-timing EWMA does (sparse ACKs → tiny
//     samples → death-spiral to ~0 throughput).
//   - Loss compensation (Hysteria "Brutal"): to deliver goodput G over a path with
//     loss p, you must send G/(1-p). Pacing rate = peakBW / (1 - lossRate), so the
//     delivered rate holds even as loss rises.
//   - Unit correctness: quic-go's pacer expects a Bandwidth in bits/s
//     (BytesPerSecond == 8). The estimate is computed in bytes/s and converted with
//     `* BytesPerSecond` — the first cut omitted this and paced at 1/8 the rate.

import (
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

const (
	elasticInitialCWND protocol.ByteCount = 512 * 1024        // 512 KB, no slow start
	elasticMaxCWND      protocol.ByteCount = 256 * 1024 * 1024 // 256 MB, effective unlimited

	maxLossComp       = 0.85 // cap loss compensation at 1/(1-0.85) ≈ 6.7×
	lossKeep          = 0.75 // loss-rate EWMA: keep 75% old, 25% new window
	lossWindowPackets = 64   // recompute the loss ratio every ~64 packets of feedback
	defaultRTT        = 100 * time.Millisecond
	// peakDecayNum/peakDecayDen apply a gentle per-RTT-window decay (×0.95) so the
	// delivery-rate peak can adapt down on a genuinely slower path but holds during
	// the ramp. The pacer's built-in 5/4 gain is what drives the ramp UP: sending
	// 1.25× the estimate each window lets the measured rate (and thus the estimate)
	// grow geometrically until the link is filled — BBR-style startup.
	peakDecayNum = 19
	peakDecayDen = 20
)

type elasticSender struct {
	clock           Clock
	rttStats        *utils.RTTStats
	maxDatagramSize protocol.ByteCount

	cwnd     protocol.ByteCount
	peakBW   uint64 // bytes/s, windowed-max delivery rate; 0 = not yet measured
	targetBW uint64 // bytes/s, fixed-rate "Brutal" target; 0 = adaptive estimation
	lossRate float64
	ackedAcc protocol.ByteCount // bytes acked since last loss-window recompute
	lostAcc  protocol.ByteCount // bytes lost since last loss-window recompute

	// Per-RTT delivery-rate window: aggregate acked bytes over ≥1 RTT of wall clock
	// for a stable rate sample (per-ACK sampling is too noisy and self-limits).
	windowAcked protocol.ByteCount
	windowStart monotime.Time

	pacer *pacer
}

var (
	_ SendAlgorithm               = (*elasticSender)(nil)
	_ SendAlgorithmWithDebugInfos = (*elasticSender)(nil)
)

func NewElasticSender(clock Clock, rttStats *utils.RTTStats, initialMaxDatagramSize protocol.ByteCount, targetBandwidth uint64) *elasticSender {
	e := &elasticSender{
		clock:           clock,
		rttStats:        rttStats,
		maxDatagramSize: initialMaxDatagramSize,
		cwnd:            elasticInitialCWND,
		targetBW:        targetBandwidth,
	}
	// Convert bytes/s → Bandwidth (bits/s units) with * BytesPerSecond.
	e.pacer = newPacer(func() Bandwidth {
		return Bandwidth(e.pacingRate()) * BytesPerSecond
	})
	return e
}

func (e *elasticSender) smoothedRTT() time.Duration {
	rtt := e.rttStats.SmoothedRTT()
	if rtt <= 0 {
		rtt = defaultRTT
	}
	return rtt
}

// deliveryRate is the loss-free goodput basis (bytes/s). In Brutal mode it is the
// fixed configured target (immune to loss-induced estimate suppression); otherwise
// the peak-hold delivery estimate once measured, else a BDP bootstrap.
func (e *elasticSender) deliveryRate() uint64 {
	if e.targetBW > 0 {
		return e.targetBW
	}
	if e.peakBW > 0 {
		return e.peakBW
	}
	return uint64(e.cwnd) * uint64(time.Second) / uint64(e.smoothedRTT())
}

// elasticPacingGain overdrives pacing above the measured delivery rate so the
// controller keeps probing for more bandwidth (filling the pipe / ramping) instead
// of settling at whatever it currently delivers. Combined with the pacer's own 5/4,
// the effective gain is ~1.9×. In a loss≠congestion model this aggression is the
// point: extra in-flight overcomes the loss-wasted fraction.
const elasticPacingGain = 1.5

// pacingRate is the loss-compensated, gained send rate (bytes/s):
// deliveryRate * gain / (1-loss).
func (e *elasticSender) pacingRate() uint64 {
	loss := e.lossRate
	if loss > maxLossComp {
		loss = maxLossComp
	}
	return uint64(float64(e.deliveryRate()) * elasticPacingGain / (1.0 - loss))
}

func (e *elasticSender) CanSend(bytesInFlight protocol.ByteCount) bool {
	return bytesInFlight < e.cwnd
}

func (e *elasticSender) HasPacingBudget(now monotime.Time) bool {
	return e.pacer.Budget(now) >= e.maxDatagramSize
}

func (e *elasticSender) TimeUntilSend(_ protocol.ByteCount) monotime.Time {
	return e.pacer.TimeUntilSend()
}

func (e *elasticSender) OnPacketSent(sentTime monotime.Time, _ protocol.ByteCount, _ protocol.PacketNumber, bytes protocol.ByteCount, _ bool) {
	e.pacer.SentPacket(sentTime, bytes)
}

func (e *elasticSender) MaybeExitSlowStart() {}

func (e *elasticSender) OnPacketAcked(_ protocol.PacketNumber, ackedBytes protocol.ByteCount, _ protocol.ByteCount, eventTime monotime.Time) {
	// Aggregate delivery over a ≥1-RTT wall-clock window for a stable rate sample,
	// then fold it into a windowed-max peak (gentle per-window decay). This ramps:
	// the pacer sends 1.25× the estimate, so each window's measured rate grows until
	// the link fills, then the peak holds even when loss makes per-ACK samples noisy.
	if e.windowStart.IsZero() {
		e.windowStart = eventTime
	}
	e.windowAcked += ackedBytes
	if elapsed := eventTime.Sub(e.windowStart); elapsed >= e.smoothedRTT() {
		rate := uint64(e.windowAcked) * uint64(time.Second) / uint64(elapsed)
		decayed := e.peakBW * peakDecayNum / peakDecayDen
		if rate > decayed {
			e.peakBW = rate
		} else {
			e.peakBW = decayed
		}
		e.windowAcked = 0
		e.windowStart = eventTime
	}

	e.ackedAcc += ackedBytes
	e.maybeUpdateLoss()

	// Slow-start-forever plus a BDP floor: open the window fast so it never
	// bottlenecks the loss-compensated pacing; never exited, never cut.
	e.cwnd += ackedBytes
	e.openWindowToBDP()
}

// cwndBDPGain sizes the window at this multiple of the loss-compensated
// bandwidth-delay product. Under loss, in-flight fills with not-yet-detected lost
// packets; the window must be several BDPs so that waste never stalls sending.
const cwndBDPGain = 4

// openWindowToBDP raises CWND to the loss-compensated BDP (×gain) when that exceeds
// the current window. Monotonic (never cut), so the loss≠congestion invariant holds.
func (e *elasticSender) openWindowToBDP() {
	bdp := protocol.ByteCount(e.pacingRate()) * protocol.ByteCount(e.smoothedRTT()) / protocol.ByteCount(time.Second)
	if target := bdp * cwndBDPGain; target > e.cwnd {
		e.cwnd = target
	}
	if e.cwnd > elasticMaxCWND {
		e.cwnd = elasticMaxCWND
	}
}

// OnCongestionEvent records loss for the loss-rate estimate but NEVER cuts the
// window. lostBytes==0 calls (the ACK-path "no loss" notification) are ignored.
func (e *elasticSender) OnCongestionEvent(_ protocol.PacketNumber, lostBytes protocol.ByteCount, _ protocol.ByteCount) {
	if lostBytes <= 0 {
		return
	}
	e.lostAcc += lostBytes
	e.maybeUpdateLoss()
	// Loss raised the compensation; widen the window to match so sparse ACKs under
	// heavy loss don't leave it stuck. Never cut.
	e.openWindowToBDP()
}

// maybeUpdateLoss folds the current feedback window's loss ratio into the EWMA.
func (e *elasticSender) maybeUpdateLoss() {
	total := e.ackedAcc + e.lostAcc
	if total < lossWindowPackets*e.maxDatagramSize {
		return
	}
	ratio := float64(e.lostAcc) / float64(total)
	e.lossRate = e.lossRate*lossKeep + ratio*(1.0-lossKeep)
	e.ackedAcc = 0
	e.lostAcc = 0
}

// OnRetransmissionTimeout is intentionally a no-op: RTO in a lossy network does
// not indicate persistent congestion.
func (e *elasticSender) OnRetransmissionTimeout(_ bool) {}

func (e *elasticSender) SetMaxDatagramSize(s protocol.ByteCount) {
	e.maxDatagramSize = s
	e.pacer.SetMaxDatagramSize(s)
}

func (e *elasticSender) GetCongestionWindow() protocol.ByteCount { return e.cwnd }
func (e *elasticSender) InSlowStart() bool                       { return false }
func (e *elasticSender) InRecovery() bool                        { return false }
