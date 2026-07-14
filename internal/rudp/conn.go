package rudp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"time"

	"chimera/internal/fec"
)

// Defaults. MSS is path MTU minus QUIC/datagram/rudp headers (~1100 B). Window
// bounds in-flight segments (and therefore the retransmit + reorder buffers, so
// memory is bounded). RTO is capped — the lesson from the PTO bug is to never
// exponential-backoff into seconds.
const (
	defaultMSS    = 1100
	defaultWindow = 2048
	defaultMinRTO = 30 * time.Millisecond
	defaultMaxRTO = 1 * time.Second

	// fecInitLoss seeds the loss EWMA / initial FEC group size (≈5 % → N≈20).
	fecInitLoss = 0.05
	// lossAlpha smooths the per-segment loss observations feeding FEC sizing.
	lossAlpha = 1.0 / 32.0

	// Congestion control (phase 3). cwnd is in segments. The decrease on loss is
	// gentle (×0.85, not ×0.5) because this is a loss-≠-congestion carrier: we
	// keep the pipe full and lean on FEC + pacing rather than collapsing the
	// window on every drop.
	initCwnd          = 16.0
	minCwnd           = 4.0
	cwndLossDecrease  = 0.85
	dupThreshold      = 3 // SACKed segments beyond a gap that trigger fast retransmit
	defaultMaxRecvSeg = 4096

	// closeLinger bounds how long Close waits for its FIN to be acked before
	// tearing down anyway, so a vanished peer can never hang a close.
	closeLinger = 30 * time.Second

	// Delayed/stretch ACKs. The receiver coalesces acknowledgements — one per
	// ackEvery delivered segments, or after ackDelay — to keep ACK datagrams from
	// crowding out data on the shared QUIC datagram channel. Urgent cases (open
	// gap, EOF) still ACK immediately.
	ackEvery = 8
	ackDelay = 4 * time.Millisecond
)

// Config tunes a Conn. Zero fields take the package defaults.
type Config struct {
	MSS    int           // max DATA payload bytes per segment
	Window uint32        // max in-flight (unacked) segments
	MinRTO time.Duration // retransmit timeout floor
	MaxRTO time.Duration // retransmit timeout ceiling (the cap)

	// FEC enables the adaptive XOR forward-error-correction layer (internal/fec):
	// first transmissions are grouped and protected by parity so most loss is
	// recovered at the receiver without a retransmission RTT. Retransmissions
	// (the ARQ fallback) always bypass FEC. Receivers feed their measured loss
	// back on ACKs to drive the sender's adaptive group size.
	FEC bool

	// MaxRecvSegments bounds the receiver's buffered (out-of-order + undelivered)
	// segments; it is advertised back as the flow-control window so sender memory
	// and receiver memory both stay bounded. 0 → defaultMaxRecvSeg.
	MaxRecvSegments uint32
}

func (c Config) withDefaults() Config {
	if c.MSS <= 0 {
		c.MSS = defaultMSS
	}
	if c.Window == 0 {
		c.Window = defaultWindow
	}
	if c.MinRTO <= 0 {
		c.MinRTO = defaultMinRTO
	}
	if c.MaxRTO <= 0 {
		c.MaxRTO = defaultMaxRTO
	}
	if c.MaxRTO < c.MinRTO {
		c.MaxRTO = c.MinRTO
	}
	if c.MaxRecvSegments == 0 {
		c.MaxRecvSegments = defaultMaxRecvSeg
	}
	return c
}

// segment is one unacked DATA unit held in the retransmit buffer.
type segment struct {
	seq      uint32
	payload  []byte
	sentAt   time.Time // zero until first transmitted
	xmits    int       // retransmission count (0 = sent once)
	needsRex bool      // flagged for immediate (fast) retransmit by SACK evidence
}

// Conn is a reliable, ordered bytestream over a Datagram. It implements
// net.Conn, so existing consumers (vision.Splice, the SOCKS relay) are
// unchanged. It is full-duplex: each side runs an independent sender (this
// Conn's Write path) and receiver (the peer's Write path).
type Conn struct {
	dg  Datagram
	cfg Config

	ctx    context.Context
	cancel context.CancelFunc

	mu sync.Mutex

	// --- send side ---
	sndUna  uint32              // oldest unacked seq (== peer's cumAck)
	sndNext uint32              // next seq to assign
	sndBuf  map[uint32]*segment // unacked segments, keyed by seq
	sndCond *sync.Cond          // woken when the window opens or state changes
	sndFin  bool                // local Close queued a FIN
	finSeq  uint32              // the FIN's own seq (== sndNext at Close)
	finSent time.Time           // last FIN (re)transmit
	finAck  bool                // peer acked our FIN (sndUna > finSeq)

	// RTT estimation (Jacobson/Karn), feeds the capped RTO.
	srtt   time.Duration
	rttvar time.Duration
	rto    time.Duration

	// Congestion window + pacing (phase 3). cwnd bounds in-flight; rwnd is the
	// peer's advertised free buffer; nextSend gates the loss-compensated pacer.
	cwnd        float64
	ssthresh    float64
	rwnd        uint32 // peer's advertised free window (segments); 0 = stalled
	nextSend    time.Time
	lastLossCut time.Time

	// lossEWMA is the sender's own measured first-transmission loss rate: the
	// fraction of acked segments that needed at least one retransmit. It drives
	// the FEC group size. Unlike the FEC decoder's estimate it is unbiased —
	// it counts every lost segment, including those in groups XOR can't repair.
	lossEWMA float64
	lossInit bool

	// --- recv side ---
	rcvNext         uint32            // next in-order seq expected (== our cumAck)
	rcvBuf          map[uint32][]byte // out-of-order received segments
	readBuf         bytes.Buffer      // contiguous delivered bytes awaiting Read
	rcvCond         *sync.Cond        // woken when data is readable or EOF/err
	rcvFin          bool              // peer sent FIN
	rcvFinSeq       uint32            // peer's finalSeq
	rcvEOF          bool              // FIN + all data consumed → reader sees io.EOF
	maxRecvSeg      uint32            // flow-control buffer cap (segments)
	lastRwndAdv     uint32            // last rwnd we advertised (for window-update acks)
	segsSinceAck    int               // delivered segments since last ACK (stretch-ACK counter)
	ackPendingSince time.Time         // when a delayed ACK became due (zero = none pending)

	// --- FEC (phase 2) ---
	fecOn bool
	enc   *fec.Encoder // first-transmit segments are grouped + parity-protected
	dec   *fec.Decoder // recovers erasures before ARQ; estimates loss for feedback
	st    stats

	// --- lifecycle ---
	txWake    chan struct{} // nudges the transmit loop
	err       error         // sticky transport/teardown error
	closed    bool          // teardown complete
	closeOnce sync.Once

	// --- deadlines (net.Conn) ---
	readDeadline  time.Time
	writeDeadline time.Time
	rdTimer       *time.Timer
	wrTimer       *time.Timer
}

// stats accumulates transport counters (guarded by c.mu).
type stats struct {
	sent         uint64 // DATA segments first-transmitted
	retrans      uint64 // DATA segments retransmitted (ARQ fallback)
	parity       uint64 // PARITY frames emitted by the FEC encoder
	fecRecovered uint64 // segments delivered via FEC recovery (no retransmit)
}

// Stats is a snapshot of a Conn's transport counters, used by tests and the
// netem bench to quantify how much loss FEC repairs without retransmission.
type Stats struct {
	Sent         uint64
	Retransmits  uint64
	ParitySent   uint64
	FECRecovered uint64
}

// Stats returns a snapshot of the connection's counters.
func (c *Conn) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Stats{
		Sent:         c.st.sent,
		Retransmits:  c.st.retrans,
		ParitySent:   c.st.parity,
		FECRecovered: c.st.fecRecovered,
	}
}

// errClosed is returned by Read/Write after the Conn is torn down.
var errClosed = errors.New("rudp: connection closed")

// NewConn wraps a Datagram in a reliable bytestream and starts its loops.
func NewConn(dg Datagram, cfg Config) *Conn {
	cfg = cfg.withDefaults()
	ctx, cancel := context.WithCancel(context.Background())
	c := &Conn{
		dg:         dg,
		cfg:        cfg,
		ctx:        ctx,
		cancel:     cancel,
		sndBuf:     make(map[uint32]*segment),
		rcvBuf:     make(map[uint32][]byte),
		rto:        cfg.MinRTO,
		txWake:     make(chan struct{}, 1),
		fecOn:      cfg.FEC,
		cwnd:       initCwnd,
		ssthresh:   float64(cfg.Window),
		rwnd:       cfg.MaxRecvSegments, // optimistic until the first ACK arrives
		maxRecvSeg: cfg.MaxRecvSegments,
	}
	if c.fecOn {
		// Start at a moderate loss assumption so early groups carry useful
		// redundancy before the measured rate converges.
		c.enc = fec.NewEncoder(fecInitLoss)
		c.dec = fec.NewDecoder(0)
		c.lossEWMA = fecInitLoss
		c.lossInit = true
	}
	c.sndCond = sync.NewCond(&c.mu)
	c.rcvCond = sync.NewCond(&c.mu)
	go c.readLoop()
	go c.transmitLoop()
	return c
}

// nudgeTx wakes the transmit loop without blocking (signals coalesce).
func (c *Conn) nudgeTx() {
	select {
	case c.txWake <- struct{}{}:
	default:
	}
}

// fail records the first terminal error and wakes everyone waiting.
func (c *Conn) fail(err error) {
	c.mu.Lock()
	if c.err == nil {
		c.err = err
	}
	c.sndCond.Broadcast()
	c.rcvCond.Broadcast()
	c.mu.Unlock()
	c.nudgeTx()
}

// ---------------------------------------------------------------------------
// Receive path
// ---------------------------------------------------------------------------

func (c *Conn) readLoop() {
	for {
		raw, err := c.dg.Recv(c.ctx)
		if err != nil {
			c.fail(fmt.Errorf("rudp: recv: %w", err))
			return
		}
		if len(raw) == 0 {
			continue
		}
		// FEC frames (0x00 data / 0x01 parity) ride under rudp's DATA framing;
		// their byte namespace is disjoint from rudp's (0x10+), so the first
		// byte disambiguates. The payload a FEC data/recovery yields is itself
		// a rudp DATA frame, so a recovered packet carries its own seq.
		if c.fecOn && (fec.IsData(raw) || fec.IsParity(raw)) {
			payload, isData, recovered := c.dec.Add(raw)
			delivered, urgent := false, false
			if isData {
				if c.applyInner(payload, false) {
					urgent = true
				}
				delivered = true
			}
			if recovered != nil {
				if c.applyInner(recovered, true) {
					urgent = true
				}
				delivered = true
			}
			if delivered {
				c.scheduleAck(urgent)
			}
			continue
		}
		f, ok := decodeFrame(raw)
		if !ok {
			continue
		}
		if f.typ == fAck {
			c.onAck(f)
			continue
		}
		// Raw DATA (a retransmit, which bypasses FEC) or FIN.
		urgent := c.applyInner(raw, false)
		c.scheduleAck(urgent)
	}
}

// applyInner decodes one inner rudp frame (DATA or FIN) and folds it into the
// receive state. recovered marks a payload reconstructed by FEC. It returns
// urgent=true when the receiver should ACK promptly rather than wait for the
// delayed-ACK timer: a gap is open (so the sender sees the SACK and fast-
// retransmits) or the stream just reached EOF. Old and duplicate segments are
// tolerated so a sender whose ACKs were lost eventually stops retransmitting.
func (c *Conn) applyInner(raw []byte, recovered bool) (urgent bool) {
	f, ok := decodeFrame(raw)
	if !ok {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	switch f.typ {
	case fData:
		if seqLess(f.seq, c.rcvNext) {
			return false // already delivered
		}
		if _, dup := c.rcvBuf[f.seq]; dup {
			return false
		}
		if recovered {
			c.st.fecRecovered++
		}
		c.rcvBuf[f.seq] = f.payload
		c.advance()
		return len(c.rcvBuf) > 0 // a gap remains → ACK now so the sender repairs it
	case fFin:
		c.rcvFin = true
		c.rcvFinSeq = f.seq
		c.advance()
		return true
	}
	return false
}

// buildAckLocked snapshots the current cumAck + SACK ranges, riding the
// receiver's FEC-measured loss estimate (so the sender sizes parity) and its
// advertised flow-control window. Caller holds c.mu.
func (c *Conn) buildAckLocked() []byte {
	var loss uint16
	if c.fecOn {
		loss = uint16(c.dec.LossEstimate()*1000 + 0.5)
	}
	rwnd := c.rwndLocked()
	c.lastRwndAdv = rwnd
	return encodeAck(c.rcvNext, c.sackRangesLocked(), loss, rwnd)
}

// sendAck immediately transmits one ACK (used for window-update probes).
func (c *Conn) sendAck() {
	c.mu.Lock()
	ack := c.buildAckLocked()
	c.mu.Unlock()
	_ = c.dg.Send(ack)
}

// scheduleAck implements delayed/stretch ACKs: rather than acknowledging every
// segment (which floods the reverse datagram path and starves data on a shared
// channel), it sends one ACK per ackEvery segments, immediately when urgent (an
// open gap or EOF), and otherwise arms a short timer the transmit loop flushes
// within ackDelay. This roughly halves datagram volume on a bulk transfer.
func (c *Conn) scheduleAck(urgent bool) {
	c.mu.Lock()
	c.segsSinceAck++
	if urgent || c.segsSinceAck >= ackEvery {
		c.segsSinceAck = 0
		c.ackPendingSince = time.Time{}
		ack := c.buildAckLocked()
		c.mu.Unlock()
		_ = c.dg.Send(ack)
		return
	}
	if c.ackPendingSince.IsZero() {
		c.ackPendingSince = time.Now()
	}
	c.mu.Unlock()
	c.nudgeTx() // let the transmit loop schedule the delayed flush
}

// rwndLocked is the receiver's free buffer in segments: the flow-control window
// advertised back to the sender. It counts both held out-of-order segments and
// delivered-but-unread bytes, so a slow reader throttles the sender and bounds
// memory on both ends. Caller holds c.mu.
func (c *Conn) rwndLocked() uint32 {
	used := uint32(len(c.rcvBuf)) + uint32(c.readBuf.Len()/c.cfg.MSS)
	if used >= c.maxRecvSeg {
		return 0
	}
	return c.maxRecvSeg - used
}

// advance delivers every contiguous buffered segment to readBuf and, once all
// data plus the FIN are in, marks EOF. Caller holds c.mu.
func (c *Conn) advance() {
	for {
		p, ok := c.rcvBuf[c.rcvNext]
		if !ok {
			break
		}
		c.readBuf.Write(p)
		delete(c.rcvBuf, c.rcvNext)
		c.rcvNext++
	}
	// FIN is a zero-length segment at finalSeq: once all data below it has been
	// delivered and the FIN has arrived, the stream is done.
	if c.rcvFin && !c.rcvEOF && c.rcvNext == c.rcvFinSeq {
		c.rcvEOF = true
		c.rcvNext++ // consume the FIN so our cumAck reflects it
		// A concurrent Close waits on sndCond for finAck; receiving the peer's
		// FIN is its signal to stop waiting for a FIN-ack that won't come.
		c.sndCond.Broadcast()
	}
	c.rcvCond.Broadcast()
}

// sackRangesLocked merges buffered out-of-order seqs into half-open ranges,
// keeping the lowest maxSackRanges (the gaps just above rcvNext matter most).
func (c *Conn) sackRangesLocked() []sackRange {
	if len(c.rcvBuf) == 0 {
		return nil
	}
	seqs := make([]uint32, 0, len(c.rcvBuf))
	for s := range c.rcvBuf {
		seqs = append(seqs, s)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	var ranges []sackRange
	start, prev := seqs[0], seqs[0]
	for _, s := range seqs[1:] {
		if s == prev+1 {
			prev = s
			continue
		}
		ranges = append(ranges, sackRange{start: start, end: prev + 1})
		start, prev = s, s
	}
	ranges = append(ranges, sackRange{start: start, end: prev + 1})
	if len(ranges) > maxSackRanges {
		ranges = ranges[:maxSackRanges]
	}
	return ranges
}

// ---------------------------------------------------------------------------
// ACK handling (send side)
// ---------------------------------------------------------------------------

// onAck retires cumulatively- and selectively-acked segments and updates the
// RTT estimate, then opens the window and nudges the transmit loop.
func (c *Conn) onAck(f frame) {
	c.mu.Lock()
	now := time.Now()

	c.rwnd = f.rwnd // peer's advertised free buffer drives flow control

	if seqLess(c.sndUna, f.cumAck) {
		for s := c.sndUna; seqLess(s, f.cumAck); s++ {
			if seg, ok := c.sndBuf[s]; ok {
				c.sampleRTTLocked(seg, now)
				c.observeLossLocked(seg)
				c.growCwndLocked()
				delete(c.sndBuf, s)
			}
		}
		c.sndUna = f.cumAck
	}
	for _, r := range f.sacks {
		for s := r.start; seqLess(s, r.end); s++ {
			if seg, ok := c.sndBuf[s]; ok {
				c.sampleRTTLocked(seg, now)
				c.observeLossLocked(seg)
				c.growCwndLocked()
				delete(c.sndBuf, s) // delivered out of order; never retransmit
			}
		}
	}
	c.markFastRetransmitLocked(f, now)

	if c.sndFin && seqLess(c.finSeq, c.sndUna) {
		c.finAck = true
	}
	if c.fecOn {
		c.enc.SetLoss(c.lossEWMA)
	}
	c.sndCond.Broadcast()
	c.mu.Unlock()
	c.nudgeTx()
}

// markFastRetransmitLocked flags any sent-but-unacked segment that the ACK shows
// is a true gap — at least dupThreshold higher seqs have been delivered while it
// has not — for immediate retransmit. SACK-driven loss detection retransmits
// real losses promptly instead of waiting for the RTO, which both lowers
// recovery latency and avoids the spurious-retransmit storm a too-tight RTO
// causes under a large unpaced window. Caller holds c.mu.
func (c *Conn) markFastRetransmitLocked(f frame, now time.Time) {
	hi := f.cumAck // highest delivered seq + 1
	for _, r := range f.sacks {
		if seqLess(hi, r.end) {
			hi = r.end
		}
	}
	cooldown := c.srtt
	if cooldown <= 0 {
		cooldown = c.cfg.MinRTO
	}
	for _, seg := range c.sndBuf {
		if seg.sentAt.IsZero() || seg.needsRex {
			continue
		}
		if !seqLess(seg.seq+dupThreshold, hi) {
			continue // fewer than dupThreshold delivered beyond it
		}
		// Flag a never-retransmitted gap immediately; re-flag an already
		// retransmitted one only after a cooldown so it cannot storm.
		if seg.xmits == 0 || now.Sub(seg.sentAt) >= cooldown {
			seg.needsRex = true
		}
	}
}

// growCwndLocked opens the congestion window for one acked segment: slow start
// below ssthresh, then congestion avoidance. Caller holds c.mu.
func (c *Conn) growCwndLocked() {
	if c.cwnd < c.ssthresh {
		c.cwnd++
	} else {
		c.cwnd += 1.0 / c.cwnd
	}
	if max := float64(c.cfg.Window); c.cwnd > max {
		c.cwnd = max
	}
}

// cutCwndLocked applies a gentle multiplicative decrease on a loss episode,
// rate-limited to once per RTT so a burst of drops is one cut. Caller holds c.mu.
func (c *Conn) cutCwndLocked(now time.Time) {
	gap := c.srtt
	if gap <= 0 {
		gap = c.cfg.MinRTO
	}
	if !c.lastLossCut.IsZero() && now.Sub(c.lastLossCut) < gap {
		return
	}
	c.lastLossCut = now
	// Loss ≠ congestion on this carrier: dip the window gently and, crucially,
	// leave ssthresh high so cwnd keeps recovering in fast slow-start growth
	// rather than collapsing into slow linear congestion-avoidance. The
	// loss-compensated pacer (rate ÷ (1-loss)) does the real work of holding
	// goodput; the window only needs to stay open.
	c.cwnd *= cwndLossDecrease
	if c.cwnd < minCwnd {
		c.cwnd = minCwnd
	}
}

// effWindowLocked is the current send ceiling: the min of cwnd, the peer's
// advertised rwnd, and the hard Window cap (floored at 1 for zero-window
// probing so a stalled receiver never deadlocks the sender). Caller holds c.mu.
func (c *Conn) effWindowLocked() uint32 {
	w := uint32(c.cwnd)
	if c.rwnd < w {
		w = c.rwnd
	}
	if w > c.cfg.Window {
		w = c.cfg.Window
	}
	if w < 1 {
		w = 1
	}
	return w
}

// pacingIntervalLocked is the gap between paced new transmissions: SRTT/cwnd,
// scaled by (1-loss) so the send rate is loss-compensated (rate/(1-loss)), like
// Brutal/ElasticCC. Zero when the pipe is effectively infinite (window-bound).
// Caller holds c.mu.
func (c *Conn) pacingIntervalLocked() time.Duration {
	srtt := c.srtt
	if srtt <= 0 {
		srtt = c.cfg.MinRTO
	}
	cw := c.cwnd
	if cw < 1 {
		cw = 1
	}
	iv := float64(srtt) * (1 - c.lossEWMA) / cw
	if iv < 0 {
		iv = 0
	}
	return time.Duration(iv)
}

// observeLossLocked folds one acked segment into the loss EWMA: a segment that
// was retransmitted before being acked counts as a loss. Caller holds c.mu.
func (c *Conn) observeLossLocked(seg *segment) {
	sample := 0.0
	if seg.xmits > 0 {
		sample = 1.0
	}
	if !c.lossInit {
		c.lossEWMA = sample
		c.lossInit = true
		return
	}
	c.lossEWMA = lossAlpha*sample + (1-lossAlpha)*c.lossEWMA
}

// sampleRTTLocked folds an acked segment's round trip into SRTT/RTTVAR using
// Karn's algorithm (skip retransmitted segments: the ACK is ambiguous) and
// recomputes the capped RTO. Caller holds c.mu.
func (c *Conn) sampleRTTLocked(seg *segment, now time.Time) {
	if seg.xmits != 0 || seg.sentAt.IsZero() {
		return
	}
	r := now.Sub(seg.sentAt)
	if r <= 0 {
		r = time.Microsecond
	}
	if c.srtt == 0 {
		c.srtt = r
		c.rttvar = r / 2
	} else {
		// RFC 6298 with alpha=1/8, beta=1/4.
		diff := c.srtt - r
		if diff < 0 {
			diff = -diff
		}
		c.rttvar = (3*c.rttvar + diff) / 4
		c.srtt = (7*c.srtt + r) / 8
	}
	rto := c.srtt + 4*c.rttvar
	if rto < c.cfg.MinRTO {
		rto = c.cfg.MinRTO
	}
	if rto > c.cfg.MaxRTO {
		rto = c.cfg.MaxRTO
	}
	c.rto = rto
}

// ---------------------------------------------------------------------------
// Transmit loop (first transmit + retransmit)
// ---------------------------------------------------------------------------

func (c *Conn) transmitLoop() {
	for {
		c.mu.Lock()
		if c.err != nil {
			c.mu.Unlock()
			return
		}
		// Terminal: our FIN is acked (or never needed) and nothing is in flight.
		if c.sndFin && c.finAck && len(c.sndBuf) == 0 {
			c.mu.Unlock()
			c.teardown(nil)
			return
		}

		now := time.Now()
		rto := c.rto
		var out [][]byte
		nextWake := now.Add(c.cfg.MaxRTO)
		segs := c.sortedSegmentsLocked()

		// Pass 1 — retransmits (fast-retransmit + RTO). These are the ARQ
		// fallback: sent as raw DATA frames (bypassing FEC) and not paced or
		// window-bound, because they free a stuck frontier. Count in-flight as
		// we go so pass 2 can respect the congestion window.
		inFlight := uint32(0)
		for _, seg := range segs {
			if seg.sentAt.IsZero() {
				continue
			}
			inFlight++
			if seg.needsRex || now.Sub(seg.sentAt) >= rto {
				out = append(out, encodeData(seg.seq, seg.payload))
				seg.sentAt = now
				seg.xmits++
				seg.needsRex = false
				c.st.retrans++
				c.cutCwndLocked(now)
				if d := now.Add(rto); d.Before(nextWake) {
					nextWake = d
				}
			} else if d := seg.sentAt.Add(rto); d.Before(nextWake) {
				nextWake = d
			}
		}

		// Pass 2 — new (unsent) segments: FEC-protected first transmissions,
		// bounded by the effective window and metered by the loss-compensated
		// pacer. Unsent segments are the high-seq tail in ascending order, so the
		// FEC encoder still groups contiguous seqs.
		effWin := c.effWindowLocked()
		for _, seg := range segs {
			if !seg.sentAt.IsZero() {
				continue
			}
			if inFlight >= effWin {
				break // congestion/flow window full
			}
			if now.Before(c.nextSend) {
				if c.nextSend.Before(nextWake) {
					nextWake = c.nextSend
				}
				break // pacer not ready
			}
			if c.fecOn {
				data, parity := c.enc.AddData(encodeData(seg.seq, seg.payload))
				out = append(out, data)
				if parity != nil {
					out = append(out, parity)
					c.st.parity++
				}
			} else {
				out = append(out, encodeData(seg.seq, seg.payload))
			}
			seg.sentAt = now
			c.st.sent++
			inFlight++
			base := c.nextSend
			if base.Before(now) {
				base = now
			}
			c.nextSend = base.Add(c.pacingIntervalLocked())
			if d := now.Add(rto); d.Before(nextWake) {
				nextWake = d
			}
		}
		// (Re)transmit FIN until the peer acks it.
		if c.sndFin && !c.finAck {
			if c.finSent.IsZero() || now.Sub(c.finSent) >= rto {
				out = append(out, encodeFin(c.finSeq))
				c.finSent = now
			}
			if d := c.finSent.Add(rto); d.Before(nextWake) {
				nextWake = d
			}
		}
		// Flush a delayed ACK whose timer has elapsed; otherwise schedule the
		// next wake to flush it on time.
		if !c.ackPendingSince.IsZero() {
			if now.Sub(c.ackPendingSince) >= ackDelay {
				out = append(out, c.buildAckLocked())
				c.ackPendingSince = time.Time{}
				c.segsSinceAck = 0
			} else if d := c.ackPendingSince.Add(ackDelay); d.Before(nextWake) {
				nextWake = d
			}
		}
		c.mu.Unlock()

		for _, b := range out {
			if err := c.dg.Send(b); err != nil {
				c.fail(fmt.Errorf("rudp: send: %w", err))
				return
			}
		}

		wait := time.Until(nextWake)
		if wait < 0 {
			wait = 0
		}
		timer := time.NewTimer(wait)
		select {
		case <-c.txWake:
			timer.Stop()
		case <-timer.C:
		case <-c.ctx.Done():
			timer.Stop()
			return
		}
	}
}

// sortedSegmentsLocked returns the retransmit buffer in seq order so loss
// recovery prefers the oldest gaps. Caller holds c.mu.
func (c *Conn) sortedSegmentsLocked() []*segment {
	segs := make([]*segment, 0, len(c.sndBuf))
	for _, s := range c.sndBuf {
		segs = append(segs, s)
	}
	sort.Slice(segs, func(i, j int) bool { return seqLess(segs[i].seq, segs[j].seq) })
	return segs
}

// ---------------------------------------------------------------------------
// net.Conn
// ---------------------------------------------------------------------------

// Write segments p into the send buffer, blocking while the in-flight window is
// full. It returns once every byte is queued (not once acked), per net.Conn.
func (c *Conn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sndFin {
		return 0, errClosed
	}
	written := 0
	for len(p) > 0 {
		for c.inFlightLocked() >= c.effWindowLocked() {
			if c.err != nil {
				return written, c.err
			}
			if c.sndFin {
				return written, errClosed
			}
			if !c.writeDeadline.IsZero() && !time.Now().Before(c.writeDeadline) {
				return written, timeoutError{}
			}
			c.sndCond.Wait()
		}
		if c.err != nil {
			return written, c.err
		}
		n := len(p)
		if n > c.cfg.MSS {
			n = c.cfg.MSS
		}
		seg := &segment{seq: c.sndNext, payload: append([]byte(nil), p[:n]...)}
		c.sndBuf[seg.seq] = seg
		c.sndNext++
		written += n
		p = p[n:]
		c.nudgeTx()
	}
	return written, nil
}

// inFlightLocked is the number of unacked segments. Caller holds c.mu.
func (c *Conn) inFlightLocked() uint32 { return uint32(len(c.sndBuf)) }

// Read returns delivered, in-order bytes, blocking until some are available,
// the stream ends (io.EOF), or an error/deadline fires.
func (c *Conn) Read(p []byte) (int, error) {
	c.mu.Lock()
	for {
		if c.readBuf.Len() > 0 {
			n, _ := c.readBuf.Read(p)
			// If reading just reopened a flow-control window that had closed,
			// send a window-update ACK so a stalled sender resumes promptly.
			windowUpdate := c.lastRwndAdv < c.maxRecvSeg/4 && c.rwndLocked() > c.lastRwndAdv
			c.mu.Unlock()
			if windowUpdate {
				c.sendAck()
			}
			return n, nil
		}
		if c.rcvEOF {
			c.mu.Unlock()
			return 0, io.EOF
		}
		if c.err != nil {
			c.mu.Unlock()
			return 0, c.err
		}
		if !c.readDeadline.IsZero() && !time.Now().Before(c.readDeadline) {
			c.mu.Unlock()
			return 0, timeoutError{}
		}
		c.rcvCond.Wait()
	}
}

// Close sends a FIN and blocks until the peer has acknowledged all data plus the
// FIN (so a lossy link still delivers the whole stream), then tears down the
// transport. It never blocks indefinitely:
//
//   - if the peer has already closed (we've seen its FIN) and all our own data
//     is acked, a FIN-ack is unnecessary — the peer is tearing down and may
//     never send one (the common half-close on a one-way bulk transfer), so we
//     return at once;
//   - a transport error unblocks it; and
//   - a linger timeout backstops the wait if the peer vanishes mid-transfer.
func (c *Conn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	if !c.sndFin {
		c.sndFin = true
		c.finSeq = c.sndNext
		c.sndCond.Broadcast() // unblock any pending Write
	}
	c.nudgeTx()

	lingerAt := time.Now().Add(closeLinger)
	timer := time.AfterFunc(closeLinger, func() { c.broadcast(c.sndCond) })
	defer timer.Stop()
	for !c.finAck && c.err == nil {
		if c.rcvEOF && len(c.sndBuf) == 0 {
			break // peer closed and all our data is acked; no FIN-ack will come
		}
		if !time.Now().Before(lingerAt) {
			break // linger expired; peer unresponsive, give up cleanly
		}
		c.sndCond.Wait()
	}
	err := c.err
	c.mu.Unlock()

	c.teardown(nil)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

// teardown cancels loops and closes the Datagram exactly once.
func (c *Conn) teardown(cause error) {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		if c.err == nil && cause != nil {
			c.err = cause
		}
		if c.rdTimer != nil {
			c.rdTimer.Stop()
		}
		if c.wrTimer != nil {
			c.wrTimer.Stop()
		}
		c.sndCond.Broadcast()
		c.rcvCond.Broadcast()
		c.mu.Unlock()
		c.cancel()
		_ = c.dg.Close()
	})
}

// LocalAddr / RemoteAddr report a placeholder rudp address. The underlying
// datagram transport owns the real path; consumers only need non-nil values.
func (c *Conn) LocalAddr() net.Addr  { return rudpAddr{} }
func (c *Conn) RemoteAddr() net.Addr { return rudpAddr{} }

func (c *Conn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	if c.rdTimer != nil {
		c.rdTimer.Stop()
		c.rdTimer = nil
	}
	if !t.IsZero() {
		c.rdTimer = time.AfterFunc(time.Until(t), func() { c.broadcast(c.rcvCond) })
	}
	c.rcvCond.Broadcast()
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	if c.wrTimer != nil {
		c.wrTimer.Stop()
		c.wrTimer = nil
	}
	if !t.IsZero() {
		c.wrTimer = time.AfterFunc(time.Until(t), func() { c.broadcast(c.sndCond) })
	}
	c.sndCond.Broadcast()
	return nil
}

// broadcast wakes a cond under the lock (used by deadline timers).
func (c *Conn) broadcast(cond *sync.Cond) {
	c.mu.Lock()
	cond.Broadcast()
	c.mu.Unlock()
}

// rudpAddr is the placeholder net.Addr for a rudp endpoint.
type rudpAddr struct{}

func (rudpAddr) Network() string { return "rudp" }
func (rudpAddr) String() string  { return "rudp" }

// timeoutError satisfies net.Error for deadline expiry.
type timeoutError struct{}

func (timeoutError) Error() string   { return "rudp: i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// seqLess reports a < b in 32-bit serial-number arithmetic (RFC 1982), so the
// comparison stays correct across the uint32 wraparound.
func seqLess(a, b uint32) bool { return int32(a-b) < 0 }
