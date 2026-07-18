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

const (
	defaultMSS    = 1100
	defaultWindow = 2048
	defaultMinRTO = 30 * time.Millisecond
	defaultMaxRTO = 1 * time.Second

	fecInitLoss = 0.05

	lossAlpha = 1.0 / 32.0

	initCwnd          = 16.0
	minCwnd           = 4.0
	cwndLossDecrease  = 0.85
	dupThreshold      = 3
	defaultMaxRecvSeg = 4096

	closeLinger = 30 * time.Second

	ackEvery = 8
	ackDelay = 4 * time.Millisecond
)

type Config struct {
	MSS    int
	Window uint32
	MinRTO time.Duration
	MaxRTO time.Duration

	FEC bool

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

type segment struct {
	seq      uint32
	payload  []byte
	sentAt   time.Time
	xmits    int
	needsRex bool
}

type Conn struct {
	dg  Datagram
	cfg Config

	ctx    context.Context
	cancel context.CancelFunc

	mu sync.Mutex

	sndUna  uint32
	sndNext uint32
	sndBuf  map[uint32]*segment
	sndCond *sync.Cond
	sndFin  bool
	finSeq  uint32
	finSent time.Time
	finAck  bool

	srtt   time.Duration
	rttvar time.Duration
	rto    time.Duration

	cwnd        float64
	ssthresh    float64
	rwnd        uint32
	nextSend    time.Time
	lastLossCut time.Time

	lossEWMA float64
	lossInit bool

	rcvNext         uint32
	rcvBuf          map[uint32][]byte
	readBuf         bytes.Buffer
	rcvCond         *sync.Cond
	rcvFin          bool
	rcvFinSeq       uint32
	rcvEOF          bool
	maxRecvSeg      uint32
	lastRwndAdv     uint32
	segsSinceAck    int
	ackPendingSince time.Time

	fecOn bool
	enc   *fec.Encoder
	dec   *fec.Decoder
	st    stats

	txWake    chan struct{}
	err       error
	closed    bool
	closeOnce sync.Once

	readDeadline  time.Time
	writeDeadline time.Time
	rdTimer       *time.Timer
	wrTimer       *time.Timer
}

type stats struct {
	sent         uint64
	retrans      uint64
	parity       uint64
	fecRecovered uint64
}

type Stats struct {
	Sent         uint64
	Retransmits  uint64
	ParitySent   uint64
	FECRecovered uint64
}

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

var errClosed = errors.New("rudp: connection closed")

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
		rwnd:       cfg.MaxRecvSegments,
		maxRecvSeg: cfg.MaxRecvSegments,
	}
	if c.fecOn {

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

func (c *Conn) nudgeTx() {
	select {
	case c.txWake <- struct{}{}:
	default:
	}
}

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

		urgent := c.applyInner(raw, false)
		c.scheduleAck(urgent)
	}
}

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
			return false
		}
		if _, dup := c.rcvBuf[f.seq]; dup {
			return false
		}
		if recovered {
			c.st.fecRecovered++
		}
		c.rcvBuf[f.seq] = f.payload
		c.advance()
		return len(c.rcvBuf) > 0
	case fFin:
		c.rcvFin = true
		c.rcvFinSeq = f.seq
		c.advance()
		return true
	}
	return false
}

func (c *Conn) buildAckLocked() []byte {
	var loss uint16
	if c.fecOn {
		loss = uint16(c.dec.LossEstimate()*1000 + 0.5)
	}
	rwnd := c.rwndLocked()
	c.lastRwndAdv = rwnd
	return encodeAck(c.rcvNext, c.sackRangesLocked(), loss, rwnd)
}

func (c *Conn) sendAck() {
	c.mu.Lock()
	ack := c.buildAckLocked()
	c.mu.Unlock()
	_ = c.dg.Send(ack)
}

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
	c.nudgeTx()
}

func (c *Conn) rwndLocked() uint32 {
	used := uint32(len(c.rcvBuf)) + uint32(c.readBuf.Len()/c.cfg.MSS)
	if used >= c.maxRecvSeg {
		return 0
	}
	return c.maxRecvSeg - used
}

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

	if c.rcvFin && !c.rcvEOF && c.rcvNext == c.rcvFinSeq {
		c.rcvEOF = true
		c.rcvNext++

		c.sndCond.Broadcast()
	}
	c.rcvCond.Broadcast()
}

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

func (c *Conn) onAck(f frame) {
	c.mu.Lock()
	now := time.Now()

	c.rwnd = f.rwnd

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
				delete(c.sndBuf, s)
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

func (c *Conn) markFastRetransmitLocked(f frame, now time.Time) {
	hi := f.cumAck
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
			continue
		}

		if seg.xmits == 0 || now.Sub(seg.sentAt) >= cooldown {
			seg.needsRex = true
		}
	}
}

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

func (c *Conn) cutCwndLocked(now time.Time) {
	gap := c.srtt
	if gap <= 0 {
		gap = c.cfg.MinRTO
	}
	if !c.lastLossCut.IsZero() && now.Sub(c.lastLossCut) < gap {
		return
	}
	c.lastLossCut = now

	c.cwnd *= cwndLossDecrease
	if c.cwnd < minCwnd {
		c.cwnd = minCwnd
	}
}

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

func (c *Conn) transmitLoop() {
	for {
		c.mu.Lock()
		if c.err != nil {
			c.mu.Unlock()
			return
		}

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

		effWin := c.effWindowLocked()
		for _, seg := range segs {
			if !seg.sentAt.IsZero() {
				continue
			}
			if inFlight >= effWin {
				break
			}
			if now.Before(c.nextSend) {
				if c.nextSend.Before(nextWake) {
					nextWake = c.nextSend
				}
				break
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

		if c.sndFin && !c.finAck {
			if c.finSent.IsZero() || now.Sub(c.finSent) >= rto {
				out = append(out, encodeFin(c.finSeq))
				c.finSent = now
			}
			if d := c.finSent.Add(rto); d.Before(nextWake) {
				nextWake = d
			}
		}

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

func (c *Conn) sortedSegmentsLocked() []*segment {
	segs := make([]*segment, 0, len(c.sndBuf))
	for _, s := range c.sndBuf {
		segs = append(segs, s)
	}
	sort.Slice(segs, func(i, j int) bool { return seqLess(segs[i].seq, segs[j].seq) })
	return segs
}

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

func (c *Conn) inFlightLocked() uint32 { return uint32(len(c.sndBuf)) }

func (c *Conn) Read(p []byte) (int, error) {
	c.mu.Lock()
	for {
		if c.readBuf.Len() > 0 {
			n, _ := c.readBuf.Read(p)

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

func (c *Conn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	if !c.sndFin {
		c.sndFin = true
		c.finSeq = c.sndNext
		c.sndCond.Broadcast()
	}
	c.nudgeTx()

	lingerAt := time.Now().Add(closeLinger)
	timer := time.AfterFunc(closeLinger, func() { c.broadcast(c.sndCond) })
	defer timer.Stop()
	for !c.finAck && c.err == nil {
		if c.rcvEOF && len(c.sndBuf) == 0 {
			break
		}
		if !time.Now().Before(lingerAt) {
			break
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

func (c *Conn) broadcast(cond *sync.Cond) {
	c.mu.Lock()
	cond.Broadcast()
	c.mu.Unlock()
}

type rudpAddr struct{}

func (rudpAddr) Network() string { return "rudp" }
func (rudpAddr) String() string  { return "rudp" }

type timeoutError struct{}

func (timeoutError) Error() string   { return "rudp: i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func seqLess(a, b uint32) bool { return int32(a-b) < 0 }
