// Package fec implements an adaptive XOR-based forward error correction layer
// for QUIC datagram payloads.
//
// Why XOR FEC here, not RaptorQ/RS?
// RaptorQ and Reed-Solomon require matrix arithmetic over GF(2^8) — the kind of
// thing that is excellent as a library but painful to inline without an external
// dependency. The XOR scheme below is the classical "1 parity block per N data
// blocks" approach: it can recover any single erasure within a group. It is
// well-understood, zero-dependency, constant-time to encode, and provides real
// protection for 5–15 % loss rates (1 in N chance of two concurrent losses) —
// the regime where CHIMERA's ElasticCC already keeps the link alive.
//
// The adaptive part: the group size N is inversely proportional to the measured
// loss rate. More loss → smaller groups → higher overhead → better recovery.
// Range: N ∈ [2, 64]; overhead at 20 % loss ≈ 33 % (N=3), at 5 % ≈ 11 % (N=9).
//
// # Wire framing
//
// Unlike a naive XOR scheme, this layer carries enough framing to operate on a
// live, unreliable, out-of-order datagram stream (not just a controlled test
// where exactly one packet is dropped). Every datagram emitted onto the QUIC
// DATAGRAM channel is one of two frame types, distinguished by the first byte:
//
//	data:   [0x00][group:2][index:1][payload...]
//	parity: [0x01][group:2][count:1][blockLen:2][parityBlock...]
//
// To recover a *variable-length* missing payload, each payload is treated as a
// length-prefixed block [origLen:2 | payload] zero-padded to the group's longest
// block, and the parity is the XOR of those blocks. On recovery the missing
// block = parity XOR (the received blocks); its first two bytes give the exact
// original length, so the recovered payload is trimmed precisely.
//
// # Integration
//
// The sender wraps each QUIC datagram send with Encoder.AddData (emitting the
// data frame plus, once per group, a parity frame). The receiver feeds every
// incoming frame to Decoder.Add, which returns the carried payload (for data
// frames) and/or a recovered payload (when a group's single erasure can be
// reconstructed). Both Encoder and Decoder are safe for concurrent use.
package fec

import (
	"encoding/binary"
	"sync"
)

const (
	minGroupSize = 2
	maxGroupSize = 64

	typeData     = 0x00
	typeParity   = 0x01
	typeFeedback = 0x02

	dataHeaderLen   = 4 // type(1) + group(2) + index(1)
	parityHeaderLen = 6 // type(1) + group(2) + count(1) + blockLen(2)
	feedbackLen     = 3 // type(1) + lossPermille(2)
	lenPrefix       = 2 // per-payload length prefix inside a block

	// maxTrackedGroups bounds decoder memory: groups that never complete (≥2
	// erasures, or whose parity is itself lost) are evicted oldest-first.
	maxTrackedGroups = 256

	// lossEWMAAlpha smooths the per-group loss observations into the running
	// estimate the receiver feeds back to the sender.
	lossEWMAAlpha = 0.2
)

// Encoder XOR-encodes datagrams into groups, emitting a parity datagram after
// every N data datagrams. N adapts to the measured loss rate via SetLoss.
type Encoder struct {
	mu          sync.Mutex
	groupSize   int
	pendingSize int // group size to adopt at the next boundary (0 = none queued)
	group       uint16
	index       int
	block       []byte // running XOR of length-prefixed, zero-padded blocks
	maxLen      int    // longest payload seen in the current group
}

// NewEncoder creates an Encoder with initial group size derived from loss (0–1).
func NewEncoder(loss float64) *Encoder {
	return &Encoder{groupSize: groupSizeFromLoss(loss)}
}

// SetLoss updates the group size based on the current measured loss rate (0–1).
// The change is queued and takes effect only at the next group boundary: a group
// must close with the same N it opened with, or the parity's advertised count
// would not match the number of blocks actually folded into it and the decoder
// would mis-reconstruct an erasure.
func (e *Encoder) SetLoss(loss float64) {
	e.mu.Lock()
	size := groupSizeFromLoss(loss)
	if e.index == 0 {
		// At a group boundary already (no blocks folded yet): adopt immediately.
		e.groupSize = size
		e.pendingSize = 0
	} else {
		e.pendingSize = size
	}
	e.mu.Unlock()
}

// AddData frames payload as a data frame and folds it into the running parity.
// It returns the data frame to send, and — once a group of N is complete — the
// parity frame to send as well (nil otherwise). Returned slices are owned by the
// caller. payload is the opaque application datagram (e.g. an assocID-prefixed
// UDP packet); it is sent verbatim inside the data frame.
func (e *Encoder) AddData(payload []byte) (data, parity []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()

	data = make([]byte, dataHeaderLen+len(payload))
	data[0] = typeData
	binary.BigEndian.PutUint16(data[1:3], e.group)
	data[3] = byte(e.index)
	copy(data[dataHeaderLen:], payload)

	e.foldBlock(payload)
	e.index++
	if e.index < e.groupSize {
		return data, nil
	}

	parity = e.makeParity()
	// Advance to the next group, adopting any queued size change now that the
	// group has closed (so N stays constant within a group).
	e.group++
	e.index = 0
	e.block = e.block[:0]
	e.maxLen = 0
	if e.pendingSize != 0 {
		e.groupSize = e.pendingSize
		e.pendingSize = 0
	}
	return data, parity
}

// foldBlock XORs the length-prefixed form of payload into the running parity.
func (e *Encoder) foldBlock(payload []byte) {
	need := lenPrefix + len(payload)
	if need > len(e.block) {
		grown := make([]byte, need)
		copy(grown, e.block)
		e.block = grown
	}
	if len(payload) > e.maxLen {
		e.maxLen = len(payload)
	}
	var lp [lenPrefix]byte
	binary.BigEndian.PutUint16(lp[:], uint16(len(payload)))
	e.block[0] ^= lp[0]
	e.block[1] ^= lp[1]
	for i, b := range payload {
		e.block[lenPrefix+i] ^= b
	}
}

func (e *Encoder) makeParity() []byte {
	blockLen := lenPrefix + e.maxLen
	out := make([]byte, parityHeaderLen+blockLen)
	out[0] = typeParity
	binary.BigEndian.PutUint16(out[1:3], e.group)
	// Advertise the actual number of blocks folded into this parity (e.index),
	// not the configured group size: if the size ever changed mid-group the two
	// would differ and the decoder would XOR against the wrong survivor count.
	out[3] = byte(e.index)
	binary.BigEndian.PutUint16(out[4:6], uint16(blockLen))
	copy(out[parityHeaderLen:], e.block) // e.block may be shorter; trailing stays zero
	return out
}

// Decoder reassembles groups from incoming data and parity frames and recovers
// the single erased payload in any group that arrives with N-1 data frames plus
// its parity frame. Thread-safe.
type Decoder struct {
	mu       sync.Mutex
	groups   map[uint16]*groupState
	order    []uint16 // insertion order, for oldest-first eviction
	lossEWMA float64  // smoothed observed loss over finalized parity-anchored groups
	lossInit bool
}

type groupState struct {
	count    int              // N; 0 until the parity frame is seen
	blockLen int              // parity block length; 0 until parity seen
	parity   []byte           // parity block bytes; nil until seen
	data     map[uint8][]byte // index → payload
	done     bool             // recovery already emitted / group complete
	counted  bool             // already folded into the loss estimate
}

// NewDecoder creates an empty Decoder. The optional groupSize argument is
// accepted for API compatibility but ignored: the authoritative N is carried in
// each parity frame, so the decoder learns it per group.
func NewDecoder(_ int) *Decoder {
	return &Decoder{groups: make(map[uint16]*groupState)}
}

// Add ingests one incoming frame. For a data frame it returns the carried
// payload (isData=true). Whenever a group becomes recoverable it also returns
// the reconstructed payload in recovered (nil otherwise). A parity frame yields
// isData=false and only possibly a recovered payload.
func (d *Decoder) Add(raw []byte) (payload []byte, isData bool, recovered []byte) {
	if len(raw) == 0 {
		return nil, false, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	switch raw[0] {
	case typeData:
		if len(raw) < dataHeaderLen {
			return nil, false, nil
		}
		gid := binary.BigEndian.Uint16(raw[1:3])
		idx := raw[3]
		p := append([]byte(nil), raw[dataHeaderLen:]...)
		g := d.groupFor(gid)
		if !g.done {
			g.data[idx] = p
		}
		return p, true, d.tryRecover(gid, g)
	case typeParity:
		if len(raw) < parityHeaderLen {
			return nil, false, nil
		}
		gid := binary.BigEndian.Uint16(raw[1:3])
		g := d.groupFor(gid)
		if !g.done {
			g.count = int(raw[3])
			g.blockLen = int(binary.BigEndian.Uint16(raw[4:6]))
			g.parity = append([]byte(nil), raw[parityHeaderLen:]...)
		}
		return nil, false, d.tryRecover(gid, g)
	default:
		return nil, false, nil
	}
}

// groupFor returns the state for gid, creating it (and evicting the oldest group
// if the tracking window is full) when first seen.
func (d *Decoder) groupFor(gid uint16) *groupState {
	if g, ok := d.groups[gid]; ok {
		return g
	}
	if len(d.order) >= maxTrackedGroups {
		oldest := d.order[0]
		d.order = d.order[1:]
		if g, ok := d.groups[oldest]; ok {
			// A parity-anchored group evicted unresolved lost ≥2 packets; fold
			// that into the loss estimate before discarding it.
			if g.count > 0 && !g.counted {
				missing := g.count - len(g.data)
				if missing < 0 {
					missing = 0
				}
				d.finalize(g, missing)
			}
			delete(d.groups, oldest)
		}
	}
	g := &groupState{data: make(map[uint8][]byte)}
	d.groups[gid] = g
	d.order = append(d.order, gid)
	return g
}

// tryRecover reconstructs the single missing payload when a group has its parity
// plus exactly N-1 of N data frames. Returns nil otherwise.
func (d *Decoder) tryRecover(gid uint16, g *groupState) []byte {
	if g.done || g.parity == nil || g.count == 0 {
		return nil
	}
	if len(g.data) != g.count-1 {
		// All N present (nothing to recover) or ≥2 missing (cannot recover).
		if len(g.data) >= g.count {
			d.finalize(g, 0) // no erasure observed for this group
			g.done = true    // free further work; data already delivered live
		}
		return nil
	}
	// block = parity XOR (length-prefixed blocks of the received payloads).
	block := make([]byte, g.blockLen)
	copy(block, g.parity)
	for _, p := range g.data {
		var lp [lenPrefix]byte
		binary.BigEndian.PutUint16(lp[:], uint16(len(p)))
		if g.blockLen >= lenPrefix {
			block[0] ^= lp[0]
			block[1] ^= lp[1]
		}
		for i, b := range p {
			if lenPrefix+i < len(block) {
				block[lenPrefix+i] ^= b
			}
		}
	}
	if len(block) < lenPrefix {
		g.done = true
		return nil
	}
	mlen := int(binary.BigEndian.Uint16(block[:lenPrefix]))
	if lenPrefix+mlen > len(block) {
		g.done = true // corrupt/length mismatch; refuse to emit garbage
		return nil
	}
	out := append([]byte(nil), block[lenPrefix:lenPrefix+mlen]...)
	d.finalize(g, 1) // exactly one erasure, recovered
	g.done = true
	return out
}

// finalize folds one finalized parity-anchored group's loss (missing/N) into the
// running EWMA. Idempotent per group via the counted flag. Caller holds d.mu.
func (d *Decoder) finalize(g *groupState, missing int) {
	if g.counted || g.count == 0 {
		return
	}
	g.counted = true
	loss := float64(missing) / float64(g.count)
	if !d.lossInit {
		d.lossEWMA = loss
		d.lossInit = true
		return
	}
	d.lossEWMA = lossEWMAAlpha*loss + (1-lossEWMAAlpha)*d.lossEWMA
}

// LossEstimate returns the receiver's smoothed observed loss rate [0,1], suitable
// for transport back to the sender via MakeFeedback. Zero until the first
// parity-anchored group is finalized.
func (d *Decoder) LossEstimate() float64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lossEWMA
}

// groupSizeFromLoss maps loss rate [0,1] to group size [minGroupSize, maxGroupSize].
// Higher loss → smaller group → higher redundancy.
func groupSizeFromLoss(loss float64) int {
	if loss <= 0 {
		return maxGroupSize
	}
	if loss >= 1 {
		return minGroupSize
	}
	n := int(1.0 / loss) // N ≈ 1/loss, clamped
	if n < minGroupSize {
		return minGroupSize
	}
	if n > maxGroupSize {
		return maxGroupSize
	}
	return n
}

// IsParity reports whether raw is a parity frame.
func IsParity(raw []byte) bool { return len(raw) > 0 && raw[0] == typeParity }

// IsData reports whether raw is a data frame.
func IsData(raw []byte) bool { return len(raw) > 0 && raw[0] == typeData }

// IsFeedback reports whether raw is a loss-feedback frame.
func IsFeedback(raw []byte) bool { return len(raw) > 0 && raw[0] == typeFeedback }

// MakeFeedback encodes an observed loss rate [0,1] as a feedback frame for the
// peer's Encoder. Loss is carried in per-mille (0–1000) — ample resolution for
// FEC group sizing while keeping the frame tiny.
func MakeFeedback(loss float64) []byte {
	if loss < 0 {
		loss = 0
	}
	if loss > 1 {
		loss = 1
	}
	out := make([]byte, feedbackLen)
	out[0] = typeFeedback
	binary.BigEndian.PutUint16(out[1:3], uint16(loss*1000+0.5))
	return out
}

// ParseFeedback decodes a feedback frame into a loss rate [0,1]. ok=false if raw
// is not a well-formed feedback frame.
func ParseFeedback(raw []byte) (loss float64, ok bool) {
	if len(raw) < feedbackLen || raw[0] != typeFeedback {
		return 0, false
	}
	permille := binary.BigEndian.Uint16(raw[1:3])
	if permille > 1000 {
		permille = 1000
	}
	return float64(permille) / 1000.0, true
}
