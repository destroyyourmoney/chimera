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

	dataHeaderLen   = 4
	parityHeaderLen = 6
	feedbackLen     = 3
	lenPrefix       = 2

	maxTrackedGroups = 256

	lossEWMAAlpha = 0.2
)

type Encoder struct {
	mu          sync.Mutex
	groupSize   int
	pendingSize int
	group       uint16
	index       int
	block       []byte
	maxLen      int
}

func NewEncoder(loss float64) *Encoder {
	return &Encoder{groupSize: groupSizeFromLoss(loss)}
}

func (e *Encoder) SetLoss(loss float64) {
	e.mu.Lock()
	size := groupSizeFromLoss(loss)
	if e.index == 0 {

		e.groupSize = size
		e.pendingSize = 0
	} else {
		e.pendingSize = size
	}
	e.mu.Unlock()
}

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

	out[3] = byte(e.index)
	binary.BigEndian.PutUint16(out[4:6], uint16(blockLen))
	copy(out[parityHeaderLen:], e.block)
	return out
}

type Decoder struct {
	mu       sync.Mutex
	groups   map[uint16]*groupState
	order    []uint16
	lossEWMA float64
	lossInit bool
}

type groupState struct {
	count    int
	blockLen int
	parity   []byte
	data     map[uint8][]byte
	done     bool
	counted  bool
}

func NewDecoder(_ int) *Decoder {
	return &Decoder{groups: make(map[uint16]*groupState)}
}

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

func (d *Decoder) groupFor(gid uint16) *groupState {
	if g, ok := d.groups[gid]; ok {
		return g
	}
	if len(d.order) >= maxTrackedGroups {
		oldest := d.order[0]
		d.order = d.order[1:]
		if g, ok := d.groups[oldest]; ok {

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

func (d *Decoder) tryRecover(gid uint16, g *groupState) []byte {
	if g.done || g.parity == nil || g.count == 0 {
		return nil
	}
	if len(g.data) != g.count-1 {

		if len(g.data) >= g.count {
			d.finalize(g, 0)
			g.done = true
		}
		return nil
	}

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
		g.done = true
		return nil
	}
	out := append([]byte(nil), block[lenPrefix:lenPrefix+mlen]...)
	d.finalize(g, 1)
	g.done = true
	return out
}

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

func (d *Decoder) LossEstimate() float64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lossEWMA
}

func groupSizeFromLoss(loss float64) int {
	if loss <= 0 {
		return maxGroupSize
	}
	if loss >= 1 {
		return minGroupSize
	}
	n := int(1.0 / loss)
	if n < minGroupSize {
		return minGroupSize
	}
	if n > maxGroupSize {
		return maxGroupSize
	}
	return n
}

func IsParity(raw []byte) bool { return len(raw) > 0 && raw[0] == typeParity }

func IsData(raw []byte) bool { return len(raw) > 0 && raw[0] == typeData }

func IsFeedback(raw []byte) bool { return len(raw) > 0 && raw[0] == typeFeedback }

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
