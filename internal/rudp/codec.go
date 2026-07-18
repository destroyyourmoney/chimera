package rudp

import "encoding/binary"

type frameType byte

const (
	fData   frameType = 0x10
	fParity frameType = 0x11
	fAck    frameType = 0x12
	fFin    frameType = 0x13
)

const maxSackRanges = 4

type sackRange struct {
	start, end uint32
}

type frame struct {
	typ          frameType
	seq          uint32
	payload      []byte
	cumAck       uint32
	sacks        []sackRange
	lossPermille uint16
	rwnd         uint32
}

func encodeData(seq uint32, payload []byte) []byte {
	out := make([]byte, 7+len(payload))
	out[0] = byte(fData)
	binary.BigEndian.PutUint32(out[1:5], seq)
	binary.BigEndian.PutUint16(out[5:7], uint16(len(payload)))
	copy(out[7:], payload)
	return out
}

func encodeFin(finalSeq uint32) []byte {
	out := make([]byte, 5)
	out[0] = byte(fFin)
	binary.BigEndian.PutUint32(out[1:5], finalSeq)
	return out
}

func encodeAck(cumAck uint32, sacks []sackRange, lossPermille uint16, rwnd uint32) []byte {
	if len(sacks) > maxSackRanges {
		sacks = sacks[:maxSackRanges]
	}
	out := make([]byte, 6+len(sacks)*8+2+4)
	out[0] = byte(fAck)
	binary.BigEndian.PutUint32(out[1:5], cumAck)
	out[5] = byte(len(sacks))
	off := 6
	for _, s := range sacks {
		binary.BigEndian.PutUint32(out[off:off+4], s.start)
		binary.BigEndian.PutUint32(out[off+4:off+8], s.end)
		off += 8
	}
	binary.BigEndian.PutUint16(out[off:off+2], lossPermille)
	off += 2
	binary.BigEndian.PutUint32(out[off:off+4], rwnd)
	return out
}

func decodeFrame(raw []byte) (f frame, ok bool) {
	if len(raw) == 0 {
		return frame{}, false
	}
	switch frameType(raw[0]) {
	case fData:
		if len(raw) < 7 {
			return frame{}, false
		}
		n := int(binary.BigEndian.Uint16(raw[5:7]))
		if len(raw) < 7+n {
			return frame{}, false
		}
		return frame{
			typ:     fData,
			seq:     binary.BigEndian.Uint32(raw[1:5]),
			payload: append([]byte(nil), raw[7:7+n]...),
		}, true
	case fFin:
		if len(raw) < 5 {
			return frame{}, false
		}
		return frame{typ: fFin, seq: binary.BigEndian.Uint32(raw[1:5])}, true
	case fAck:
		if len(raw) < 6 {
			return frame{}, false
		}
		nSack := int(raw[5])
		if len(raw) < 6+nSack*8+2+4 {
			return frame{}, false
		}
		sacks := make([]sackRange, nSack)
		off := 6
		for i := range sacks {
			sacks[i] = sackRange{
				start: binary.BigEndian.Uint32(raw[off : off+4]),
				end:   binary.BigEndian.Uint32(raw[off+4 : off+8]),
			}
			off += 8
		}
		loss := binary.BigEndian.Uint16(raw[off : off+2])
		off += 2
		return frame{
			typ:          fAck,
			cumAck:       binary.BigEndian.Uint32(raw[1:5]),
			sacks:        sacks,
			lossPermille: loss,
			rwnd:         binary.BigEndian.Uint32(raw[off : off+4]),
		}, true
	default:

		return frame{}, false
	}
}
