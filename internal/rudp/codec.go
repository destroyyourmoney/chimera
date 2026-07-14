package rudp

import "encoding/binary"

// Wire format. Each rudp datagram is exactly one frame, tagged by its first
// byte. rudp runs its own datagram stream, independent of (and never layered
// over) any reliable QUIC stream.
//
//	DATA   : [0x10 | seq:4    | len:2 | payload(len) ]
//	PARITY : [0x11 | group:4  | k:1   | idx:1 | blockLen:2 | parityBlock ]  (FEC, phase 2)
//	ACK    : [0x12 | cumAck:4 | nSack:1 | (sackStart:4, sackEnd:4)*nSack | lossPermille:2 | rwnd:4 ]
//	FIN    : [0x13 | finalSeq:4 ]
//
// rwnd is the receiver's free buffer space in segments (flow control, phase 3):
// the sender keeps new-segment in-flight ≤ rwnd so receiver memory stays bounded.
//
// seq numbers DATA segments monotonically. cumAck is the next in-order seq the
// receiver still needs (everything below it has been delivered). SACK ranges
// are half-open [start,end) spans of received-but-not-yet-contiguous seqs, so
// the sender retransmits only true gaps. finalSeq is the FIN's own seq (one
// past the last DATA seq); the receiver treats FIN as a zero-length segment at
// that seq, so a clean close is just the stream reaching finalSeq+1.
type frameType byte

const (
	fData   frameType = 0x10
	fParity frameType = 0x11
	fAck    frameType = 0x12
	fFin    frameType = 0x13
)

// maxSackRanges bounds the SACK block count in an ACK frame. SACK is purely an
// optimization (it never affects correctness), so a small cap keeps ACKs tiny.
const maxSackRanges = 4

// sackRange is a half-open [start, end) span of contiguously received seqs.
type sackRange struct {
	start, end uint32
}

// frame is the decoded form of any rudp datagram. Only the fields relevant to
// typ are populated.
type frame struct {
	typ          frameType
	seq          uint32      // fData: segment seq; fFin: finalSeq
	payload      []byte      // fData
	cumAck       uint32      // fAck
	sacks        []sackRange // fAck
	lossPermille uint16      // fAck
	rwnd         uint32      // fAck: receiver free buffer in segments (flow control)
}

// encodeData builds a DATA frame for seq carrying payload.
func encodeData(seq uint32, payload []byte) []byte {
	out := make([]byte, 7+len(payload))
	out[0] = byte(fData)
	binary.BigEndian.PutUint32(out[1:5], seq)
	binary.BigEndian.PutUint16(out[5:7], uint16(len(payload)))
	copy(out[7:], payload)
	return out
}

// encodeFin builds a FIN frame whose finalSeq is the FIN's own seq.
func encodeFin(finalSeq uint32) []byte {
	out := make([]byte, 5)
	out[0] = byte(fFin)
	binary.BigEndian.PutUint32(out[1:5], finalSeq)
	return out
}

// encodeAck builds an ACK frame. At most maxSackRanges ranges are emitted.
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

// decodeFrame parses one rudp datagram. ok is false for malformed or unknown
// frames, which the caller drops.
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
		// PARITY (0x11) is decoded by the FEC layer in phase 2; treat as
		// unknown here so phase-1 builds drop it cleanly.
		return frame{}, false
	}
}
