package rudp

import (
	"bytes"
	"testing"
)

func TestCodecDataRoundTrip(t *testing.T) {
	for _, payload := range [][]byte{nil, {}, []byte("x"), bytes.Repeat([]byte{0xAB}, 1100)} {
		raw := encodeData(0xDEADBEEF, payload)
		f, ok := decodeFrame(raw)
		if !ok || f.typ != fData {
			t.Fatalf("decode data failed: ok=%v typ=%x", ok, f.typ)
		}
		if f.seq != 0xDEADBEEF {
			t.Fatalf("seq = %x, want DEADBEEF", f.seq)
		}
		if !bytes.Equal(f.payload, payload) {
			t.Fatalf("payload = %x, want %x", f.payload, payload)
		}
	}
}

func TestCodecFinRoundTrip(t *testing.T) {
	raw := encodeFin(12345)
	f, ok := decodeFrame(raw)
	if !ok || f.typ != fFin || f.seq != 12345 {
		t.Fatalf("fin round-trip: ok=%v typ=%x seq=%d", ok, f.typ, f.seq)
	}
}

func TestCodecAckRoundTrip(t *testing.T) {
	sacks := []sackRange{{10, 15}, {20, 21}}
	raw := encodeAck(7, sacks, 333, 4096)
	f, ok := decodeFrame(raw)
	if !ok || f.typ != fAck {
		t.Fatalf("decode ack failed: ok=%v typ=%x", ok, f.typ)
	}
	if f.cumAck != 7 || f.lossPermille != 333 || f.rwnd != 4096 {
		t.Fatalf("ack fields: cumAck=%d loss=%d rwnd=%d", f.cumAck, f.lossPermille, f.rwnd)
	}
	if len(f.sacks) != 2 || f.sacks[0] != (sackRange{10, 15}) || f.sacks[1] != (sackRange{20, 21}) {
		t.Fatalf("sacks = %+v", f.sacks)
	}
}

func TestCodecAckCapsSackRanges(t *testing.T) {
	many := make([]sackRange, 10)
	for i := range many {
		many[i] = sackRange{uint32(i * 2), uint32(i*2 + 1)}
	}
	f, ok := decodeFrame(encodeAck(0, many, 0, 0))
	if !ok || len(f.sacks) != maxSackRanges {
		t.Fatalf("expected %d sacks, got ok=%v n=%d", maxSackRanges, ok, len(f.sacks))
	}
}

func TestCodecRejectsTruncatedAndUnknown(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{byte(fData), 0, 0},             // too short for header
		{byte(fData), 0, 0, 0, 0, 0, 5}, // len says 5, no payload
		{byte(fFin), 0, 0},              // short fin
		{byte(fAck), 0, 0, 0, 0, 9},     // nSack=9, no ranges
		{byte(fAck), 0, 0, 0, 0, 0, 0},  // nSack=0 but missing rwnd tail
		{byte(fParity), 1, 2, 3},        // phase-2 frame, dropped in phase 1
		{0xFF, 1, 2},                    // unknown type
	}
	for i, raw := range cases {
		if _, ok := decodeFrame(raw); ok {
			t.Fatalf("case %d: expected reject, got ok", i)
		}
	}
}

func TestSeqLessWraparound(t *testing.T) {
	if !seqLess(0xFFFFFFFF, 0) {
		t.Fatal("0xFFFFFFFF should be < 0 across wrap")
	}
	if seqLess(0, 0xFFFFFFFF) {
		t.Fatal("0 should not be < 0xFFFFFFFF across wrap")
	}
	if seqLess(5, 5) {
		t.Fatal("equal seqs are not less")
	}
}
