package fec

import (
	"encoding/binary"
	"math/rand"
	"testing"
)

func TestEncoderNeverMisRecoversUnderAdaptiveLoss(t *testing.T) {
	rnd := rand.New(rand.NewSource(7))
	enc := NewEncoder(0.2)
	dec := NewDecoder(0)
	const total = 5000

	orig := make(map[uint32][]byte)
	mkPayload := func(seq uint32) []byte {
		n := 20 + rnd.Intn(60)
		b := make([]byte, n)
		binary.BigEndian.PutUint32(b, seq)
		for i := 4; i < n; i++ {
			b[i] = byte(seq) ^ byte(i)
		}
		return b
	}

	var wire [][]byte
	deliver := func(raw []byte) {
		payload, isData, recovered := dec.Add(raw)
		check := func(p []byte) {
			if len(p) < 4 {
				t.Fatalf("recovered too short: %x", p)
			}
			seq := binary.BigEndian.Uint32(p)
			want, ok := orig[seq]
			if !ok {
				t.Fatalf("payload for unknown seq %d: %x", seq, p)
			}
			if string(p) != string(want) {
				t.Fatalf("mis-recovery seq %d: got %x want %x", seq, p, want)
			}
		}
		if isData {
			check(payload)
		}
		if recovered != nil {
			check(recovered)
		}
	}

	for seq := uint32(0); seq < total; seq++ {
		if seq%200 == 0 {
			enc.SetLoss(0.1 + 0.3*rnd.Float64())
		}
		p := mkPayload(seq)
		orig[seq] = p
		data, parity := enc.AddData(p)
		for _, f := range [][]byte{data, parity} {
			if f == nil {
				continue
			}
			if rnd.Float64() < 0.2 {
				continue
			}
			wire = append(wire, append([]byte(nil), f...))
			if rnd.Float64() < 0.1 {
				wire = append(wire, append([]byte(nil), f...))
			}
			if len(wire) > 16 {
				rnd.Shuffle(len(wire), func(i, j int) { wire[i], wire[j] = wire[j], wire[i] })
				for _, w := range wire {
					deliver(w)
				}
				wire = wire[:0]
			}
		}
	}
	for _, w := range wire {
		deliver(w)
	}
}
