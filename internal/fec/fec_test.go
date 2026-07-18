package fec

import (
	"bytes"
	"testing"
)

func TestEncoder_EmitsParityAfterGroup(t *testing.T) {
	enc := NewEncoder(0)
	enc.SetLoss(0.5)

	if _, parity := enc.AddData([]byte{0x01, 0x02, 0x03}); parity != nil {
		t.Fatal("parity emitted too early (after 1 of 2 packets)")
	}
	data, parity := enc.AddData([]byte{0x04, 0x05, 0x06})
	if !IsData(data) {
		t.Fatal("data frame not marked as data")
	}
	if parity == nil {
		t.Fatal("parity not emitted after completing a group of 2")
	}
	if !IsParity(parity) {
		t.Fatal("emitted parity datagram is not marked as parity")
	}
}

func TestDecoder_RecoversErasedDataPacket(t *testing.T) {
	enc := NewEncoder(0.5)
	dec := NewDecoder(0)

	pkt1 := []byte{0xAA, 0xBB, 0xCC}
	pkt2 := []byte{0x11, 0x22, 0x33, 0x44}

	d1, _ := enc.AddData(pkt1)
	_, parity := enc.AddData(pkt2)
	if parity == nil {
		t.Fatal("encoder did not emit parity")
	}

	if p, isData, rec := dec.Add(d1); !isData || !bytes.Equal(p, pkt1) || rec != nil {
		t.Fatalf("data frame: got payload=%x isData=%v rec=%x", p, isData, rec)
	}
	_, isData, recovered := dec.Add(parity)
	if isData {
		t.Fatal("parity frame should not report isData")
	}
	if recovered == nil {
		t.Fatal("decoder did not recover missing packet")
	}
	if !bytes.Equal(recovered, pkt2) {
		t.Fatalf("recovered %x want %x", recovered, pkt2)
	}
}

func TestDecoder_RecoversErasedFirstPacket(t *testing.T) {
	enc := NewEncoder(0.5)
	dec := NewDecoder(0)

	pkt1 := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	pkt2 := []byte{0xFE, 0xDC}

	_, _ = enc.AddData(pkt1)
	d2, parity := enc.AddData(pkt2)

	dec.Add(d2)
	_, _, recovered := dec.Add(parity)
	if !bytes.Equal(recovered, pkt1) {
		t.Fatalf("recovered %x want %x", recovered, pkt1)
	}
}

func TestDecoder_NoFalseRecoveryWhenAllArrive(t *testing.T) {
	enc := NewEncoder(0.5)
	dec := NewDecoder(0)

	d1, _ := enc.AddData([]byte{0x01, 0x02})
	d2, parity := enc.AddData([]byte{0x03, 0x04})

	for _, f := range [][]byte{d1, d2, parity} {
		if _, _, rec := dec.Add(f); rec != nil {
			t.Fatalf("unexpected recovery when no packet was lost: %x", rec)
		}
	}
}

func TestDecoder_NoRecoveryWithTwoErasures(t *testing.T) {
	enc := NewEncoder(0)
	enc.SetLoss(0.25)
	dec := NewDecoder(0)

	var parity []byte
	frames := make([][]byte, 0, 4)
	for i := 0; i < 4; i++ {
		d, p := enc.AddData([]byte{byte(i), byte(i + 1)})
		frames = append(frames, d)
		if p != nil {
			parity = p
		}
	}

	dec.Add(frames[0])
	dec.Add(frames[1])
	if _, _, rec := dec.Add(parity); rec != nil {
		t.Fatalf("two erasures must not recover, got %x", rec)
	}
}

func TestDecoder_RecoversParityArrivingBeforeData(t *testing.T) {
	enc := NewEncoder(0.5)
	dec := NewDecoder(0)

	pkt1 := []byte{0x09, 0x08, 0x07}
	pkt2 := []byte{0x10, 0x20}
	d1, _ := enc.AddData(pkt1)
	_, parity := enc.AddData(pkt2)

	if _, _, rec := dec.Add(parity); rec != nil {
		t.Fatalf("recovery before any data frame should be impossible, got %x", rec)
	}
	_, _, recovered := dec.Add(d1)
	if !bytes.Equal(recovered, pkt2) {
		t.Fatalf("recovered %x want %x", recovered, pkt2)
	}
}

func TestGroupSizeFromLoss(t *testing.T) {
	cases := []struct {
		loss float64
		want int
	}{
		{0.0, maxGroupSize},
		{1.0, minGroupSize},
		{0.5, 2},
		{0.1, 10},
		{0.05, 20},
	}
	for _, c := range cases {
		if got := groupSizeFromLoss(c.loss); got != c.want {
			t.Errorf("groupSizeFromLoss(%v) = %d, want %d", c.loss, got, c.want)
		}
	}
}

func TestEncoder_AdvancesGroupID(t *testing.T) {
	enc := NewEncoder(0.5)
	enc.AddData([]byte{0x01})
	_, p1 := enc.AddData([]byte{0x02})
	d3, _ := enc.AddData([]byte{0x03})
	if p1 == nil {
		t.Fatal("group 0 parity not emitted")
	}
	if !IsData(d3) || d3[1] != 0x00 || d3[2] != 0x01 {
		t.Fatalf("third data frame should belong to group 1, header=%x", d3[:3])
	}
}

func TestDecoder_LossEstimate(t *testing.T) {

	dec := NewDecoder(0)
	const groups = 40
	for g := 0; g < groups; g++ {
		enc := NewEncoder(0)
		enc.SetLoss(0.25)
		var frames [][]byte
		var parity []byte
		for i := 0; i < 4; i++ {
			d, p := enc.AddData([]byte{byte(g), byte(i), 0xAB})
			frames = append(frames, d)
			if p != nil {
				parity = p
			}
		}

		for i, f := range frames {
			if i == 2 {
				continue
			}
			dec.Add(f)
		}
		dec.Add(parity)
	}
	got := dec.LossEstimate()
	if got < 0.20 || got > 0.30 {
		t.Fatalf("loss estimate = %.3f, want ≈0.25", got)
	}
}

func TestDecoder_LossEstimateZeroWhenClean(t *testing.T) {
	dec := NewDecoder(0)
	for g := 0; g < 10; g++ {
		enc := NewEncoder(0.5)
		d1, _ := enc.AddData([]byte{byte(g), 0x01})
		d2, parity := enc.AddData([]byte{byte(g), 0x02})
		dec.Add(d1)
		dec.Add(d2)
		dec.Add(parity)
	}
	if got := dec.LossEstimate(); got != 0 {
		t.Fatalf("loss estimate = %.3f, want 0 on a clean stream", got)
	}
}

func TestFeedbackRoundTrip(t *testing.T) {
	cases := []float64{0, 0.1, 0.25, 0.5, 1.0}
	for _, loss := range cases {
		fb := MakeFeedback(loss)
		if !IsFeedback(fb) {
			t.Fatalf("MakeFeedback(%v) not recognized as feedback", loss)
		}
		if IsData(fb) || IsParity(fb) {
			t.Fatalf("feedback frame misclassified as data/parity")
		}
		got, ok := ParseFeedback(fb)
		if !ok {
			t.Fatalf("ParseFeedback failed for %v", loss)
		}
		if diff := got - loss; diff > 0.001 || diff < -0.001 {
			t.Fatalf("round-trip loss = %.4f, want %.4f", got, loss)
		}
	}
	if _, ok := ParseFeedback([]byte{typeData, 0x00, 0x00}); ok {
		t.Fatal("ParseFeedback accepted a non-feedback frame")
	}
}

func TestFeedbackDrivesEncoderGroupSize(t *testing.T) {
	enc := NewEncoder(0)

	loss, ok := ParseFeedback(MakeFeedback(0.5))
	if !ok {
		t.Fatal("feedback parse failed")
	}
	enc.SetLoss(loss)

	enc.AddData([]byte{0x01})
	if _, parity := enc.AddData([]byte{0x02}); parity == nil {
		t.Fatal("encoder did not adopt smaller group size after feedback")
	}
}

func TestIsParityIsData(t *testing.T) {
	if IsParity(nil) || IsData(nil) {
		t.Fatal("nil is neither parity nor data")
	}
	if !IsData([]byte{typeData, 0x00}) {
		t.Fatal("data marker not detected")
	}
	if !IsParity([]byte{typeParity, 0x00}) {
		t.Fatal("parity marker not detected")
	}
}
