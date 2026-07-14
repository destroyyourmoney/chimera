//go:build chimera_quic

package quic

import (
	"bytes"
	"testing"

	"chimera/internal/fec"
	"chimera/internal/tunnel"
)

// TestDatagramFECRecovery exercises the exact encode→(drop)→decode contract used
// by udpToQuic (send) and runDatagramDispatch (receive): a wrapped UDP datagram
// whose data frame is lost on the wire is reconstructed from the group's parity
// and unwraps back to the original assocID + payload.
func TestDatagramFECRecovery(t *testing.T) {
	enc := fec.NewEncoder(0.5) // groupSize=2: one parity per two datagrams
	dec := fec.NewDecoder(0)

	const assocA, assocB = uint16(0x0123), uint16(0x0007)
	payA := []byte("hello-udp-A")
	payB := []byte("second-datagram-B-longer")

	// Sender side (mirrors udpToQuic): wrap + FEC-frame each datagram.
	frameA, _ := enc.AddData(tunnel.WrapDatagram(assocA, payA))
	frameB, parity := enc.AddData(tunnel.WrapDatagram(assocB, payB))
	if parity == nil {
		t.Fatal("expected a parity frame after a full group")
	}
	_ = frameB // frameB is the datagram we simulate as lost on the wire

	// Receiver side (mirrors runDatagramDispatch): frameB is dropped; frameA and
	// parity arrive. Collect every payload that would be dispatched.
	var dispatched [][]byte
	collect := func(raw []byte) {
		payload, isData, recovered := dec.Add(raw)
		if isData {
			dispatched = append(dispatched, payload)
		}
		if recovered != nil {
			dispatched = append(dispatched, recovered)
		}
	}
	collect(frameA)
	collect(parity) // recovery happens here

	if len(dispatched) != 2 {
		t.Fatalf("expected 2 dispatched datagrams (A live + B recovered), got %d", len(dispatched))
	}

	// Verify the recovered datagram unwraps to assocB + payB.
	var recoveredB []byte
	for _, d := range dispatched {
		id, p, ok := tunnel.UnwrapDatagram(d)
		if !ok {
			t.Fatalf("dispatched datagram did not unwrap: %x", d)
		}
		if id == assocB {
			recoveredB = p
		}
	}
	if recoveredB == nil {
		t.Fatal("datagram B was not recovered via FEC")
	}
	if !bytes.Equal(recoveredB, payB) {
		t.Fatalf("recovered B payload = %q, want %q", recoveredB, payB)
	}
}
