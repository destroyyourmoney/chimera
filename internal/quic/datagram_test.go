//go:build chimera_quic

package quic

import (
	"bytes"
	"testing"

	"chimera/internal/fec"
	"chimera/internal/tunnel"
)

func TestDatagramFECRecovery(t *testing.T) {
	enc := fec.NewEncoder(0.5)
	dec := fec.NewDecoder(0)

	const assocA, assocB = uint16(0x0123), uint16(0x0007)
	payA := []byte("hello-udp-A")
	payB := []byte("second-datagram-B-longer")

	frameA, _ := enc.AddData(tunnel.WrapDatagram(assocA, payA))
	frameB, parity := enc.AddData(tunnel.WrapDatagram(assocB, payB))
	if parity == nil {
		t.Fatal("expected a parity frame after a full group")
	}
	_ = frameB

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
	collect(parity)

	if len(dispatched) != 2 {
		t.Fatalf("expected 2 dispatched datagrams (A live + B recovered), got %d", len(dispatched))
	}

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
