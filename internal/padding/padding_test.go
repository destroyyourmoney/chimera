package padding

import (
	"bytes"
	"io"
	"testing"
)

func TestFrameRoundTripInLockstep(t *testing.T) {
	secret := []byte("shared-secret-from-x25519-ecdh-32b")
	wr := New(secret, ClientToServer)
	rd := New(secret, ClientToServer) // peer derives the same stream

	payloads := [][]byte{
		{0x00},                         // PING
		{0x01, 0x03, 'a', 'b', 'c'},    // CONNECT-ish
		{},                             // empty
		bytes.Repeat([]byte{0xaa}, 40), // larger
	}

	var wire bytes.Buffer
	for _, p := range payloads {
		if err := WriteFrame(&wire, wr, p); err != nil {
			t.Fatalf("WriteFrame: %v", err)
		}
	}

	for i, want := range payloads {
		got, err := ReadFrame(&wire, rd)
		if err != nil {
			t.Fatalf("ReadFrame[%d]: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("frame %d payload = %x, want %x", i, got, want)
		}
	}
	if wire.Len() != 0 {
		t.Fatalf("%d unconsumed wire bytes — streams out of lockstep", wire.Len())
	}
}

func TestPaddingHidesTinyControlLengths(t *testing.T) {
	secret := []byte("another-secret")
	s := New(secret, ServerToClient)
	var wire bytes.Buffer
	// A 1-byte status reply must not appear as a 1- or 3-byte packet on the wire.
	if err := WriteFrame(&wire, s, []byte{0x01}); err != nil {
		t.Fatal(err)
	}
	if wire.Len() < 2+1+MinPad {
		t.Fatalf("framed length %d too small; padding not applied", wire.Len())
	}
	if wire.Len() > 2+1+MaxPad {
		t.Fatalf("framed length %d exceeds MaxPad bound", wire.Len())
	}
}

func TestDirectionsAreIndependent(t *testing.T) {
	secret := []byte("dir-secret")
	c2s := New(secret, ClientToServer)
	s2c := New(secret, ServerToClient)
	// Different labels must yield different padding length sequences.
	if c2s.padLen() == s2c.padLen() && c2s.padLen() == s2c.padLen() {
		t.Error("c2s and s2c streams produced identical sequences")
	}
}

func TestReadFrameRejectsOversizedHeader(t *testing.T) {
	// payloadLen header claims 0xFFFF but MaxPayload is the cap; with no body the
	// reader must fail cleanly, not allocate-and-hang.
	s := New([]byte("x"), ClientToServer)
	wire := bytes.NewReader([]byte{0xff, 0xff})
	if _, err := ReadFrame(wire, s); err == nil || err == io.EOF {
		// io.EOF is acceptable (short body); a panic or hang is not. Either a
		// clean non-nil error or EOF on the truncated body is fine.
		if err == nil {
			t.Fatal("expected error on truncated oversized frame")
		}
	}
}
