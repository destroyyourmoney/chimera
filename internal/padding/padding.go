// Package padding implements CHIMERA seeded padding (the Reality "seed" model).
//
// The tiny control messages at the start of a tunnel session — a 1-byte PING, a
// short CONNECT request, a 1-byte status reply — have distinctive fixed lengths.
// On the wire that length sequence is a fingerprint. Seeded padding removes it:
// both endpoints derive the SAME deterministic length stream from the handshake
// shared secret (which only they possess), so every framed control message is
// bulked out to a TLS-record-plausible size with NO negotiation bytes on the
// wire. Because the stream is shared, the reader knows exactly how many padding
// bytes to discard.
//
// Two independent streams are derived per session — one per direction — so the
// client and server stay in lockstep even with interleaved traffic. Padding
// bytes are drawn from the same keystream, giving them the high, uniform entropy
// of encrypted application data rather than a low-entropy tell.
package padding

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	mrand "math/rand/v2"
)

const (
	// MinPad/MaxPad bound the per-frame padding so a control message lands in a
	// plausible TLS record-size band instead of its raw tiny length.
	MinPad = 32
	MaxPad = 512
	// MaxPayload caps a single framed control payload (defensive bound for the reader).
	MaxPayload = 1 << 16
)

var errFrameTooLarge = errors.New("padding: framed payload exceeds bound")

// Stream is a deterministic, shared-secret-seeded source of padding LENGTHS.
// Both endpoints derive it from the same secret+label and draw exactly one value
// per frame, so the length sequences stay in lockstep. Padding CONTENT is not
// derived here: the writer fills it with fresh randomness (so it carries the high
// entropy of encrypted data) and the reader simply discards those bytes off the
// wire, so content never needs to be reproduced.
type Stream struct {
	rng *mrand.ChaCha8
}

// Direction labels keep the two per-session streams independent.
const (
	ClientToServer = "chimera-pad-c2s-v0"
	ServerToClient = "chimera-pad-s2c-v0"
)

// New derives a Stream from the handshake shared secret and a direction label.
func New(secret []byte, direction string) *Stream {
	h := sha256.New()
	h.Write([]byte(direction))
	h.Write(secret)
	var seed [32]byte
	copy(seed[:], h.Sum(nil))
	return &Stream{rng: mrand.NewChaCha8(seed)}
}

// padLen returns the next padding length in [MinPad, MaxPad]. Exactly one draw
// per frame keeps writer and reader in lockstep.
func (s *Stream) padLen() int {
	return MinPad + int(s.rng.Uint64()%uint64(MaxPad-MinPad+1))
}

// WriteFrame writes payload as: u16 payloadLen | payload | seeded-pad. The peer's
// matching Stream reproduces padLen and strips it. Advances the stream by one frame.
func WriteFrame(w io.Writer, s *Stream, payload []byte) error {
	if len(payload) > MaxPayload {
		return errFrameTooLarge
	}
	pad := s.padLen()
	buf := make([]byte, 2+len(payload)+pad)
	binary.BigEndian.PutUint16(buf[:2], uint16(len(payload)))
	copy(buf[2:], payload)
	if _, err := rand.Read(buf[2+len(payload):]); err != nil { // content: fresh entropy, writer-local
		return err
	}
	_, err := w.Write(buf)
	return err
}

// ReadFrame reads one frame written by WriteFrame, returning the payload and
// discarding the seeded padding. Advances the stream by one frame, in lockstep
// with the writer.
func ReadFrame(r io.Reader, s *Stream) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n > MaxPayload {
		return nil, errFrameTooLarge
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	pad := s.padLen()
	if _, err := io.CopyN(io.Discard, r, int64(pad)); err != nil {
		return nil, err
	}
	return payload, nil
}
