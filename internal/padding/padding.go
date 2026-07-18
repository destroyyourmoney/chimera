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
	MinPad = 32
	MaxPad = 512

	MaxPayload = 1 << 16
)

var errFrameTooLarge = errors.New("padding: framed payload exceeds bound")

type Stream struct {
	rng *mrand.ChaCha8
}

const (
	ClientToServer = "chimera-pad-c2s-v0"
	ServerToClient = "chimera-pad-s2c-v0"
)

func New(secret []byte, direction string) *Stream {
	h := sha256.New()
	h.Write([]byte(direction))
	h.Write(secret)
	var seed [32]byte
	copy(seed[:], h.Sum(nil))
	return &Stream{rng: mrand.NewChaCha8(seed)}
}

func (s *Stream) padLen() int {
	return MinPad + int(s.rng.Uint64()%uint64(MaxPad-MinPad+1))
}

func WriteFrame(w io.Writer, s *Stream, payload []byte) error {
	if len(payload) > MaxPayload {
		return errFrameTooLarge
	}
	pad := s.padLen()
	buf := make([]byte, 2+len(payload)+pad)
	binary.BigEndian.PutUint16(buf[:2], uint16(len(payload)))
	copy(buf[2:], payload)
	if _, err := rand.Read(buf[2+len(payload):]); err != nil {
		return err
	}
	_, err := w.Write(buf)
	return err
}

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
