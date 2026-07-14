package rudp

import "context"

// Datagram is the unreliable packet transport rudp rides on. It is deliberately
// tiny — Send/Recv of opaque, best-effort, possibly-reordered, possibly-dropped
// frames — so rudp can be exercised over an in-memory lossy pipe in tests and
// over a real QUIC DATAGRAM channel in production through the same code path.
//
// Implementations must be safe for one concurrent Send and one concurrent Recv
// (rudp drives Send from its transmit loop and Recv from its read loop). Frames
// passed to Send are owned by the implementation only for the duration of the
// call; frames returned by Recv are owned by the caller.
type Datagram interface {
	// Send transmits one frame on a best-effort basis. A nil error does not
	// promise delivery — only that the frame was handed to the transport.
	Send(frame []byte) error

	// Recv blocks until the next frame arrives, ctx is cancelled, or the
	// transport fails. It returns the received frame or a non-nil error.
	Recv(ctx context.Context) ([]byte, error)

	// Close releases the transport. Concurrent and repeated calls are safe.
	Close() error
}
