package rudp

import "context"

type Datagram interface {
	Send(frame []byte) error

	Recv(ctx context.Context) ([]byte, error)

	Close() error
}
