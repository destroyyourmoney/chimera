//go:build chimera_utls

package server

import (
	"bufio"
	"io"
	"net"

	"chimera/internal/reality"
)

func (s *server) authedTransport(c net.Conn, br *bufio.Reader, raw, ss []byte) (io.ReadWriteCloser, error) {

	prefix := raw
	if n := br.Buffered(); n > 0 {
		extra, _ := br.Peek(n)
		prefix = append(append([]byte(nil), raw...), extra...)
		_, _ = br.Discard(n)
	}
	tc, err := reality.ServerWrap(c, prefix, ss, s.stealHost)
	if err != nil {
		return nil, err
	}
	return tc, nil
}
