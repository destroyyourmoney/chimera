//go:build chimera_utls

package server

import (
	"bufio"
	"io"
	"net"

	"chimera/internal/reality"
)

// authedTransport (chimera_utls build) terminates a real TLS 1.3 session with
// the authenticated client (Reality handshake takeover) and runs the inner
// protocol inside it, so none of those bytes are visible on the wire.
func (s *server) authedTransport(c net.Conn, br *bufio.Reader, raw, ss []byte) (io.ReadWriteCloser, error) {
	// crypto/tls must re-read the ClientHello, so re-deliver it plus anything the
	// bufio reader already pulled past it (e.g. the TLS 1.3 dummy ChangeCipherSpec).
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
