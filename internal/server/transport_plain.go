//go:build !chimera_utls

package server

import (
	"bufio"
	"io"
	"net"
)

// authedTransport (default build) runs the inner protocol over the raw
// post-handshake TCP stream: reads come from the buffered reader (which holds
// any bytes already pulled past the ClientHello), writes go to the connection.
func (s *server) authedTransport(c net.Conn, br *bufio.Reader, _, _ []byte) (io.ReadWriteCloser, error) {
	return rawTransport{r: br, c: c}, nil
}

type rawTransport struct {
	r io.Reader
	c net.Conn
}

func (t rawTransport) Read(p []byte) (int, error)  { return t.r.Read(p) }
func (t rawTransport) Write(p []byte) (int, error) { return t.c.Write(p) }
func (t rawTransport) Close() error                { return nil } // c is closed by handle
