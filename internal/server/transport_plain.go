//go:build !chimera_utls

package server

import (
	"bufio"
	"io"
	"net"
)

func (s *server) authedTransport(c net.Conn, br *bufio.Reader, _, _ []byte) (io.ReadWriteCloser, error) {
	return rawTransport{r: br, c: c}, nil
}

type rawTransport struct {
	r io.Reader
	c net.Conn
}

func (t rawTransport) Read(p []byte) (int, error)  { return t.r.Read(p) }
func (t rawTransport) Write(p []byte) (int, error) { return t.c.Write(p) }
func (t rawTransport) Close() error                { return nil }
