package socks

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"

	"chimera/internal/endpoint"
	"chimera/internal/serve"
)

const (
	cmdConnect   = 0x01
	cmdUDPAssoc  = 0x03
	atypIPv4     = 0x01
	atypDomain   = 0x03
	atypIPv6     = 0x04
	repSucceeded = 0x00
	repGenFail   = 0x01
	repCmdNotSup = 0x07
)

func Serve(ctx context.Context, listen string, dialer endpoint.Dialer) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	return ServeListener(ctx, ln, dialer)
}

func ServeListener(ctx context.Context, ln net.Listener, dialer endpoint.Dialer) error {
	slog.Info("socks inbound up", "listen", ln.Addr().String())
	err := serve.Loop(ctx, ln, serve.DefaultDrain, func(c net.Conn) {
		handle(c, dialer)
	})
	slog.Info("socks inbound stopped")
	return err
}

func handle(c net.Conn, dialer endpoint.Dialer) {
	defer c.Close()
	cmd, host, port, err := negotiate(c)
	if err != nil {
		return
	}
	switch cmd {
	case cmdConnect:

		if _, err := c.Write([]byte{0x05, repSucceeded, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
			return
		}
		up, err := dialer.DialConnect(host, port)
		if err != nil {
			slog.Warn("socks tunnel failed", "host", host, "port", port, "err", err)
			return
		}
		defer up.Close()
		go func() { _, _ = io.Copy(up, c) }()
		_, _ = io.Copy(c, up)
	case cmdUDPAssoc:
		ud, ok := dialer.(endpoint.UDPDialer)
		if !ok {
			_, _ = c.Write([]byte{0x05, repCmdNotSup, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
			return
		}
		serveUDPAssoc(c, ud)
	default:
		_, _ = c.Write([]byte{0x05, repCmdNotSup, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	}
}

func negotiate(c net.Conn) (cmd byte, host string, port uint16, err error) {

	head := make([]byte, 2)
	if _, err = io.ReadFull(c, head); err != nil {
		return
	}
	if head[0] != 0x05 {
		err = fmt.Errorf("socks: bad version %d", head[0])
		return
	}
	if _, err = io.ReadFull(c, make([]byte, int(head[1]))); err != nil {
		return
	}
	if _, err = c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	req := make([]byte, 4)
	if _, err = io.ReadFull(c, req); err != nil {
		return
	}
	cmd = req[1]
	switch req[3] {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err = io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case atypDomain:
		l := make([]byte, 1)
		if _, err = io.ReadFull(c, l); err != nil {
			return
		}
		b := make([]byte, int(l[0]))
		if _, err = io.ReadFull(c, b); err != nil {
			return
		}
		host = string(b)
	case atypIPv6:
		b := make([]byte, 16)
		if _, err = io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		err = fmt.Errorf("socks: bad atyp %d", req[3])
		return
	}
	pb := make([]byte, 2)
	if _, err = io.ReadFull(c, pb); err != nil {
		return
	}
	port = binary.BigEndian.Uint16(pb)
	return cmd, host, port, nil
}
