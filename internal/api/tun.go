//go:build chimera_netstack && (linux || darwin)

package api

import (
	"context"
	"errors"

	"chimera/internal/netstack"
	"chimera/internal/tun"
)

func (s *Session) ConnectTUN(ctx context.Context, fd, mtu int) error {
	s.mu.RLock()
	dialer := s.dialer
	state := s.state
	s.mu.RUnlock()
	if state != StateConnected || dialer == nil {
		return errors.New("api: not connected; call Connect first")
	}

	udp, _ := dialer.(netstack.UDPDialer)
	stack, err := netstack.New(dialer, udp)
	if err != nil {
		return err
	}
	defer stack.Close()

	br, err := tun.OpenFD(fd, mtu, stack)
	if err != nil {
		return err
	}
	defer br.Close()

	return br.Run(ctx)
}
