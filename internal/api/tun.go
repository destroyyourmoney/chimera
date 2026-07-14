//go:build chimera_netstack && (linux || darwin)

package api

import (
	"context"
	"errors"

	"chimera/internal/netstack"
	"chimera/internal/tun"
)

// ConnectTUN bridges an OS-provided TUN file descriptor to the tunnel, giving a
// full-device VPN: every IP packet on the TUN is forwarded through the carrier.
// fd comes from the platform VPN API — Android VpnService.establish() or a
// desktop privileged helper. It blocks until ctx is cancelled or the device
// errors; the fd is adopted and closed on return. The Session must already be
// Connected (Connect sets up the endpoint pool).
//
// Compiled only with -tags chimera_netstack on linux/darwin; the default build
// uses the stub in tun_stub.go.
func (s *Session) ConnectTUN(ctx context.Context, fd, mtu int) error {
	s.mu.RLock()
	dialer := s.dialer
	state := s.state
	s.mu.RUnlock()
	if state != StateConnected || dialer == nil {
		return errors.New("api: not connected; call Connect first")
	}

	// UDP forwarding is best-effort: only QUIC-backed pools implement UDPDialer.
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
