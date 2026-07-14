//go:build chimera_netstack && (linux || darwin)

package tun

import (
	"fmt"
	"os"

	wgtun "golang.zx2c4.com/wireguard/tun"

	"chimera/internal/netstack"
)

// OpenFD bridges an already-open TUN file descriptor to stack. Mobile VPN APIs
// (Android VpnService.Builder.establish(), iOS NEPacketTunnelProvider) hand the app
// a fd rather than a device name; this is the mobile entry point (paired with a
// gomobile binding). The fd is adopted; closing the Bridge closes it.
func OpenFD(fd int, mtu int, stack *netstack.Stack) (*Bridge, error) {
	dev, err := wgtun.CreateTUNFromFile(os.NewFile(uintptr(fd), "chimera-tun"), mtu)
	if err != nil {
		return nil, fmt.Errorf("tun: adopt fd %d: %w", fd, err)
	}
	if actual, err := dev.MTU(); err == nil && actual > 0 {
		mtu = actual
	}
	return &Bridge{dev: dev, stack: stack, mtu: mtu}, nil
}
