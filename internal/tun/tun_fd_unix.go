//go:build chimera_netstack && (linux || darwin)

package tun

import (
	"fmt"
	"os"

	wgtun "golang.zx2c4.com/wireguard/tun"

	"chimera/internal/netstack"
)

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
