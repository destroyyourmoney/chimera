//go:build chimera_netstack && (linux || darwin || windows)

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"chimera/internal/endpoint"
	"chimera/internal/netstack"
	"chimera/internal/tun"
	"chimera/internal/winnet"
)

// runTUN builds a userspace netstack over the carrier dialer and bridges it to a
// real TUN device (full-tunnel VPN mode). Compiled only with -tags chimera_netstack.
func runTUN(ctx context.Context, dialer endpoint.Dialer, name string, mtu int, setup *winnet.Config, keepSetup bool) error {
	// UDP forwarding is optional: only pools that can open a datagram carrier
	// (QUIC-backed) implement netstack.UDPDialer; otherwise UDP flows are dropped.
	udp, _ := dialer.(netstack.UDPDialer)
	stack, err := netstack.New(dialer, udp)
	if err != nil {
		return err
	}
	defer stack.Close()

	br, err := tun.Open(name, mtu, stack)
	if err != nil {
		return err
	}
	defer br.Close()

	if setup != nil {
		cfg := *setup
		cfg.InterfaceAlias = br.Name()
		if err := winnet.Apply(ctx, cfg, false, os.Stdout); err != nil {
			return err
		}
		if !keepSetup {
			defer func() {
				restoreCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if err := winnet.Restore(restoreCtx, cfg, false, os.Stdout); err != nil {
					fmt.Fprintf(os.Stderr, "warning: failed to restore OS network setup: %v\n", err)
				}
			}()
		}
	}

	fmt.Printf("tun up: %s (mtu %d) - full-tunnel via carrier\n", br.Name(), br.MTU())
	return br.Run(ctx)
}
