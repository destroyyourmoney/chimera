//go:build chimera_netstack && (linux || darwin || windows)

// Package tun bridges a real TUN device to the userspace netstack: it pumps raw
// IP packets from the kernel TUN interface into the netstack (InjectInbound) and
// writes the netstack's replies back out (ReadOutbound). This is the full-tunnel
// (VPN) data path; the SOCKS inbound is the TUN-less alternative.
//
// Creating the device needs privileges (root / CAP_NET_ADMIN on Linux, utun on
// macOS), so end-to-end device tests run only in a privileged CI lane. The packet
// translation that follows the device — netstack TCP/UDP forwarders → carrier — is
// covered without privileges by internal/netstack's channel-endpoint tests.
package tun

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"

	wgtun "golang.zx2c4.com/wireguard/tun"

	"chimera/internal/netstack"
)

// tunHeadroom is the per-packet buffer offset reserved for the platform TUN header
// (4 B address-family header on darwin/BSD, up to 10 B virtio-net header on Linux).
// wireguard/tun's contract: pass this offset to Read/Write and the IP packet sits
// at buf[offset : offset+size].
const tunHeadroom = 16

// Bridge moves IP packets between a TUN device and a netstack.Stack.
type Bridge struct {
	dev   wgtun.Device
	stack *netstack.Stack
	mtu   int
}

// Open creates TUN device `name` (empty = OS-assigned, e.g. utunN) with `mtu` and
// bridges it to stack.
func Open(name string, mtu int, stack *netstack.Stack) (*Bridge, error) {
	if runtime.GOOS == "windows" && name == "" {
		name = "chimera"
	}
	dev, err := wgtun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("tun: create device %q: %w", name, err)
	}
	if actual, err := dev.MTU(); err == nil && actual > 0 {
		mtu = actual
	}
	return &Bridge{dev: dev, stack: stack, mtu: mtu}, nil
}

// Name returns the device's actual name (e.g. utun3 on macOS).
func (b *Bridge) Name() string { n, _ := b.dev.Name(); return n }

// MTU returns the device MTU.
func (b *Bridge) MTU() int { return b.mtu }

// Run bridges packets until ctx is cancelled or the device errors.
func (b *Bridge) Run(ctx context.Context) error {
	// Closing the device unblocks the blocking Read in deviceToStack.
	go func() { <-ctx.Done(); _ = b.dev.Close() }()
	go b.stackToDevice(ctx)
	err := b.deviceToStack()
	if ctx.Err() != nil && (errors.Is(err, os.ErrClosed) || err != nil) {
		return nil
	}
	return err
}

// deviceToStack reads IP packets from the TUN device and injects them into the stack.
func (b *Bridge) deviceToStack() error {
	batch := b.dev.BatchSize()
	if batch < 1 {
		batch = 1
	}
	bufs := make([][]byte, batch)
	sizes := make([]int, batch)
	for i := range bufs {
		bufs[i] = make([]byte, tunHeadroom+b.mtu+64)
	}
	for {
		n, err := b.dev.Read(bufs, sizes, tunHeadroom)
		if err != nil {
			return err
		}
		for i := 0; i < n; i++ {
			b.stack.InjectInbound(bufs[i][tunHeadroom : tunHeadroom+sizes[i]])
		}
	}
}

// stackToDevice writes the stack's outbound IP packets to the TUN device.
func (b *Bridge) stackToDevice(ctx context.Context) {
	for {
		pkt := b.stack.ReadOutbound(ctx)
		if pkt == nil {
			return
		}
		buf := make([]byte, tunHeadroom+len(pkt))
		copy(buf[tunHeadroom:], pkt)
		if _, err := b.dev.Write([][]byte{buf}, tunHeadroom); err != nil {
			return
		}
	}
}

// Close tears down the device.
func (b *Bridge) Close() error { return b.dev.Close() }
