//go:build chimera_netstack && (linux || darwin || windows)

package tun

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync/atomic"

	wgtun "golang.zx2c4.com/wireguard/tun"

	"chimera/internal/netstack"
)

const tunHeadroom = 16

type Bridge struct {
	dev   wgtun.Device
	stack *netstack.Stack
	mtu   int

	bytesUp   uint64
	bytesDown uint64
}

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

func (b *Bridge) Name() string { n, _ := b.dev.Name(); return n }

func (b *Bridge) MTU() int { return b.mtu }

func (b *Bridge) Stats() (up, down uint64) {
	return atomic.LoadUint64(&b.bytesUp), atomic.LoadUint64(&b.bytesDown)
}

func (b *Bridge) Run(ctx context.Context) error {

	go func() { <-ctx.Done(); _ = b.dev.Close() }()
	go b.stackToDevice(ctx)
	err := b.deviceToStack()
	if ctx.Err() != nil && (errors.Is(err, os.ErrClosed) || err != nil) {
		return nil
	}
	return err
}

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
			atomic.AddUint64(&b.bytesUp, uint64(sizes[i]))
			b.stack.InjectInbound(bufs[i][tunHeadroom : tunHeadroom+sizes[i]])
		}
	}
}

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
		atomic.AddUint64(&b.bytesDown, uint64(len(pkt)))
	}
}

func (b *Bridge) Close() error { return b.dev.Close() }
