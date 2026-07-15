//go:build chimera_netstack && (linux || darwin || windows)

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"chimera/internal/endpoint"
	"chimera/internal/netstack"
	"chimera/internal/tun"
	"chimera/internal/winnet"
)

// tunStatus is the JSON document periodically written to -status-file so a
// parent process (chimera-helper) can report live tunnel state/throughput
// back to its own client without a direct channel into this process.
type tunStatus struct {
	State     string `json:"state"`
	BytesUp   uint64 `json:"bytesUp"`
	BytesDown uint64 `json:"bytesDown"`
	Server    string `json:"server"`
	Transport string `json:"transport"`
	UpdatedAt int64  `json:"updatedAt"`
}

// writeStatus atomically replaces statusFile's contents (write to a temp
// file in the same directory, then rename) so a concurrent reader never
// observes a torn write.
func writeStatus(statusFile string, st tunStatus) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := statusFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, statusFile)
}

// runStatusWriter periodically writes br's stats to statusFile until ctx is
// done, then writes a final "idle" status so a stale "running" status file
// never lingers.
func runStatusWriter(ctx context.Context, statusFile string, br *tun.Bridge, server, transport string) {
	if statusFile == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(statusFile), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not create status file dir: %v\n", err)
		return
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		up, down := br.Stats()
		_ = writeStatus(statusFile, tunStatus{
			State:     "running",
			BytesUp:   up,
			BytesDown: down,
			Server:    server,
			Transport: transport,
			UpdatedAt: time.Now().Unix(),
		})
		select {
		case <-ctx.Done():
			up, down := br.Stats()
			_ = writeStatus(statusFile, tunStatus{
				State:     "idle",
				BytesUp:   up,
				BytesDown: down,
				Server:    server,
				Transport: transport,
				UpdatedAt: time.Now().Unix(),
			})
			return
		case <-ticker.C:
		}
	}
}

// runTUN builds a userspace netstack over the carrier dialer and bridges it to a
// real TUN device (full-tunnel VPN mode). Compiled only with -tags chimera_netstack.
func runTUN(ctx context.Context, dialer endpoint.Dialer, name string, mtu int, setup *winnet.Config, keepSetup bool, statusFile, server, transport string) error {
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
	go runStatusWriter(ctx, statusFile, br, server, transport)
	return br.Run(ctx)
}
