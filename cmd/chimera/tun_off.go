//go:build !chimera_netstack || (!linux && !darwin && !windows)

package main

import (
	"context"
	"errors"

	"chimera/internal/endpoint"
	"chimera/internal/winnet"
)

// runTUN stub for builds without the netstack data path (default build, or
// unsupported OS). TUN mode requires -tags chimera_netstack on linux/darwin/windows.
func runTUN(_ context.Context, _ endpoint.Dialer, _ string, _ int, _ *winnet.Config, _ bool) error {
	return errors.New("tun mode requires building with -tags chimera_netstack on linux/darwin/windows")
}
