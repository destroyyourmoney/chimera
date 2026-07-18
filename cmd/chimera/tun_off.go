//go:build !chimera_netstack || (!linux && !darwin && !windows)

package main

import (
	"context"
	"errors"

	"chimera/internal/endpoint"
	"chimera/internal/winnet"
)

func runTUN(_ context.Context, _ endpoint.Dialer, _ string, _ int, _ *winnet.Config, _ bool, _, _, _ string) error {
	return errors.New("tun mode requires building with -tags chimera_netstack on linux/darwin/windows")
}
