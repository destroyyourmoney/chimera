//go:build !(chimera_netstack && (linux || darwin))

package api

import (
	"context"
	"errors"
)

func (s *Session) ConnectTUN(_ context.Context, _, _ int) error {
	return errors.New("api: fd-based TUN support not built for this target (use RunSOCKS, or chimera tun on supported desktop builds)")
}
